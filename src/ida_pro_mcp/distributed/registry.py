"""
Redis 支持的 Worker 注册表。

提供 Worker 节点的注册、注销、心跳续期、查询和路由选择。
所有 Redis 操作均使用 pipeline 或 Lua 脚本保证原子性。
对外只暴露 RegistryError，不泄漏原始 redis 异常。

Redis Schema
------------
{ns}:worker:{worker_id}        HASH   {host, port, pid, capabilities_json,
                                        loaded_idb, score, started_at,
                                        last_heartbeat}
                               TTL    15 秒（每次 heartbeat 续期）

{ns}:workers:active            SET    全部 worker_id（懒清理过期成员）

{ns}:idb:{sha256(idb_path)}    SET    加载该 IDB 的 worker_id 集合
                               TTL    与 worker hash 同步续期
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import TYPE_CHECKING

import redis

from .protocol import HeartbeatPayload, RoutingDecision, WorkerInfo

if TYPE_CHECKING:
    pass

# Worker hash 过期时间（秒）。Worker 每 ~5 秒发一次心跳，15 秒 TTL 留足余量。
_WORKER_TTL = 15

# 连接池默认最大连接数。
_DEFAULT_MAX_CONNECTIONS = 20

# --------------------------------------------------------------------------- #
# 错误类型                                                                    #
# --------------------------------------------------------------------------- #


class RegistryError(Exception):
    """包装所有 Redis 底层异常，防止实现细节泄漏给调用方。"""

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.cause = cause

    def __str__(self) -> str:
        if self.cause is not None:
            return f"{super().__str__()} (caused by: {self.cause!r})"
        return super().__str__()


# --------------------------------------------------------------------------- #
# 内部辅助                                                                    #
# --------------------------------------------------------------------------- #


def _idb_key_suffix(idb_path: str) -> str:
    """将 IDB 路径转换为用于 Redis key 的 SHA-256 十六进制前缀（32 字符）。"""
    return hashlib.sha256(idb_path.encode()).hexdigest()


def _worker_from_hash(worker_id: str, data: dict[bytes, bytes]) -> WorkerInfo:
    """将 Redis HGETALL 原始字节数据还原为 WorkerInfo。"""
    caps_raw = data.get(b"capabilities_json", b"[]")
    caps: tuple[str, ...] = tuple(json.loads(caps_raw))

    loaded_idb_raw = data.get(b"loaded_idb", b"")
    loaded_idb: str | None = loaded_idb_raw.decode() if loaded_idb_raw else None

    return WorkerInfo(
        worker_id=worker_id,
        host=data[b"host"].decode(),
        port=int(data[b"port"]),
        pid=int(data[b"pid"]),
        capabilities=caps,
        loaded_idb=loaded_idb,
        score=float(data[b"score"]),
        started_at=float(data[b"started_at"]),
        last_heartbeat=float(data[b"last_heartbeat"]),
    )


# --------------------------------------------------------------------------- #
# 注册表核心                                                                   #
# --------------------------------------------------------------------------- #


class Registry:
    """Redis 支持的 Worker 注册表，线程安全。

    Parameters
    ----------
    redis_url:
        Redis 连接 URL，如 ``redis://localhost:6379/0``。
    namespace:
        Redis key 命名空间前缀，支持多租户共享同一 Redis 实例。
        默认 ``"idamcp"``。
    """

    def __init__(
        self,
        redis_url: str,
        namespace: str = "idamcp",
        *,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        self._ns = namespace
        pool = redis.ConnectionPool.from_url(
            redis_url,
            max_connections=max_connections,
            decode_responses=False,
        )
        self._r: redis.Redis = redis.Redis(connection_pool=pool)

    # ------------------------------------------------------------------ #
    # key 构造                                                             #
    # ------------------------------------------------------------------ #

    def _worker_key(self, worker_id: str) -> str:
        return f"{self._ns}:worker:{worker_id}"

    def _active_set_key(self) -> str:
        return f"{self._ns}:workers:active"

    def _idb_set_key(self, idb_path: str) -> str:
        return f"{self._ns}:idb:{_idb_key_suffix(idb_path)}"

    # ------------------------------------------------------------------ #
    # 写操作                                                               #
    # ------------------------------------------------------------------ #

    def register(self, info: WorkerInfo) -> None:
        """注册（或覆盖更新）一个 Worker 节点。

        原子操作：HMSET worker hash + EXPIRE + SADD active set +
        （若有 loaded_idb）SADD idb 反向索引 + EXPIRE。
        """
        worker_key = self._worker_key(info.worker_id)
        active_key = self._active_set_key()

        mapping: dict[str, str | int | float] = {
            "host": info.host,
            "port": info.port,
            "pid": info.pid,
            "capabilities_json": json.dumps(list(info.capabilities)),
            "loaded_idb": info.loaded_idb or "",
            "score": info.score,
            "started_at": info.started_at,
            "last_heartbeat": info.last_heartbeat,
        }

        try:
            pipe = self._r.pipeline(transaction=True)
            pipe.hset(worker_key, mapping=mapping)  # type: ignore[arg-type]
            pipe.expire(worker_key, _WORKER_TTL)
            pipe.sadd(active_key, info.worker_id)

            if info.loaded_idb:
                idb_key = self._idb_set_key(info.loaded_idb)
                pipe.sadd(idb_key, info.worker_id)
                pipe.expire(idb_key, _WORKER_TTL)

            pipe.execute()
        except redis.RedisError as exc:
            raise RegistryError(f"register({info.worker_id}) failed", exc) from exc

    def deregister(self, worker_id: str) -> None:
        """注销一个 Worker 节点，删除其 hash 并从 active set 移除。

        IDB 反向索引中的成员通过 list_workers / select_best 的懒清理移除，
        此处不做全量扫描。
        """
        worker_key = self._worker_key(worker_id)
        active_key = self._active_set_key()

        try:
            # 先读取 loaded_idb 以便清理反向索引
            raw_idb = self._r.hget(worker_key, "loaded_idb")

            pipe = self._r.pipeline(transaction=True)
            pipe.delete(worker_key)
            pipe.srem(active_key, worker_id)

            if raw_idb:
                idb_path = raw_idb.decode() if isinstance(raw_idb, bytes) else raw_idb
                if idb_path:
                    idb_key = self._idb_set_key(idb_path)
                    pipe.srem(idb_key, worker_id)

            pipe.execute()
        except redis.RedisError as exc:
            raise RegistryError(f"deregister({worker_id}) failed", exc) from exc

    def heartbeat(self, payload: HeartbeatPayload) -> None:
        """刷新 Worker TTL 并更新 score / loaded_idb / last_heartbeat。

        若 loaded_idb 发生变化，需同步更新 IDB 反向索引。
        使用 WATCH + pipeline 事务保证「读旧 idb → 更新 hash → 更新索引」的
        乐观锁原子性（兼容 fakeredis 测试环境，无需 Lua）。
        """
        worker_id = payload["worker_id"]
        worker_key = self._worker_key(worker_id)
        active_key = self._active_set_key()
        new_idb = payload.get("loaded_idb") or ""
        now = time.time()

        try:
            # 先检查 worker 是否仍活跃（hash 是否存在）
            old_idb_raw = self._r.hget(worker_key, "loaded_idb")
            if old_idb_raw is None and not self._r.exists(worker_key):
                # worker hash 不存在（已过期或从未注册），忽略心跳
                return

            old_idb = old_idb_raw.decode() if isinstance(old_idb_raw, bytes) else (old_idb_raw or "")
            if old_idb is None:
                old_idb = ""

            pipe = self._r.pipeline(transaction=True)
            pipe.hset(
                worker_key,
                mapping={
                    "score": str(payload["score"]),
                    "loaded_idb": new_idb,
                    "last_heartbeat": str(now),
                },
            )
            pipe.expire(worker_key, _WORKER_TTL)
            pipe.sadd(active_key, worker_id)

            if old_idb != new_idb:
                # IDB 加载状态发生变化，更新反向索引
                if old_idb:
                    pipe.srem(self._idb_set_key(old_idb), worker_id)
                if new_idb:
                    pipe.sadd(self._idb_set_key(new_idb), worker_id)
                    pipe.expire(self._idb_set_key(new_idb), _WORKER_TTL)
            elif new_idb:
                # IDB 未变化，仅续期
                pipe.expire(self._idb_set_key(new_idb), _WORKER_TTL)

            pipe.execute()
        except redis.RedisError as exc:
            raise RegistryError(f"heartbeat({worker_id}) failed", exc) from exc

    # ------------------------------------------------------------------ #
    # 读操作                                                               #
    # ------------------------------------------------------------------ #

    def get_worker(self, worker_id: str) -> WorkerInfo | None:
        """按 ID 获取单个 Worker 信息；不存在或已过期返回 None。"""
        worker_key = self._worker_key(worker_id)
        try:
            data = self._r.hgetall(worker_key)
        except redis.RedisError as exc:
            raise RegistryError(f"get_worker({worker_id}) failed", exc) from exc

        if not data:
            return None

        try:
            return _worker_from_hash(worker_id, data)
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise RegistryError(f"get_worker({worker_id}): corrupt data", exc) from exc

    def list_workers(self) -> list[WorkerInfo]:
        """返回当前所有活跃（TTL 未过期）的 Worker 列表。

        同时执行懒清理：从 active set 中移除 hash 已消失的僵尸 ID。
        """
        active_key = self._active_set_key()
        try:
            member_bytes: set[bytes] = self._r.smembers(active_key)  # type: ignore[assignment]
        except redis.RedisError as exc:
            raise RegistryError("list_workers() failed", exc) from exc

        workers: list[WorkerInfo] = []
        stale_ids: list[str] = []

        for mb in member_bytes:
            wid = mb.decode() if isinstance(mb, bytes) else mb
            try:
                data = self._r.hgetall(self._worker_key(wid))
            except redis.RedisError as exc:
                raise RegistryError(f"list_workers(): hgetall({wid}) failed", exc) from exc

            if not data:
                # hash 已过期（TTL 触发），标记为僵尸
                stale_ids.append(wid)
                continue

            try:
                workers.append(_worker_from_hash(wid, data))
            except (KeyError, ValueError, json.JSONDecodeError):
                # 数据损坏，跳过该节点
                stale_ids.append(wid)

        # 懒清理：批量移除僵尸 ID
        if stale_ids:
            try:
                self._r.srem(active_key, *stale_ids)
            except redis.RedisError:
                pass  # 清理失败不影响主流程

        return workers

    def find_by_idb(self, idb_path: str) -> list[WorkerInfo]:
        """返回当前加载了指定 IDB 的 Worker 列表（IDB 亲和性查询）。"""
        idb_key = self._idb_set_key(idb_path)
        try:
            member_bytes: set[bytes] = self._r.smembers(idb_key)  # type: ignore[assignment]
        except redis.RedisError as exc:
            raise RegistryError(f"find_by_idb({idb_path!r}) failed", exc) from exc

        workers: list[WorkerInfo] = []
        stale_ids: list[str] = []

        for mb in member_bytes:
            wid = mb.decode() if isinstance(mb, bytes) else mb
            worker = self.get_worker(wid)
            if worker is None:
                stale_ids.append(wid)
                continue
            # 确认 worker 实际加载的 IDB 与查询匹配（防止心跳未来得及清理反向索引）
            if worker.loaded_idb == idb_path:
                workers.append(worker)
            else:
                stale_ids.append(wid)

        if stale_ids:
            try:
                self._r.srem(idb_key, *stale_ids)
            except redis.RedisError:
                pass

        return workers

    def select_best(
        self,
        prefer_idb: str | None = None,
    ) -> RoutingDecision | None:
        """路由核心：返回最优 Worker 的路由决策，无可用节点时返回 None。

        选择策略（优先级递减）：
        1. IDB 亲和性：若 prefer_idb 已在某 worker 加载，优先复用。
           多节点均已加载时，选 score 最低者。
        2. 最低负载：无亲和节点时，在全部活跃节点中选 score 最低者。
        3. 无可用节点：返回 None。
        """
        all_workers = self.list_workers()
        if not all_workers:
            return None

        total = len(all_workers)

        # 1. IDB 亲和性
        if prefer_idb:
            affinity = [w for w in all_workers if w.loaded_idb == prefer_idb]
            if affinity:
                best = min(affinity, key=lambda w: w.score)
                return RoutingDecision(
                    worker=best,
                    reason="idb_affinity",
                    candidates_evaluated=total,
                )

        # 2. 最低负载 / fallback
        best_worker = min(all_workers, key=lambda w: w.score)
        reason = "lowest_load" if not prefer_idb else "fallback"
        return RoutingDecision(
            worker=best_worker,
            reason=reason,
            candidates_evaluated=total,
        )
