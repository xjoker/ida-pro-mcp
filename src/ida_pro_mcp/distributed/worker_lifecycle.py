"""
Worker 生命周期管理：注册、心跳、注销。

线程安全，设计为嵌入 idalib_server 启动流程的独立组件，
也可在测试环境中单独实例化（无需 IDA SDK）。

使用方法
--------
    registry = Registry(redis_url)
    lifecycle = WorkerLifecycle(registry, host="127.0.0.1", port=8745)
    lifecycle.start()            # 注册 + 启动心跳线程
    lifecycle.update_loaded_idb("/path/to/binary.i64")
    lifecycle.update_score(1.5)
    lifecycle.stop()             # 注销 + 停止心跳线程
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from .protocol import HeartbeatPayload, WorkerInfo
from .registry import Registry, RegistryError

logger = logging.getLogger(__name__)


class WorkerLifecycle:
    """管理 Worker 注册、心跳续期与注销的生命周期控制器。

    线程安全，幂等。设计目标是嵌入 idalib_server 启动流程，
    也可独立测试（无需 IDA SDK）。

    Parameters
    ----------
    registry:
        已连接的 Registry 实例（包含 Redis 连接池）。
    host:
        本 worker 对外暴露的 HTTP host（Coordinator 用来转发请求）。
    port:
        本 worker 对外暴露的 HTTP port。
    capabilities:
        能力标签元组，默认 ``("idalib", "headless")``。
    heartbeat_interval:
        心跳间隔（秒），默认 5.0 秒。
    """

    def __init__(
        self,
        registry: Registry,
        host: str,
        port: int,
        capabilities: tuple[str, ...] = ("idalib", "headless"),
        heartbeat_interval: float = 5.0,
    ) -> None:
        self._registry = registry
        self._host = host
        self._port = port
        self._capabilities = capabilities
        self._heartbeat_interval = heartbeat_interval

        # 生成 UUID4 hex，整个 worker 生命周期不变（含多次 start/stop 循环）
        self._worker_id: str = uuid.uuid4().hex

        # 可变状态，通过锁保护
        self._lock = threading.Lock()
        self._loaded_idb: str | None = None
        self._score: float = 0.0
        self._in_flight: int = 0

        # 心跳线程控制
        self._stop_event = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._started_at: float = 0.0

    # ---------------------------------------------------------------------- #
    # 公开属性                                                                 #
    # ---------------------------------------------------------------------- #

    @property
    def worker_id(self) -> str:
        """UUID4 hex，整个实例生命周期内不变。"""
        return self._worker_id

    @property
    def is_running(self) -> bool:
        """心跳线程是否在运行。"""
        t = self._heartbeat_thread
        return t is not None and t.is_alive()

    # ---------------------------------------------------------------------- #
    # 生命周期控制                                                              #
    # ---------------------------------------------------------------------- #

    def start(self) -> None:
        """注册到 Registry 并启动心跳 daemon 线程。幂等——重复调用无副作用。"""
        if self.is_running:
            logger.debug("WorkerLifecycle.start() called while already running — no-op")
            return

        self._started_at = time.time()
        self._stop_event.clear()

        # 首次注册
        self._register()

        # 启动心跳线程
        short_id = self._worker_id[:8]
        thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"WorkerHeartbeat-{short_id}",
            daemon=True,
        )
        self._heartbeat_thread = thread
        thread.start()
        logger.info(
            "WorkerLifecycle started: worker_id=%s host=%s port=%d",
            self._worker_id,
            self._host,
            self._port,
        )

    def stop(self) -> None:
        """注销 worker 并停止心跳线程。幂等——可从信号处理器安全调用。"""
        if not self.is_running and self._heartbeat_thread is None:
            logger.debug("WorkerLifecycle.stop() called while not running — no-op")
            return

        # 通知心跳线程退出
        self._stop_event.set()

        t = self._heartbeat_thread
        if t is not None and t.is_alive():
            # 等待线程退出，最多等 2 个心跳周期
            t.join(timeout=self._heartbeat_interval * 2)

        self._heartbeat_thread = None

        # best-effort 注销，失败时记录 warning 不抛
        self._deregister()
        logger.info("WorkerLifecycle stopped: worker_id=%s", self._worker_id)

    # ---------------------------------------------------------------------- #
    # 状态更新（线程安全）                                                      #
    # ---------------------------------------------------------------------- #

    def update_loaded_idb(self, idb_path: str | None) -> None:
        """更新当前加载的 IDB 路径；None 表示无已加载数据库。下次心跳时上报。"""
        with self._lock:
            self._loaded_idb = idb_path
            self._score = self._compute_score()
        logger.debug("WorkerLifecycle: loaded_idb -> %s", idb_path)

    def update_score(self, score: float) -> None:
        """直接设置 score（覆盖自动计算值）。下次心跳时上报。"""
        with self._lock:
            self._score = score
        logger.debug("WorkerLifecycle: score -> %.2f", score)

    def update_in_flight(self, count: int) -> None:
        """更新 in-flight 任务计数，触发 score 重新计算。下次心跳时上报。"""
        with self._lock:
            self._in_flight = count
            self._score = self._compute_score()
        logger.debug("WorkerLifecycle: in_flight -> %d, score -> %.2f", count, self._score)

    # ---------------------------------------------------------------------- #
    # 内部实现                                                                 #
    # ---------------------------------------------------------------------- #

    def _compute_score(self) -> float:
        """score 计算：loaded_idb 存在 +0.5，每个 in-flight 任务 +1.0。

        调用方须在 _lock 保护下调用（已持有锁时）。
        """
        loaded_penalty = 0.5 if self._loaded_idb is not None else 0.0
        return self._in_flight * 1.0 + loaded_penalty

    def _snapshot(self) -> tuple[str | None, float, int]:
        """在锁内原子读取可变状态，返回 (loaded_idb, score, in_flight)。"""
        with self._lock:
            return self._loaded_idb, self._score, self._in_flight

    def _build_worker_info(self) -> WorkerInfo:
        """构造 WorkerInfo 数据类快照。"""
        loaded_idb, score, _ = self._snapshot()
        return WorkerInfo(
            worker_id=self._worker_id,
            host=self._host,
            port=self._port,
            pid=os.getpid(),
            capabilities=self._capabilities,
            loaded_idb=loaded_idb,
            score=score,
            started_at=self._started_at,
            last_heartbeat=time.time(),
        )

    def _build_heartbeat_payload(self) -> HeartbeatPayload:
        """构造 HeartbeatPayload 字典。"""
        loaded_idb, score, in_flight = self._snapshot()
        return HeartbeatPayload(
            worker_id=self._worker_id,
            loaded_idb=loaded_idb,
            score=score,
            in_flight_tasks=in_flight,
        )

    def _register(self) -> None:
        """向 Registry 注册，失败时记录 warning 不抛。"""
        try:
            info = self._build_worker_info()
            self._registry.register(info)
            logger.debug("Registered worker %s with Registry", self._worker_id)
        except RegistryError as exc:
            logger.warning("Failed to register worker %s: %s", self._worker_id, exc)

    def _deregister(self) -> None:
        """向 Registry 注销，失败时记录 warning 不抛（best-effort）。"""
        try:
            self._registry.deregister(self._worker_id)
            logger.debug("Deregistered worker %s from Registry", self._worker_id)
        except RegistryError as exc:
            logger.warning("Failed to deregister worker %s: %s", self._worker_id, exc)

    def _send_heartbeat(self) -> None:
        """发送单次心跳，失败时记录 warning 不抛（防止 Redis 短暂故障导致 worker 崩溃）。"""
        try:
            payload = self._build_heartbeat_payload()
            self._registry.heartbeat(payload)
            logger.debug("Heartbeat sent for worker %s", self._worker_id)
        except RegistryError as exc:
            logger.warning("Heartbeat failed for worker %s: %s", self._worker_id, exc)

    def _heartbeat_loop(self) -> None:
        """心跳线程主循环，每 heartbeat_interval 秒发送一次心跳。"""
        logger.debug(
            "Heartbeat thread started (interval=%.1fs, worker_id=%s)",
            self._heartbeat_interval,
            self._worker_id,
        )
        while not self._stop_event.wait(timeout=self._heartbeat_interval):
            self._send_heartbeat()
        logger.debug("Heartbeat thread exiting for worker %s", self._worker_id)
