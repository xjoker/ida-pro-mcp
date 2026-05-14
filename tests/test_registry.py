"""
Registry 单元测试，使用 fakeredis 模拟 Redis。

覆盖场景：
- 基础 CRUD（register / get_worker / deregister）
- 心跳续期与字段更新
- list_workers 过滤已过期节点
- find_by_idb IDB 反向索引
- select_best 三种路由策略（IDB 亲和 / 最低负载 / 无可用）
- 并发同 ID register 覆盖行为
- RegistryError 包装
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

import fakeredis

from ida_pro_mcp.distributed.protocol import (
    HeartbeatPayload,
    RoutingDecision,
    WorkerInfo,
)
from ida_pro_mcp.distributed.registry import Registry, RegistryError


# --------------------------------------------------------------------------- #
# 辅助函数                                                                    #
# --------------------------------------------------------------------------- #


def _fake_registry(namespace: str = "test") -> Registry:
    """创建一个使用 fakeredis 后端的 Registry 实例。"""
    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server)

    reg = Registry.__new__(Registry)
    reg._ns = namespace
    reg._r = fake_client
    return reg


def _make_worker(
    worker_id: str = "worker-001",
    host: str = "127.0.0.1",
    port: int = 13337,
    pid: int = 1234,
    capabilities: tuple[str, ...] = ("idalib", "x86_64"),
    loaded_idb: str | None = None,
    score: float = 0.5,
    started_at: float | None = None,
    last_heartbeat: float | None = None,
) -> WorkerInfo:
    now = time.time()
    return WorkerInfo(
        worker_id=worker_id,
        host=host,
        port=port,
        pid=pid,
        capabilities=capabilities,
        loaded_idb=loaded_idb,
        score=score,
        started_at=started_at or now,
        last_heartbeat=last_heartbeat or now,
    )


def _make_heartbeat(
    worker_id: str = "worker-001",
    loaded_idb: str | None = None,
    score: float = 0.5,
    in_flight_tasks: int = 0,
) -> HeartbeatPayload:
    return HeartbeatPayload(
        worker_id=worker_id,
        loaded_idb=loaded_idb,
        score=score,
        in_flight_tasks=in_flight_tasks,
    )


# --------------------------------------------------------------------------- #
# 测试类                                                                      #
# --------------------------------------------------------------------------- #


class TestRegisterAndGet(unittest.TestCase):
    """register / get_worker 基础流程。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_register_and_get(self) -> None:
        """register 后 get_worker 应返回相同信息。"""
        w = _make_worker()
        self.reg.register(w)
        got = self.reg.get_worker(w.worker_id)

        self.assertIsNotNone(got)
        assert got is not None
        self.assertEqual(got.worker_id, w.worker_id)
        self.assertEqual(got.host, w.host)
        self.assertEqual(got.port, w.port)
        self.assertEqual(got.pid, w.pid)
        self.assertEqual(got.capabilities, w.capabilities)
        self.assertIsNone(got.loaded_idb)
        self.assertAlmostEqual(got.score, w.score, places=4)

    def test_get_nonexistent(self) -> None:
        """查询不存在的 worker_id 应返回 None。"""
        result = self.reg.get_worker("ghost-id")
        self.assertIsNone(result)

    def test_register_with_idb(self) -> None:
        """register 时包含 loaded_idb，get_worker 应正确还原。"""
        w = _make_worker(loaded_idb="/projects/target.idb")
        self.reg.register(w)
        got = self.reg.get_worker(w.worker_id)

        self.assertIsNotNone(got)
        assert got is not None
        self.assertEqual(got.loaded_idb, "/projects/target.idb")

    def test_register_same_id_overwrites(self) -> None:
        """同 worker_id 二次 register 应覆盖旧数据（不报错，不重复条目）。"""
        w1 = _make_worker(score=0.1)
        w2 = _make_worker(score=0.9)  # 同 ID，不同 score

        self.reg.register(w1)
        self.reg.register(w2)

        got = self.reg.get_worker(w1.worker_id)
        self.assertIsNotNone(got)
        assert got is not None
        self.assertAlmostEqual(got.score, 0.9, places=4)

        # active set 中不应有重复
        workers = self.reg.list_workers()
        self.assertEqual(len(workers), 1)


class TestDeregister(unittest.TestCase):
    """deregister 基础流程。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_deregister_removes_worker(self) -> None:
        """deregister 后 get_worker 应返回 None，list_workers 不包含该节点。"""
        w = _make_worker()
        self.reg.register(w)
        self.reg.deregister(w.worker_id)

        self.assertIsNone(self.reg.get_worker(w.worker_id))
        self.assertEqual(self.reg.list_workers(), [])

    def test_deregister_nonexistent_is_safe(self) -> None:
        """注销不存在的 ID 不应抛出异常。"""
        try:
            self.reg.deregister("ghost-id")
        except RegistryError:
            self.fail("deregister() should not raise for non-existent worker")

    def test_deregister_cleans_idb_index(self) -> None:
        """deregister 后 IDB 反向索引应同步清理。"""
        idb = "/data/sample.idb"
        w = _make_worker(loaded_idb=idb)
        self.reg.register(w)
        self.reg.deregister(w.worker_id)

        found = self.reg.find_by_idb(idb)
        self.assertEqual(found, [])


class TestHeartbeat(unittest.TestCase):
    """heartbeat 续期与字段更新。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_heartbeat_updates_score(self) -> None:
        """heartbeat 应更新 score 字段。"""
        w = _make_worker(score=0.3)
        self.reg.register(w)

        hb = _make_heartbeat(worker_id=w.worker_id, score=0.8)
        self.reg.heartbeat(hb)

        got = self.reg.get_worker(w.worker_id)
        self.assertIsNotNone(got)
        assert got is not None
        self.assertAlmostEqual(got.score, 0.8, places=4)

    def test_heartbeat_updates_loaded_idb(self) -> None:
        """heartbeat 应更新 loaded_idb 并同步 IDB 反向索引。"""
        w = _make_worker()
        self.reg.register(w)

        idb = "/new/project.idb"
        hb = _make_heartbeat(worker_id=w.worker_id, loaded_idb=idb)
        self.reg.heartbeat(hb)

        got = self.reg.get_worker(w.worker_id)
        self.assertIsNotNone(got)
        assert got is not None
        self.assertEqual(got.loaded_idb, idb)

        found = self.reg.find_by_idb(idb)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].worker_id, w.worker_id)

    def test_heartbeat_clears_old_idb_index(self) -> None:
        """heartbeat 切换 IDB 时，旧 IDB 的反向索引应被清除。"""
        old_idb = "/old/project.idb"
        new_idb = "/new/project.idb"

        w = _make_worker(loaded_idb=old_idb)
        self.reg.register(w)

        hb = _make_heartbeat(worker_id=w.worker_id, loaded_idb=new_idb)
        self.reg.heartbeat(hb)

        self.assertEqual(self.reg.find_by_idb(old_idb), [])
        self.assertEqual(len(self.reg.find_by_idb(new_idb)), 1)

    def test_heartbeat_nonexistent_worker_is_safe(self) -> None:
        """对不存在节点的心跳应静默忽略，不抛异常。"""
        hb = _make_heartbeat(worker_id="ghost-id")
        try:
            self.reg.heartbeat(hb)
        except RegistryError:
            self.fail("heartbeat() should not raise for non-existent worker")


class TestListWorkers(unittest.TestCase):
    """list_workers 过滤过期节点。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_list_empty(self) -> None:
        """无注册节点时应返回空列表。"""
        self.assertEqual(self.reg.list_workers(), [])

    def test_list_multiple(self) -> None:
        """多节点全部活跃时应全部返回。"""
        w1 = _make_worker(worker_id="a", port=13337)
        w2 = _make_worker(worker_id="b", port=13338)
        self.reg.register(w1)
        self.reg.register(w2)

        workers = self.reg.list_workers()
        ids = {w.worker_id for w in workers}
        self.assertEqual(ids, {"a", "b"})

    def test_list_filters_expired(self) -> None:
        """已过期节点（TTL 触发后 hash 消失）不应出现在返回列表中。"""
        w = _make_worker(worker_id="expiring")
        self.reg.register(w)

        # 模拟过期：直接删除 Redis hash，active set 保留（懒清理场景）
        self.reg._r.delete(self.reg._worker_key(w.worker_id))

        workers = self.reg.list_workers()
        ids = [x.worker_id for x in workers]
        self.assertNotIn("expiring", ids)


class TestFindByIdb(unittest.TestCase):
    """find_by_idb IDB 反向索引查询。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_find_by_idb_basic(self) -> None:
        """注册加载了 IDB 的 worker 后，find_by_idb 应能找到它。"""
        idb = "/projects/crackme.idb"
        w = _make_worker(loaded_idb=idb)
        self.reg.register(w)

        found = self.reg.find_by_idb(idb)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].worker_id, w.worker_id)

    def test_find_by_idb_no_match(self) -> None:
        """未加载任何 IDB 时，find_by_idb 应返回空列表。"""
        w = _make_worker()
        self.reg.register(w)

        found = self.reg.find_by_idb("/projects/other.idb")
        self.assertEqual(found, [])

    def test_find_by_idb_multiple_workers(self) -> None:
        """同一 IDB 被多个 worker 加载时，find_by_idb 应全部返回。"""
        idb = "/shared/firmware.idb"
        w1 = _make_worker(worker_id="w1", port=13337, loaded_idb=idb)
        w2 = _make_worker(worker_id="w2", port=13338, loaded_idb=idb)
        self.reg.register(w1)
        self.reg.register(w2)

        found = self.reg.find_by_idb(idb)
        ids = {w.worker_id for w in found}
        self.assertEqual(ids, {"w1", "w2"})


class TestSelectBest(unittest.TestCase):
    """select_best 三种路由策略。"""

    def setUp(self) -> None:
        self.reg = _fake_registry()

    def test_select_best_no_workers(self) -> None:
        """无 worker 时应返回 None。"""
        result = self.reg.select_best()
        self.assertIsNone(result)

    def test_select_best_lowest_load(self) -> None:
        """无 prefer_idb 时选 score 最低的节点，reason="lowest_load"。"""
        w_low = _make_worker(worker_id="low", port=13337, score=0.1)
        w_high = _make_worker(worker_id="high", port=13338, score=0.9)
        self.reg.register(w_low)
        self.reg.register(w_high)

        decision = self.reg.select_best()
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(decision.worker.worker_id, "low")
        self.assertEqual(decision.reason, "lowest_load")
        self.assertEqual(decision.candidates_evaluated, 2)

    def test_select_best_idb_affinity(self) -> None:
        """有 prefer_idb 且有节点已加载该 IDB 时，reason="idb_affinity"。"""
        idb = "/projects/target.idb"
        w_affinity = _make_worker(worker_id="affinity", port=13337, score=0.8, loaded_idb=idb)
        w_free = _make_worker(worker_id="free", port=13338, score=0.1)
        self.reg.register(w_affinity)
        self.reg.register(w_free)

        decision = self.reg.select_best(prefer_idb=idb)
        self.assertIsNotNone(decision)
        assert decision is not None
        # 即使 affinity 节点 score 更高，也应选择它
        self.assertEqual(decision.worker.worker_id, "affinity")
        self.assertEqual(decision.reason, "idb_affinity")

    def test_select_best_fallback(self) -> None:
        """有 prefer_idb 但无节点加载该 IDB 时，回退到负载最低节点，reason="fallback"。"""
        w1 = _make_worker(worker_id="w1", port=13337, score=0.3)
        w2 = _make_worker(worker_id="w2", port=13338, score=0.7)
        self.reg.register(w1)
        self.reg.register(w2)

        decision = self.reg.select_best(prefer_idb="/nonexistent.idb")
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(decision.worker.worker_id, "w1")
        self.assertEqual(decision.reason, "fallback")

    def test_select_best_idb_affinity_picks_lowest_score_among_affinity(self) -> None:
        """多个 worker 均加载同一 IDB 时，选 score 最低者。"""
        idb = "/multi/load.idb"
        w1 = _make_worker(worker_id="a", port=13337, score=0.6, loaded_idb=idb)
        w2 = _make_worker(worker_id="b", port=13338, score=0.2, loaded_idb=idb)
        self.reg.register(w1)
        self.reg.register(w2)

        decision = self.reg.select_best(prefer_idb=idb)
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(decision.worker.worker_id, "b")
        self.assertEqual(decision.reason, "idb_affinity")


class TestRegistryError(unittest.TestCase):
    """RegistryError 异常包装验证。"""

    def test_registry_error_wraps_cause(self) -> None:
        """RegistryError 应包含原始 cause 异常。"""
        cause = ValueError("original error")
        err = RegistryError("wrapped", cause)

        self.assertIs(err.cause, cause)
        self.assertIn("original error", str(err))

    def test_registry_error_without_cause(self) -> None:
        """无 cause 的 RegistryError 仍应正常工作。"""
        err = RegistryError("standalone error")
        self.assertIsNone(err.cause)
        self.assertIn("standalone error", str(err))


if __name__ == "__main__":
    unittest.main(verbosity=2)
