"""
WorkerLifecycle 单元测试，使用 fakeredis 与 Registry 真实交互（不 mock Registry）。

覆盖场景：
1.  start/stop 幂等性（重复调用无副作用）
2.  心跳线程实际工作：fakeredis 中 last_heartbeat 字段被更新
3.  update_loaded_idb 反映到下次心跳（registry 查得到新值）
4.  update_score 反映到下次心跳
5.  stop() 后 worker 立即从 registry 消失
6.  异常处理：Registry 底层抛 RegistryError 时 lifecycle 不崩溃，记 warning
7.  信号场景：模拟 SIGTERM → stop 被调
8.  worker_id 不变（多次 start/stop 复用同一 UUID）
"""

from __future__ import annotations

import os
import signal
import threading
import time
import unittest
import logging

import fakeredis

from ida_pro_mcp.distributed.protocol import WorkerInfo
from ida_pro_mcp.distributed.registry import Registry, RegistryError
from ida_pro_mcp.distributed.worker_lifecycle import WorkerLifecycle


# --------------------------------------------------------------------------- #
# 辅助工厂                                                                    #
# --------------------------------------------------------------------------- #


def _fake_registry(namespace: str = "test") -> Registry:
    """创建使用 fakeredis 后端的 Registry，与测试中的 lifecycle 共用同一 FakeServer。"""
    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server)
    reg = Registry.__new__(Registry)
    reg._ns = namespace
    reg._r = fake_client
    return reg


def _make_lifecycle(
    registry: Registry,
    host: str = "127.0.0.1",
    port: int = 18745,
    heartbeat_interval: float = 0.05,   # 测试用短间隔（50ms）
) -> WorkerLifecycle:
    return WorkerLifecycle(
        registry=registry,
        host=host,
        port=port,
        capabilities=("idalib", "headless"),
        heartbeat_interval=heartbeat_interval,
    )


# --------------------------------------------------------------------------- #
# 测试类                                                                      #
# --------------------------------------------------------------------------- #


class TestWorkerLifecycleIdempotent(unittest.TestCase):
    """测试 1：start/stop 幂等性"""

    def test_start_idempotent(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg)
        try:
            lc.start()
            self.assertTrue(lc.is_running)
            # 重复调用 start 不应抛异常，线程仍保持一个
            lc.start()
            self.assertTrue(lc.is_running)
        finally:
            lc.stop()

    def test_stop_idempotent(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg)
        lc.start()
        lc.stop()
        self.assertFalse(lc.is_running)
        # 重复调用 stop 不应抛异常
        lc.stop()
        self.assertFalse(lc.is_running)

    def test_stop_before_start_noop(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg)
        # 从未 start 过，stop 应是 no-op
        lc.stop()
        self.assertFalse(lc.is_running)


class TestWorkerLifecycleHeartbeat(unittest.TestCase):
    """测试 2：心跳线程实际工作，fakeredis 中字段被更新"""

    def test_heartbeat_updates_last_heartbeat(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            # 等待至少 3 次心跳（3 × 50ms = 150ms，留余量等 300ms）
            time.sleep(0.30)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker, "worker 应在 registry 中存在")
            # last_heartbeat 应接近现在（不超过 2 秒前）
            self.assertAlmostEqual(worker.last_heartbeat, time.time(), delta=2.0)
        finally:
            lc.stop()

    def test_worker_registered_on_start(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg)
        try:
            lc.start()
            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertEqual(worker.host, "127.0.0.1")
            self.assertEqual(worker.port, 18745)
            self.assertIn("idalib", worker.capabilities)
        finally:
            lc.stop()


class TestWorkerLifecycleUpdateLoadedIdb(unittest.TestCase):
    """测试 3：update_loaded_idb 反映到下次心跳"""

    def test_update_loaded_idb_reflected_in_registry(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            idb_path = "/tmp/test.i64"
            lc.update_loaded_idb(idb_path)
            # 等待至少 2 次心跳
            time.sleep(0.20)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertEqual(worker.loaded_idb, idb_path)
        finally:
            lc.stop()

    def test_update_loaded_idb_clear(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            lc.update_loaded_idb("/tmp/test.i64")
            time.sleep(0.15)
            lc.update_loaded_idb(None)
            time.sleep(0.15)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertIsNone(worker.loaded_idb)
        finally:
            lc.stop()


class TestWorkerLifecycleUpdateScore(unittest.TestCase):
    """测试 4：update_score 反映到下次心跳"""

    def test_update_score_reflected_in_registry(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            lc.update_score(9.99)
            time.sleep(0.20)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertAlmostEqual(worker.score, 9.99, places=2)
        finally:
            lc.stop()

    def test_score_auto_computed_from_in_flight(self):
        """update_in_flight 会自动重算 score。"""
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            lc.update_in_flight(3)   # score = 3.0
            time.sleep(0.20)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertAlmostEqual(worker.score, 3.0, places=2)
        finally:
            lc.stop()

    def test_score_with_loaded_idb(self):
        """loaded_idb 存在时 score 额外 +0.5。"""
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        try:
            lc.start()
            lc.update_loaded_idb("/tmp/x.i64")  # +0.5
            lc.update_in_flight(2)               # +2.0 → total 2.5
            time.sleep(0.20)

            worker = reg.get_worker(lc.worker_id)
            self.assertIsNotNone(worker)
            self.assertAlmostEqual(worker.score, 2.5, places=2)
        finally:
            lc.stop()


class TestWorkerLifecycleStop(unittest.TestCase):
    """测试 5：stop() 后 worker 立即从 registry 消失"""

    def test_worker_deregistered_on_stop(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        lc.start()

        # 确认已注册
        self.assertIsNotNone(reg.get_worker(lc.worker_id))

        lc.stop()
        self.assertFalse(lc.is_running)

        # 注销后 Registry 中不应再有该 worker
        worker = reg.get_worker(lc.worker_id)
        self.assertIsNone(worker, "stop() 后 worker 应从 registry 消失")

    def test_worker_not_in_active_set_after_stop(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        lc.start()
        lc.stop()

        active = reg.list_workers()
        ids = [w.worker_id for w in active]
        self.assertNotIn(lc.worker_id, ids)


class TestWorkerLifecycleErrorHandling(unittest.TestCase):
    """测试 6：Registry 抛 RegistryError 时 lifecycle 不崩溃，记 warning"""

    def _make_failing_registry(self) -> Registry:
        """构造一个所有写操作都抛 RegistryError 的 Registry stub。"""
        from unittest.mock import MagicMock

        reg = MagicMock(spec=Registry)
        reg.register.side_effect = RegistryError("simulated register failure")
        reg.heartbeat.side_effect = RegistryError("simulated heartbeat failure")
        reg.deregister.side_effect = RegistryError("simulated deregister failure")
        return reg

    def test_start_does_not_crash_on_registry_error(self):
        """注册失败时 start 不抛异常，心跳线程正常启动。"""
        reg = self._make_failing_registry()
        lc = WorkerLifecycle(registry=reg, host="127.0.0.1", port=18745, heartbeat_interval=0.05)
        try:
            lc.start()  # 不应抛
            self.assertTrue(lc.is_running)
        finally:
            lc.stop()  # stop 也不应抛

    def test_heartbeat_does_not_crash_on_registry_error(self):
        """心跳持续失败时线程不崩溃，is_running 保持 True。"""
        reg = self._make_failing_registry()
        lc = WorkerLifecycle(registry=reg, host="127.0.0.1", port=18745, heartbeat_interval=0.05)
        try:
            lc.start()
            time.sleep(0.25)  # 经历多次心跳失败
            self.assertTrue(lc.is_running, "心跳失败不应导致线程退出")
        finally:
            lc.stop()

    def test_warning_logged_on_register_failure(self):
        reg = self._make_failing_registry()
        lc = WorkerLifecycle(registry=reg, host="127.0.0.1", port=18745, heartbeat_interval=0.5)
        with self.assertLogs("ida_pro_mcp.distributed.worker_lifecycle", level=logging.WARNING):
            lc.start()
        lc.stop()

    def test_stop_does_not_crash_on_deregister_failure(self):
        """注销失败时 stop 不抛异常。"""
        reg = self._make_failing_registry()
        lc = WorkerLifecycle(registry=reg, host="127.0.0.1", port=18745, heartbeat_interval=0.05)
        lc.start()
        lc.stop()  # 不应抛
        self.assertFalse(lc.is_running)


class TestWorkerLifecycleSignal(unittest.TestCase):
    """测试 7：信号场景 — SIGTERM 触发 stop"""

    def test_sigterm_triggers_stop(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)
        lc.start()
        self.assertTrue(lc.is_running)

        # 安装信号处理器，模拟 idalib_server 的 cleanup_and_exit
        stop_called = threading.Event()

        def _handler(signum, frame):
            lc.stop()
            stop_called.set()

        original = signal.signal(signal.SIGTERM, _handler)
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            stop_called.wait(timeout=2.0)
            self.assertTrue(stop_called.is_set(), "SIGTERM handler 应被调用")
            self.assertFalse(lc.is_running, "stop() 应在 SIGTERM 后执行")
        finally:
            signal.signal(signal.SIGTERM, original)


class TestWorkerLifecycleWorkerId(unittest.TestCase):
    """测试 8：worker_id 不变（多次 start/stop 用同一个 UUID）"""

    def test_worker_id_stable_across_start_stop(self):
        reg = _fake_registry()
        lc = _make_lifecycle(reg, heartbeat_interval=0.05)

        wid = lc.worker_id  # 首次读取
        self.assertIsInstance(wid, str)
        self.assertEqual(len(wid), 32, "UUID4 hex 应为 32 字符")

        lc.start()
        self.assertEqual(lc.worker_id, wid, "start 后 worker_id 不变")
        lc.stop()
        self.assertEqual(lc.worker_id, wid, "stop 后 worker_id 不变")

        # 第二次 start/stop 循环
        lc.start()
        self.assertEqual(lc.worker_id, wid, "第二次 start 后 worker_id 仍不变")
        lc.stop()
        self.assertEqual(lc.worker_id, wid, "第二次 stop 后 worker_id 仍不变")

    def test_different_instances_have_different_worker_ids(self):
        reg = _fake_registry()
        lc1 = _make_lifecycle(reg)
        lc2 = _make_lifecycle(reg)
        self.assertNotEqual(lc1.worker_id, lc2.worker_id)


if __name__ == "__main__":
    unittest.main()
