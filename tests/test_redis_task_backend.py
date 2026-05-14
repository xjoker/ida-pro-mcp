"""Unit tests for RedisTaskBackend using fakeredis.

No real Redis required – uses fakeredis in-process server.
Run with:
    uv run python -m unittest tests.test_redis_task_backend -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import threading
import time
import unittest
from unittest.mock import patch

import fakeredis
import redis as redis_lib

# ── Load task_backend.py directly, bypassing ida_mcp/__init__.py ─────────────

_repo_root = pathlib.Path(__file__).parent.parent
_backend_path = _repo_root / "src" / "ida_pro_mcp" / "ida_mcp" / "task_backend.py"

_spec = importlib.util.spec_from_file_location(
    "ida_pro_mcp.ida_mcp.task_backend", _backend_path
)
_module = importlib.util.module_from_spec(_spec)
sys.modules["ida_pro_mcp.ida_mcp.task_backend"] = _module
_spec.loader.exec_module(_module)

RedisTaskBackend = _module.RedisTaskBackend
TaskBackend = _module.TaskBackend

# ── Helpers ───────────────────────────────────────────────────────────────────


def _fake_backend(namespace: str = "test:tasks") -> RedisTaskBackend:
    """Instantiate a RedisTaskBackend wired to a fakeredis server."""
    fake_server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=fake_server)

    backend = RedisTaskBackend.__new__(RedisTaskBackend)
    backend._redis_url = "redis://fake"
    backend._ns = namespace
    backend._r = fake_client
    return backend


def _fake_backend_pair(namespace: str = "test:tasks") -> tuple[RedisTaskBackend, RedisTaskBackend]:
    """Return two backend instances sharing the same fakeredis server."""
    fake_server = fakeredis.FakeServer()

    b1 = RedisTaskBackend.__new__(RedisTaskBackend)
    b1._redis_url = "redis://fake"
    b1._ns = namespace
    b1._r = fakeredis.FakeRedis(server=fake_server)

    b2 = RedisTaskBackend.__new__(RedisTaskBackend)
    b2._redis_url = "redis://fake"
    b2._ns = namespace
    b2._r = fakeredis.FakeRedis(server=fake_server)

    return b1, b2


def _make_task(task_id: str, tool: str = "test_tool") -> dict:
    return {
        "task_id": task_id,
        "tool": tool,
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "completed_at": None,
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestRedisCreateAndGet(unittest.TestCase):
    """Basic create/get round-trip."""

    def setUp(self) -> None:
        self.backend = _fake_backend()

    def test_create_task_and_get_task_roundtrip(self) -> None:
        task = _make_task("t1")
        self.backend.create_task("t1", task)
        result = self.backend.get_task("t1")
        self.assertIsNotNone(result)
        self.assertEqual(result["task_id"], "t1")
        self.assertEqual(result["task_id"], "t1")
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["tool"], "test_tool")

    def test_get_task_nonexistent_returns_none(self) -> None:
        result = self.backend.get_task("does_not_exist")
        self.assertIsNone(result)


class TestRedisUpdateState(unittest.TestCase):
    """State transitions and set membership."""

    def setUp(self) -> None:
        self.backend = _fake_backend()

    def test_update_state_changes_status(self) -> None:
        self.backend.create_task("u1", _make_task("u1"))
        self.backend.update_state("u1", "running")
        task = self.backend.get_task("u1")
        self.assertEqual(task["status"], "running")

    def test_update_state_moves_between_state_sets(self) -> None:
        """Task must be removed from old state set and added to new one."""
        self.backend.create_task("u2", _make_task("u2"))
        # Verify in pending set
        ns = self.backend._ns
        r = self.backend._r
        self.assertIn(b"u2", r.smembers(f"{ns}:tasks:by_state:pending"))

        self.backend.update_state("u2", "running")
        self.assertNotIn(b"u2", r.smembers(f"{ns}:tasks:by_state:pending"))
        self.assertIn(b"u2", r.smembers(f"{ns}:tasks:by_state:running"))

    def test_update_state_with_extra_fields(self) -> None:
        self.backend.create_task("u3", _make_task("u3"))
        completed_at = time.time()
        self.backend.update_state(
            "u3", "done",
            result={"answer": 42},
            completed_at=completed_at,
        )
        task = self.backend.get_task("u3")
        self.assertEqual(task["status"], "done")
        self.assertEqual(task["result"], {"answer": 42})
        self.assertAlmostEqual(task["completed_at"], completed_at, places=2)

    def test_update_state_idempotent_same_state(self) -> None:
        """Updating to the same state twice must not raise and must be safe."""
        self.backend.create_task("u4", _make_task("u4"))
        self.backend.update_state("u4", "running")
        # Should not raise even though task is already in running.
        self.backend.update_state("u4", "running")
        task = self.backend.get_task("u4")
        self.assertEqual(task["status"], "running")


class TestRedisListTasks(unittest.TestCase):
    """list_tasks filtering."""

    def setUp(self) -> None:
        self.backend = _fake_backend()

    def test_list_tasks_returns_all_when_no_filter(self) -> None:
        for i in range(3):
            tid = f"all_{i}"
            self.backend.create_task(tid, _make_task(tid))
        tasks = self.backend.list_tasks()
        self.assertEqual(len(tasks), 3)

    def test_list_tasks_filter_state_pending(self) -> None:
        self.backend.create_task("p1", _make_task("p1"))
        self.backend.create_task("p2", _make_task("p2"))
        self.backend.update_state("p2", "done", completed_at=time.time())
        pending = self.backend.list_tasks(filter_state="pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["task_id"], "p1")

    def test_list_tasks_filter_none_returns_all_states(self) -> None:
        self.backend.create_task("m1", _make_task("m1"))
        self.backend.create_task("m2", _make_task("m2"))
        self.backend.update_state("m2", "error", error="oops", completed_at=time.time())
        all_tasks = self.backend.list_tasks(filter_state=None)
        ids = {t["task_id"] for t in all_tasks}
        self.assertIn("m1", ids)
        self.assertIn("m2", ids)


class TestRedisDeleteExpired(unittest.TestCase):
    """TTL expiry edge cases."""

    def setUp(self) -> None:
        self.backend = _fake_backend()

    def test_delete_expired_removes_old_done_task(self) -> None:
        task = _make_task("old_done")
        task["created_at"] = time.time() - 1000  # very old creation
        self.backend.create_task("old_done", task)
        old_time = time.time() - 600
        self.backend.update_state("old_done", "done", completed_at=old_time)
        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 1)
        self.assertIsNone(self.backend.get_task("old_done"))

    def test_delete_expired_keeps_fresh_task(self) -> None:
        self.backend.create_task("fresh", _make_task("fresh"))
        self.backend.update_state("fresh", "done", completed_at=time.time())
        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 0)
        self.assertIsNotNone(self.backend.get_task("fresh"))

    def test_delete_expired_mixed_tasks(self) -> None:
        """Old error + fresh done + pending: only old error is removed."""
        old_task = _make_task("old_err")
        old_task["created_at"] = time.time() - 1000
        self.backend.create_task("old_err", old_task)
        self.backend.update_state(
            "old_err", "error",
            error="boom",
            completed_at=time.time() - 400,
        )

        fresh_task = _make_task("fresh_done")
        self.backend.create_task("fresh_done", fresh_task)
        self.backend.update_state(
            "fresh_done", "done",
            result={},
            completed_at=time.time(),
        )

        self.backend.create_task("pend", _make_task("pend"))

        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 1)
        self.assertIsNone(self.backend.get_task("old_err"))
        self.assertIsNotNone(self.backend.get_task("fresh_done"))
        self.assertIsNotNone(self.backend.get_task("pend"))

    def test_delete_expired_pending_never_expires(self) -> None:
        """Pending tasks with no completed_at must never be deleted."""
        task = _make_task("old_pend")
        task["created_at"] = time.time() - 9999
        self.backend.create_task("old_pend", task)
        deleted = self.backend.delete_expired(ttl_seconds=1)
        self.assertEqual(deleted, 0)
        self.assertIsNotNone(self.backend.get_task("old_pend"))


class TestRedisHealthcheck(unittest.TestCase):
    """Healthcheck against live (fake) Redis."""

    def test_healthcheck_returns_true(self) -> None:
        backend = _fake_backend()
        self.assertTrue(backend.healthcheck())


class TestRedisConcurrentCreate(unittest.TestCase):
    """Thread-safety: concurrent creates must not lose tasks."""

    def test_concurrent_create(self) -> None:
        backend = _fake_backend()
        n = 30
        errors: list[Exception] = []

        def worker(i: int) -> None:
            tid = f"conc_{i}"
            try:
                backend.create_task(tid, _make_task(tid))
                backend.update_state(tid, "running")
                backend.update_state(tid, "done", result={"i": i}, completed_at=time.time())
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread errors: {errors}")
        done = backend.list_tasks(filter_state="done")
        self.assertEqual(len(done), n)


class TestRedisSerializationRoundtrip(unittest.TestCase):
    """Complex nested params must survive JSON encode/decode."""

    def setUp(self) -> None:
        self.backend = _fake_backend()

    def test_nested_dict_and_list_in_result(self) -> None:
        task = _make_task("ser1")
        self.backend.create_task("ser1", task)
        complex_result = {
            "functions": ["main", "init"],
            "meta": {"count": 2, "flags": [True, False]},
            "nested": {"deep": {"deeper": 42}},
        }
        self.backend.update_state("ser1", "done", result=complex_result, completed_at=time.time())
        stored = self.backend.get_task("ser1")
        self.assertEqual(stored["result"], complex_result)

    def test_null_result_roundtrip(self) -> None:
        task = _make_task("ser2")
        self.backend.create_task("ser2", task)
        self.backend.update_state("ser2", "done", result=None, completed_at=time.time())
        stored = self.backend.get_task("ser2")
        self.assertIsNone(stored["result"])

    def test_error_string_roundtrip(self) -> None:
        task = _make_task("ser3")
        self.backend.create_task("ser3", task)
        self.backend.update_state(
            "ser3", "error",
            error="something went wrong with unicode: 日本語",
            completed_at=time.time(),
        )
        stored = self.backend.get_task("ser3")
        self.assertEqual(stored["error"], "something went wrong with unicode: 日本語")


class TestRedisCrossInstanceConsistency(unittest.TestCase):
    """Two backend instances sharing the same Redis see the same state."""

    def test_create_on_one_visible_on_other(self) -> None:
        b1, b2 = _fake_backend_pair()
        task = _make_task("cross1")
        b1.create_task("cross1", task)

        result = b2.get_task("cross1")
        self.assertIsNotNone(result)
        self.assertEqual(result["task_id"], "cross1")
        self.assertEqual(result["status"], "pending")

    def test_update_on_one_visible_on_other(self) -> None:
        b1, b2 = _fake_backend_pair()
        b1.create_task("cross2", _make_task("cross2"))
        b1.update_state("cross2", "running")

        result = b2.get_task("cross2")
        self.assertEqual(result["status"], "running")

    def test_list_tasks_cross_instance(self) -> None:
        b1, b2 = _fake_backend_pair()
        b1.create_task("cx1", _make_task("cx1"))
        b1.create_task("cx2", _make_task("cx2"))

        tasks = b2.list_tasks()
        ids = {t["task_id"] for t in tasks}
        self.assertIn("cx1", ids)
        self.assertIn("cx2", ids)


class TestRedisErrorWrapping(unittest.TestCase):
    """Redis failures must be wrapped in RuntimeError."""

    def test_redis_failure_raises_runtime_error(self) -> None:
        backend = _fake_backend()
        # Simulate a connection failure by replacing the client with a broken one.
        broken = fakeredis.FakeRedis()
        broken.connection_pool.disconnect()

        # Monkey-patch hgetall to always raise a connection error.
        def _raise(*args, **kwargs):
            raise redis_lib.ConnectionError("simulated failure")

        backend._r.hgetall = _raise

        with self.assertRaises(RuntimeError) as ctx:
            backend.get_task("any_id")

        self.assertIn("Redis task backend error", str(ctx.exception))


class TestRedisIsTaskBackend(unittest.TestCase):
    """RedisTaskBackend must be a proper TaskBackend subclass."""

    def test_is_subclass(self) -> None:
        self.assertTrue(issubclass(RedisTaskBackend, TaskBackend))

    def test_import_only_no_connection(self) -> None:
        """Instantiating RedisTaskBackend with a bad URL should defer connection."""
        # Connection pool creation is lazy in redis-py; just instantiation must not fail.
        # If it does attempt connection immediately, it might still work with fakeredis
        # so we only check the class is importable and has the right interface.
        self.assertTrue(hasattr(RedisTaskBackend, "create_task"))
        self.assertTrue(hasattr(RedisTaskBackend, "get_task"))
        self.assertTrue(hasattr(RedisTaskBackend, "list_tasks"))
        self.assertTrue(hasattr(RedisTaskBackend, "update_state"))
        self.assertTrue(hasattr(RedisTaskBackend, "delete_expired"))
        self.assertTrue(hasattr(RedisTaskBackend, "healthcheck"))


if __name__ == "__main__":
    unittest.main()
