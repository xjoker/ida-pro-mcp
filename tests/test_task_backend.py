"""Unit tests for InMemoryTaskBackend (and RedisTaskBackend stub).

No IDA dependency – pure Python only.
Run with:
    uv run python -m unittest tests.test_task_backend -v
"""
import importlib.util
import pathlib
import sys
import threading
import time
import unittest

# ── Load task_backend.py directly, bypassing ida_mcp/__init__.py ─────────────
# __init__.py imports idaapi (IDA-only), which is unavailable in plain Python.
# task_backend.py itself has no IDA dependency, so we load it in isolation.

_repo_root = pathlib.Path(__file__).parent.parent
_backend_path = _repo_root / "src" / "ida_pro_mcp" / "ida_mcp" / "task_backend.py"

_spec = importlib.util.spec_from_file_location(
    "ida_pro_mcp.ida_mcp.task_backend", _backend_path
)
_module = importlib.util.module_from_spec(_spec)
sys.modules["ida_pro_mcp.ida_mcp.task_backend"] = _module
_spec.loader.exec_module(_module)

TaskBackend = _module.TaskBackend
InMemoryTaskBackend = _module.InMemoryTaskBackend
RedisTaskBackend = _module.RedisTaskBackend

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_task(task_id: str, tool: str = "test_tool") -> dict:
    return {
        "task_id": task_id,
        "tool": tool,
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": time.monotonic(),
        "completed_at": None,
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestInMemoryTaskBackendCRUD(unittest.TestCase):
    """Complete CRUD round-trip tests."""

    def setUp(self) -> None:
        self.backend = InMemoryTaskBackend()

    def test_create_and_get_task(self) -> None:
        task = _make_task("task1")
        self.backend.create_task("task1", task)
        result = self.backend.get_task("task1")
        self.assertIsNotNone(result)
        self.assertEqual(result["task_id"], "task1")
        self.assertEqual(result["status"], "pending")

    def test_get_task_returns_copy(self) -> None:
        """Mutation of returned dict must not affect stored state."""
        task = _make_task("task2")
        self.backend.create_task("task2", task)
        fetched = self.backend.get_task("task2")
        fetched["status"] = "corrupted"
        self.assertEqual(self.backend.get_task("task2")["status"], "pending")

    def test_update_state_changes_status(self) -> None:
        task = _make_task("task3")
        self.backend.create_task("task3", task)
        self.backend.update_state("task3", "running")
        self.assertEqual(self.backend.get_task("task3")["status"], "running")

    def test_update_state_with_extra_fields(self) -> None:
        task = _make_task("task4")
        self.backend.create_task("task4", task)
        completed_at = time.monotonic()
        self.backend.update_state(
            "task4", "done", result={"data": 42}, completed_at=completed_at
        )
        stored = self.backend.get_task("task4")
        self.assertEqual(stored["status"], "done")
        self.assertEqual(stored["result"], {"data": 42})
        self.assertAlmostEqual(stored["completed_at"], completed_at, places=3)

    def test_get_nonexistent_task_returns_none(self) -> None:
        result = self.backend.get_task("does_not_exist")
        self.assertIsNone(result)

    def test_list_tasks_all(self) -> None:
        for i in range(3):
            t = _make_task(f"lt_{i}")
            self.backend.create_task(f"lt_{i}", t)
        tasks = self.backend.list_tasks()
        self.assertEqual(len(tasks), 3)

    def test_list_tasks_filter_by_state(self) -> None:
        self.backend.create_task("f1", _make_task("f1"))
        self.backend.create_task("f2", _make_task("f2"))
        self.backend.update_state("f2", "done", completed_at=time.monotonic())
        pending = self.backend.list_tasks(filter_state="pending")
        done = self.backend.list_tasks(filter_state="done")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["task_id"], "f1")
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["task_id"], "f2")

    def test_healthcheck_returns_true(self) -> None:
        self.assertTrue(self.backend.healthcheck())


class TestDeleteExpired(unittest.TestCase):
    """TTL expiry edge cases."""

    def setUp(self) -> None:
        self.backend = InMemoryTaskBackend()

    def test_delete_expired_removes_old_done_task(self) -> None:
        task = _make_task("old_done")
        self.backend.create_task("old_done", task)
        old_time = time.monotonic() - 600
        self.backend.update_state("old_done", "done", completed_at=old_time)
        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 1)
        self.assertIsNone(self.backend.get_task("old_done"))

    def test_delete_expired_keeps_fresh_done_task(self) -> None:
        task = _make_task("fresh_done")
        self.backend.create_task("fresh_done", task)
        self.backend.update_state(
            "fresh_done", "done", completed_at=time.monotonic()
        )
        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 0)
        self.assertIsNotNone(self.backend.get_task("fresh_done"))

    def test_delete_expired_mixed(self) -> None:
        """Old error + fresh done + pending: only old error is removed."""
        self.backend.create_task("old_err", _make_task("old_err"))
        self.backend.update_state(
            "old_err", "error",
            error="boom",
            completed_at=time.monotonic() - 400,
        )
        self.backend.create_task("new_done", _make_task("new_done"))
        self.backend.update_state(
            "new_done", "done",
            result={},
            completed_at=time.monotonic(),
        )
        self.backend.create_task("pend", _make_task("pend"))

        deleted = self.backend.delete_expired(ttl_seconds=300)
        self.assertEqual(deleted, 1)
        self.assertIsNone(self.backend.get_task("old_err"))
        self.assertIsNotNone(self.backend.get_task("new_done"))
        self.assertIsNotNone(self.backend.get_task("pend"))

    def test_delete_expired_pending_task_never_expires(self) -> None:
        """A pending task (completed_at=None) must never be deleted."""
        task = _make_task("pend2")
        task["created_at"] = time.monotonic() - 9999
        self.backend.create_task("pend2", task)
        deleted = self.backend.delete_expired(ttl_seconds=1)
        self.assertEqual(deleted, 0)


class TestConcurrency(unittest.TestCase):
    """Thread-safety: concurrent create and update must not lose data."""

    def test_concurrent_create_and_update(self) -> None:
        backend = InMemoryTaskBackend()
        n = 50
        errors: list[Exception] = []

        def create_and_update(i: int) -> None:
            tid = f"c_{i}"
            try:
                backend.create_task(tid, _make_task(tid))
                backend.update_state(tid, "running")
                backend.update_state(
                    tid, "done",
                    result={"i": i},
                    completed_at=time.monotonic(),
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=create_and_update, args=(i,))
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Errors in threads: {errors}")
        done_tasks = backend.list_tasks(filter_state="done")
        self.assertEqual(len(done_tasks), n)


class TestRedisBackendStub(unittest.TestCase):
    """RedisTaskBackend must be importable and raise NotImplementedError."""

    def setUp(self) -> None:
        self.backend = RedisTaskBackend("redis://localhost:6379/0")

    def _assert_not_implemented(self, fn):
        with self.assertRaises(NotImplementedError):
            fn()

    def test_create_task_raises(self) -> None:
        self._assert_not_implemented(
            lambda: self.backend.create_task("x", {})
        )

    def test_get_task_raises(self) -> None:
        self._assert_not_implemented(lambda: self.backend.get_task("x"))

    def test_list_tasks_raises(self) -> None:
        self._assert_not_implemented(lambda: self.backend.list_tasks())

    def test_update_state_raises(self) -> None:
        self._assert_not_implemented(
            lambda: self.backend.update_state("x", "done")
        )

    def test_delete_expired_raises(self) -> None:
        self._assert_not_implemented(
            lambda: self.backend.delete_expired(300)
        )

    def test_healthcheck_raises(self) -> None:
        self._assert_not_implemented(lambda: self.backend.healthcheck())

    def test_is_task_backend_subclass(self) -> None:
        self.assertIsInstance(self.backend, TaskBackend)


class TestImportContract(unittest.TestCase):
    """Public import surface must be stable."""

    def test_inmemory_is_taskbackend(self) -> None:
        backend = InMemoryTaskBackend()
        self.assertIsInstance(backend, TaskBackend)


if __name__ == "__main__":
    unittest.main()
