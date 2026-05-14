"""Abstract storage backend for the async task queue.

Concrete implementations:
- InMemoryTaskBackend  (default, single-process)
- RedisTaskBackend     (stub; v1.4 Wave 2C will fill the implementation)
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod


class TaskBackend(ABC):
    """Abstract storage backend for async task queue."""

    @abstractmethod
    def create_task(self, task_id: str, params: dict) -> None:
        """Persist a new task in pending state.

        ``params`` should contain at minimum ``tool`` and ``created_at``.
        The backend stores the full initial record.
        """

    @abstractmethod
    def update_state(self, task_id: str, state: str, **fields) -> None:
        """Atomically update the task's status and any extra fields.

        ``fields`` may include ``result``, ``error``, ``completed_at``, etc.
        Implementations MUST be thread-safe.
        """

    @abstractmethod
    def get_task(self, task_id: str) -> dict | None:
        """Return a copy of the task record, or ``None`` if not found."""

    @abstractmethod
    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        """Return all task records, optionally filtered by status string."""

    @abstractmethod
    def delete_expired(self, ttl_seconds: int) -> int:
        """Delete done/error tasks whose ``completed_at`` is older than ttl_seconds.

        Returns the number of tasks deleted.
        """

    @abstractmethod
    def healthcheck(self) -> bool:
        """Return True if the backend is reachable and functioning."""


# ── InMemory implementation ───────────────────────────────────────────────────

class InMemoryTaskBackend(TaskBackend):
    """Default backend; behaviour preserved exactly from the original api_tasks.py."""

    def __init__(self) -> None:
        self._tasks: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create_task(self, task_id: str, params: dict) -> None:
        with self._lock:
            self._tasks[task_id] = dict(params)

    def update_state(self, task_id: str, state: str, **fields) -> None:
        with self._lock:
            if task_id not in self._tasks:
                return
            self._tasks[task_id]["status"] = state
            self._tasks[task_id].update(fields)

    def get_task(self, task_id: str) -> dict | None:
        with self._lock:
            task = self._tasks.get(task_id)
            return dict(task) if task is not None else None

    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        with self._lock:
            tasks = list(self._tasks.values())
        if filter_state is not None:
            tasks = [t for t in tasks if t.get("status") == filter_state]
        return [dict(t) for t in tasks]

    def delete_expired(self, ttl_seconds: int) -> int:
        now = time.monotonic()
        with self._lock:
            expired = [
                tid
                for tid, t in self._tasks.items()
                if t.get("status") in ("done", "error")
                and t.get("completed_at") is not None
                and now - t["completed_at"] > ttl_seconds
            ]
            for tid in expired:
                del self._tasks[tid]
        return len(expired)

    def healthcheck(self) -> bool:
        return True


# ── Redis stub ────────────────────────────────────────────────────────────────

class RedisTaskBackend(TaskBackend):
    """Stub backend for cross-node task visibility.

    All methods raise NotImplementedError until Wave 2C fills the
    implementation.  Instantiation succeeds (no Redis connection is made
    here) so the environment-variable routing in api_tasks.py can import this
    class safely even when redis-py is not installed.
    """

    def __init__(self, redis_url: str) -> None:  # noqa: ARG002
        self._redis_url = redis_url

    def create_task(self, task_id: str, params: dict) -> None:
        raise NotImplementedError("v1.4 Wave 2C 实施")

    def update_state(self, task_id: str, state: str, **fields) -> None:
        raise NotImplementedError("v1.4 Wave 2C 实施")

    def get_task(self, task_id: str) -> dict | None:
        raise NotImplementedError("v1.4 Wave 2C 实施")

    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        raise NotImplementedError("v1.4 Wave 2C 实施")

    def delete_expired(self, ttl_seconds: int) -> int:
        raise NotImplementedError("v1.4 Wave 2C 实施")

    def healthcheck(self) -> bool:
        raise NotImplementedError("v1.4 Wave 2C 实施")
