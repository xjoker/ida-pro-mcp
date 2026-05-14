"""Abstract storage backend for the async task queue.

Concrete implementations:
- InMemoryTaskBackend  (default, single-process)
- RedisTaskBackend     (multi-host; requires redis-py + Redis server)
"""
from __future__ import annotations

import json
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


# ── Redis implementation ──────────────────────────────────────────────────────

# Serialisable field names whose values are stored as JSON strings in the hash.
_JSON_FIELDS = frozenset({"result", "error", "params"})

# Fallback TTL applied directly to each task hash key (30 min) as a safety net
# in case delete_expired is never called (e.g. process crash).
_HASH_TTL_SEC = 1800


def _encode_task(params: dict) -> dict[str, str]:
    """Convert a task dict into a flat mapping of str -> str for HSET."""
    encoded: dict[str, str] = {}
    for key, value in params.items():
        if key in _JSON_FIELDS or not isinstance(value, str | int | float | bool | type(None)):
            encoded[key] = json.dumps(value)
        else:
            encoded[key] = "" if value is None else str(value)
    return encoded


def _decode_task(raw: dict[bytes, bytes]) -> dict:
    """Convert a raw HGETALL result (bytes -> bytes) back to a Python dict."""
    task: dict = {}
    for key_bytes, val_bytes in raw.items():
        key = key_bytes.decode()
        val_str = val_bytes.decode()
        if key in _JSON_FIELDS:
            try:
                task[key] = json.loads(val_str) if val_str else None
            except json.JSONDecodeError:
                task[key] = val_str
        elif val_str == "":
            task[key] = None
        elif val_str == "True":
            task[key] = True
        elif val_str == "False":
            task[key] = False
        else:
            # Try numeric decode; fall back to string.
            for cast in (int, float):
                try:
                    task[key] = cast(val_str)
                    break
                except ValueError:
                    continue
            else:
                task[key] = val_str
    return task


class RedisTaskBackend(TaskBackend):
    """Redis-backed task storage for multi-host deployments.

    Redis Schema
    ------------
    ``{ns}:task:{task_id}``        HASH    all task fields
    ``{ns}:tasks:by_state:{state}`` SET    task_id members per state
    ``{ns}:tasks:all``             ZSET   score = created_at unix timestamp

    Parameters
    ----------
    redis_url:
        Full Redis URL, e.g. ``redis://localhost:6379/0``.
    namespace:
        Key prefix to namespace all task keys (default ``idamcp:tasks``).
    max_connections:
        Size of the connection pool (default 20).
    """

    def __init__(
        self,
        redis_url: str,
        namespace: str = "idamcp:tasks",
        *,
        max_connections: int = 20,
    ) -> None:
        import redis

        self._redis_url = redis_url
        self._ns = namespace
        pool = redis.ConnectionPool.from_url(
            redis_url, max_connections=max_connections
        )
        self._r: redis.Redis = redis.Redis(connection_pool=pool)

    # ── Key helpers ───────────────────────────────────────────────────────────

    def _task_key(self, task_id: str) -> str:
        return f"{self._ns}:task:{task_id}"

    def _state_key(self, state: str) -> str:
        return f"{self._ns}:tasks:by_state:{state}"

    def _all_key(self) -> str:
        return f"{self._ns}:tasks:all"

    # ── Public interface ──────────────────────────────────────────────────────

    def create_task(self, task_id: str, params: dict) -> None:
        """Persist a new task.  Uses a pipeline for atomicity."""
        try:
            created_at: float = params.get("created_at") or time.time()
            state: str = params.get("status", "pending")
            encoded = _encode_task(params)

            pipe = self._r.pipeline(transaction=True)
            pipe.hset(self._task_key(task_id), mapping=encoded)
            pipe.expire(self._task_key(task_id), _HASH_TTL_SEC)
            pipe.sadd(self._state_key(state), task_id)
            pipe.zadd(self._all_key(), {task_id: created_at})
            pipe.execute()
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc

    def update_state(self, task_id: str, state: str, **fields) -> None:
        """Atomically update status + move task between state sets.

        Also merges any extra ``fields`` into the task hash.
        """
        try:
            # Retrieve old state so we can remove from the correct set.
            old_state_bytes: bytes | None = self._r.hget(
                self._task_key(task_id), "status"
            )
            old_state: str | None = (
                old_state_bytes.decode() if old_state_bytes else None
            )

            update_map = _encode_task({**fields, "status": state})

            pipe = self._r.pipeline(transaction=True)
            pipe.hset(self._task_key(task_id), mapping=update_map)
            # Remove from old state set (safe even if same state – idempotent).
            if old_state is not None:
                pipe.srem(self._state_key(old_state), task_id)
            # Add to new state set.
            pipe.sadd(self._state_key(state), task_id)
            # Refresh the hash TTL so recently completed tasks survive longer.
            pipe.expire(self._task_key(task_id), _HASH_TTL_SEC)
            pipe.execute()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc

    def get_task(self, task_id: str) -> dict | None:
        """Return a copy of the task record, or ``None`` if not found."""
        try:
            raw = self._r.hgetall(self._task_key(task_id))
            if not raw:
                return None
            return _decode_task(raw)
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc

    def list_tasks(self, filter_state: str | None = None) -> list[dict]:
        """Return all task records, optionally filtered by state.

        Uses the ZSET (``tasks:all``) to enumerate all known task IDs, then
        fetches each hash.  The ZSET is the ground-truth membership list;
        the per-state SETs are only used for fast state-filtered lookups.
        """
        try:
            if filter_state is not None:
                # Fast path: use the state SET directly.
                task_ids = [
                    tid.decode() for tid in self._r.smembers(self._state_key(filter_state))
                ]
            else:
                # Enumerate all task IDs ordered by creation time.
                task_ids = [
                    tid.decode()
                    for tid in self._r.zrange(self._all_key(), 0, -1)
                ]

            results: list[dict] = []
            for task_id in task_ids:
                raw = self._r.hgetall(self._task_key(task_id))
                if raw:
                    results.append(_decode_task(raw))
            return results
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc

    def delete_expired(self, ttl_seconds: int) -> int:
        """Delete done/error tasks older than ``ttl_seconds``.

        Uses the ZSET score (creation unix timestamp) as a fast range filter,
        then checks ``completed_at`` to honour the real expiry threshold.

        Returns the number of tasks actually deleted.
        """
        try:
            cutoff = time.time() - ttl_seconds
            # Candidates: tasks created before the cutoff window.
            candidates = self._r.zrangebyscore(self._all_key(), "-inf", cutoff)

            deleted = 0
            for tid_bytes in candidates:
                task_id = tid_bytes.decode()
                task_key = self._task_key(task_id)
                raw = self._r.hgetall(task_key)
                if not raw:
                    # Hash already gone (hash TTL expired); clean up ZSET entry.
                    self._r.zrem(self._all_key(), task_id)
                    deleted += 1
                    continue

                task = _decode_task(raw)
                status = task.get("status", "")
                completed_at = task.get("completed_at")

                # Only expire terminal-state tasks with a recorded completed_at.
                if status in ("done", "error") and completed_at is not None:
                    pipe = self._r.pipeline(transaction=True)
                    pipe.delete(task_key)
                    pipe.zrem(self._all_key(), task_id)
                    pipe.srem(self._state_key(status), task_id)
                    pipe.execute()
                    deleted += 1

            return deleted
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc

    def healthcheck(self) -> bool:
        """Ping Redis; return True if responsive."""
        try:
            return self._r.ping()
        except Exception as exc:
            raise RuntimeError(f"Redis task backend error: {exc}") from exc
