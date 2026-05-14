"""
Worker routing abstractions for the IDA Pro MCP Coordinator.

Defines WorkerEndpoint (dataclass), Router (ABC), and MockRouter (round-robin
implementation backed by a static list of endpoints).  Wave 2B will provide a
RedisRouter that replaces MockRouter without touching any other file.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class WorkerEndpoint:
    """Represents a single IDA/idalib worker process reachable over HTTP."""

    host: str
    port: int
    worker_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.worker_id:
            self.worker_id = f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.worker_id

    @classmethod
    def from_string(cls, spec: str) -> "WorkerEndpoint":
        """Parse 'host:port' or 'host:port:worker_id' into a WorkerEndpoint."""
        parts = spec.split(":", 2)
        if len(parts) < 2:
            raise ValueError(f"Invalid worker spec '{spec}': expected host:port")
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError(f"Invalid port in worker spec '{spec}'")
        worker_id = parts[2] if len(parts) == 3 else f"{host}:{port}"
        return cls(host=host, port=port, worker_id=worker_id)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class Router(ABC):
    """Abstract router: maps an incoming MCP request to a WorkerEndpoint."""

    @abstractmethod
    def select_worker(
        self,
        request_method: str,
        request_params: dict | None,
    ) -> WorkerEndpoint:
        """Return the worker that should handle this request.

        Args:
            request_method: JSON-RPC method name, e.g. "tools/call".
            request_params: Parsed params dict, or None for notifications.

        Returns:
            A WorkerEndpoint to forward the request to.

        Raises:
            RuntimeError: If no workers are available.
        """

    @abstractmethod
    def list_workers(self) -> list[WorkerEndpoint]:
        """Return all known worker endpoints (alive or not)."""


# ---------------------------------------------------------------------------
# Mock / static round-robin implementation
# ---------------------------------------------------------------------------


class MockRouter(Router):
    """Simple round-robin router backed by a static list of endpoints.

    Intended for local development and testing.  When no workers are
    registered, select_worker() raises RuntimeError.
    """

    def __init__(self, workers: list[WorkerEndpoint] | None = None) -> None:
        self._workers: list[WorkerEndpoint] = list(workers or [])
        self._index: int = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_worker(self, endpoint: WorkerEndpoint) -> None:
        with self._lock:
            self._workers.append(endpoint)

    def select_worker(
        self,
        request_method: str,
        request_params: dict | None,
    ) -> WorkerEndpoint:
        with self._lock:
            if not self._workers:
                raise RuntimeError("No workers registered in MockRouter")
            endpoint = self._workers[self._index % len(self._workers)]
            self._index = (self._index + 1) % len(self._workers)
            return endpoint

    def list_workers(self) -> list[WorkerEndpoint]:
        with self._lock:
            return list(self._workers)
