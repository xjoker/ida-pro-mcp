"""
Worker routing abstractions for the IDA Pro MCP Coordinator.

Defines WorkerEndpoint (dataclass), Router (ABC), MockRouter (round-robin
implementation backed by a static list of endpoints), and RegistryRouter
(dynamic routing backed by Redis Registry with IDB affinity).
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class NoWorkerAvailableError(Exception):
    """Raised when no worker is registered or all are unhealthy.

    Used by RegistryRouter when Registry.select_best() returns None or raises.
    Maps to JSON-RPC error code -32001 in the Coordinator.
    """


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
            NoWorkerAvailableError: If no workers are available.
            RuntimeError: Legacy — MockRouter raises this for compatibility.
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


# ---------------------------------------------------------------------------
# Registry-backed router (Wave 2B)
# ---------------------------------------------------------------------------

# IDB path parameter names to probe, in priority order.
_IDB_PARAM_KEYS: tuple[str, ...] = ("database", "idb_path", "input_path")

# list_workers() result cache TTL in seconds.
_LIST_WORKERS_CACHE_TTL: float = 1.0


class RegistryRouter(Router):
    """Dynamic router backed by a Redis Registry with IDB affinity routing.

    On each call to select_worker():
    1. Extract prefer_idb from request_params["arguments"] (highest priority key wins).
    2. Call registry.select_best(prefer_idb=...) to obtain a RoutingDecision.
    3. Convert WorkerInfo → WorkerEndpoint and return it.

    list_workers() caches Registry.list_workers() for 1 second to avoid
    hammering Redis on repeated health-check calls.
    """

    def __init__(self, registry: "Registry") -> None:  # type: ignore[name-defined]  # noqa: F821
        self._registry = registry
        self._cache_lock = threading.Lock()
        self._cached_workers: list[WorkerEndpoint] = []
        self._cache_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # IDB extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_idb(request_params: dict | None) -> str | None:
        """Extract preferred IDB path from MCP request params.

        Checks request_params["arguments"] for the following keys in order:
        "database", "idb_path", "input_path".  Returns the first non-empty
        string found, or None if nothing matches.
        """
        if not isinstance(request_params, dict):
            return None

        arguments = request_params.get("arguments")
        if not isinstance(arguments, dict):
            return None

        for key in _IDB_PARAM_KEYS:
            value = arguments.get(key)
            if isinstance(value, str) and value:
                return value

        return None

    # ------------------------------------------------------------------
    # Router interface
    # ------------------------------------------------------------------

    def select_worker(
        self,
        request_method: str,
        request_params: dict | None,
    ) -> WorkerEndpoint:
        """Select the best worker for the request using Registry.select_best().

        Raises:
            NoWorkerAvailableError: If no workers are registered or all are
                unhealthy, or if the Registry call fails (Redis error).
        """
        prefer_idb = self._extract_idb(request_params)

        try:
            decision = self._registry.select_best(prefer_idb=prefer_idb)
        except Exception as exc:
            logger.error("Registry.select_best() failed: %s", exc)
            raise NoWorkerAvailableError(
                f"Registry unavailable: {exc}"
            ) from exc

        if decision is None:
            raise NoWorkerAvailableError(
                "No workers registered in Registry (or all are unhealthy)"
            )

        worker = decision.worker
        logger.debug(
            "Routed %s → worker=%s reason=%s idb=%s",
            request_method,
            worker.worker_id,
            decision.reason,
            prefer_idb,
        )
        return WorkerEndpoint(
            host=worker.host,
            port=worker.port,
            worker_id=worker.worker_id,
        )

    def list_workers(self) -> list[WorkerEndpoint]:
        """Return all active workers, cached for up to 1 second."""
        with self._cache_lock:
            now = time.monotonic()
            if now < self._cache_expires_at:
                return list(self._cached_workers)

        # Fetch outside the lock to avoid holding it during network I/O.
        try:
            infos = self._registry.list_workers()
            endpoints = [
                WorkerEndpoint(host=w.host, port=w.port, worker_id=w.worker_id)
                for w in infos
            ]
        except Exception as exc:
            logger.error("Registry.list_workers() failed: %s", exc)
            # Return stale cache rather than raising.
            with self._cache_lock:
                return list(self._cached_workers)

        with self._cache_lock:
            self._cached_workers = endpoints
            self._cache_expires_at = time.monotonic() + _LIST_WORKERS_CACHE_TTL
            return list(endpoints)
