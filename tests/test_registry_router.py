"""
Unit tests for RegistryRouter (Wave 2B).

Tests IDB affinity extraction, routing decisions, NoWorkerAvailableError,
cache behaviour, and various request_params structures.

All tests use fakeredis — no real Redis required.
"""

from __future__ import annotations

import time
import unittest

import fakeredis

from ida_pro_mcp.distributed.protocol import WorkerInfo
from ida_pro_mcp.distributed.registry import Registry
from ida_pro_mcp.distributed.router import (
    NoWorkerAvailableError,
    RegistryRouter,
    WorkerEndpoint,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_registry(namespace: str = "test") -> Registry:
    """Return a Registry backed by an in-process fakeredis server."""
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
    loaded_idb: str | None = None,
    score: float = 0.5,
) -> WorkerInfo:
    now = time.time()
    return WorkerInfo(
        worker_id=worker_id,
        host=host,
        port=port,
        pid=1234,
        capabilities=("idalib",),
        loaded_idb=loaded_idb,
        score=score,
        started_at=now,
        last_heartbeat=now,
    )


# ---------------------------------------------------------------------------
# Tests: _extract_idb static method
# ---------------------------------------------------------------------------


class TestExtractIdb(unittest.TestCase):
    """Test IDB path extraction from request_params."""

    def _extract(self, params):
        return RegistryRouter._extract_idb(params)

    # -- Happy paths ---------------------------------------------------------

    def test_database_key(self):
        """'database' key is the highest priority IDB param."""
        params = {"arguments": {"database": "/path/to/file.idb"}}
        self.assertEqual(self._extract(params), "/path/to/file.idb")

    def test_idb_path_key(self):
        """'idb_path' is returned when 'database' is absent."""
        params = {"arguments": {"idb_path": "/path/to/file.idb"}}
        self.assertEqual(self._extract(params), "/path/to/file.idb")

    def test_input_path_key(self):
        """'input_path' is returned when higher-priority keys are absent."""
        params = {"arguments": {"input_path": "/path/to/file.idb"}}
        self.assertEqual(self._extract(params), "/path/to/file.idb")

    def test_database_wins_over_idb_path(self):
        """'database' beats 'idb_path' when both are present."""
        params = {
            "arguments": {
                "database": "/priority.idb",
                "idb_path": "/secondary.idb",
            }
        }
        self.assertEqual(self._extract(params), "/priority.idb")

    def test_database_wins_over_input_path(self):
        """'database' beats 'input_path' when both are present."""
        params = {
            "arguments": {
                "database": "/priority.idb",
                "input_path": "/secondary.idb",
            }
        }
        self.assertEqual(self._extract(params), "/priority.idb")

    # -- Edge cases ----------------------------------------------------------

    def test_no_params(self):
        """None params → None."""
        self.assertIsNone(self._extract(None))

    def test_empty_dict(self):
        """Empty params dict → None."""
        self.assertIsNone(self._extract({}))

    def test_no_arguments_key(self):
        """Params without 'arguments' key → None."""
        self.assertIsNone(self._extract({"name": "decompile_function"}))

    def test_arguments_not_a_dict(self):
        """Non-dict 'arguments' → None (don't crash)."""
        self.assertIsNone(self._extract({"arguments": "not_a_dict"}))
        self.assertIsNone(self._extract({"arguments": ["list", "not", "dict"]}))

    def test_empty_string_value_skipped(self):
        """Empty string values should be skipped (treat as absent)."""
        params = {"arguments": {"database": "", "idb_path": "/valid.idb"}}
        self.assertEqual(self._extract(params), "/valid.idb")

    def test_all_empty_returns_none(self):
        """All IDB param keys are empty strings → None."""
        params = {
            "arguments": {
                "database": "",
                "idb_path": "",
                "input_path": "",
            }
        }
        self.assertIsNone(self._extract(params))

    def test_non_string_value_skipped(self):
        """Non-string values in arguments are skipped."""
        params = {"arguments": {"database": 12345, "idb_path": "/valid.idb"}}
        self.assertEqual(self._extract(params), "/valid.idb")

    def test_other_argument_fields_ignored(self):
        """Unknown argument fields don't interfere with extraction."""
        params = {
            "arguments": {
                "address": "0x401000",
                "count": 100,
                "database": "/target.idb",
            }
        }
        self.assertEqual(self._extract(params), "/target.idb")


# ---------------------------------------------------------------------------
# Tests: RegistryRouter.select_worker
# ---------------------------------------------------------------------------


class TestRegistryRouterSelectWorker(unittest.TestCase):
    """Core routing logic tests."""

    def setUp(self):
        self.registry = _fake_registry()
        self.router = RegistryRouter(self.registry)

    def test_no_workers_raises(self):
        """Empty registry → NoWorkerAvailableError."""
        with self.assertRaises(NoWorkerAvailableError):
            self.router.select_worker("tools/call", {})

    def test_single_worker_selected(self):
        """Single registered worker is always selected."""
        w = _make_worker(worker_id="solo", host="10.0.0.1", port=13337)
        self.registry.register(w)

        ep = self.router.select_worker("tools/call", {})
        self.assertEqual(ep.worker_id, "solo")
        self.assertIsInstance(ep, WorkerEndpoint)

    def test_idb_affinity_hit(self):
        """Worker with matching loaded_idb is preferred over lower-load worker."""
        idb = "/projects/target.idb"
        w_affinity = _make_worker(
            worker_id="affinity", port=13337, score=0.9, loaded_idb=idb
        )
        w_cheap = _make_worker(worker_id="cheap", port=13338, score=0.1)
        self.registry.register(w_affinity)
        self.registry.register(w_cheap)

        params = {"arguments": {"database": idb}}
        ep = self.router.select_worker("tools/call", params)
        self.assertEqual(ep.worker_id, "affinity")

    def test_idb_affinity_miss_fallback_to_lowest_load(self):
        """No worker has the IDB → fallback to lowest-score worker."""
        w1 = _make_worker(worker_id="w1", port=13337, score=0.8)
        w2 = _make_worker(worker_id="w2", port=13338, score=0.2)
        self.registry.register(w1)
        self.registry.register(w2)

        params = {"arguments": {"database": "/nonexistent.idb"}}
        ep = self.router.select_worker("tools/call", params)
        self.assertEqual(ep.worker_id, "w2")

    def test_no_idb_param_selects_lowest_load(self):
        """Requests without IDB params → lowest-score worker selected."""
        w1 = _make_worker(worker_id="w1", port=13337, score=0.9)
        w2 = _make_worker(worker_id="w2", port=13338, score=0.1)
        self.registry.register(w1)
        self.registry.register(w2)

        ep = self.router.select_worker("tools/list", None)
        self.assertEqual(ep.worker_id, "w2")

    def test_idb_via_idb_path_key(self):
        """IDB extracted from 'idb_path' key when 'database' is absent."""
        idb = "/projects/firmware.idb"
        w = _make_worker(worker_id="fw-worker", port=13337, loaded_idb=idb)
        self.registry.register(w)

        params = {"arguments": {"idb_path": idb}}
        ep = self.router.select_worker("tools/call", params)
        self.assertEqual(ep.worker_id, "fw-worker")

    def test_idb_via_input_path_key(self):
        """IDB extracted from 'input_path' key (third priority)."""
        idb = "/projects/binary.idb"
        w = _make_worker(worker_id="bin-worker", port=13337, loaded_idb=idb)
        self.registry.register(w)

        params = {"arguments": {"input_path": idb}}
        ep = self.router.select_worker("tools/call", params)
        self.assertEqual(ep.worker_id, "bin-worker")

    def test_returned_endpoint_has_correct_fields(self):
        """Returned WorkerEndpoint has correct host/port/worker_id."""
        w = _make_worker(worker_id="wkr-42", host="192.168.1.5", port=14000)
        self.registry.register(w)

        ep = self.router.select_worker("ping", {})
        self.assertEqual(ep.host, "192.168.1.5")
        self.assertEqual(ep.port, 14000)
        self.assertEqual(ep.worker_id, "wkr-42")

    def test_multiple_affinity_workers_selects_lowest_score(self):
        """When multiple workers have IDB affinity, pick the lowest score."""
        idb = "/shared.idb"
        w_heavy = _make_worker(
            worker_id="heavy", port=13337, score=0.8, loaded_idb=idb
        )
        w_light = _make_worker(
            worker_id="light", port=13338, score=0.2, loaded_idb=idb
        )
        self.registry.register(w_heavy)
        self.registry.register(w_light)

        params = {"arguments": {"database": idb}}
        ep = self.router.select_worker("tools/call", params)
        self.assertEqual(ep.worker_id, "light")

    def test_params_without_arguments_key(self):
        """Params dict lacking 'arguments' → no IDB → lowest load selected."""
        w1 = _make_worker(worker_id="w1", port=13337, score=0.5)
        w2 = _make_worker(worker_id="w2", port=13338, score=0.3)
        self.registry.register(w1)
        self.registry.register(w2)

        # Params has a 'name' but no 'arguments'
        ep = self.router.select_worker("tools/call", {"name": "decompile_function"})
        self.assertEqual(ep.worker_id, "w2")


# ---------------------------------------------------------------------------
# Tests: RegistryRouter.list_workers
# ---------------------------------------------------------------------------


class TestRegistryRouterListWorkers(unittest.TestCase):
    """list_workers with 1-second caching."""

    def setUp(self):
        self.registry = _fake_registry()
        self.router = RegistryRouter(self.registry)

    def test_list_empty_registry(self):
        self.assertEqual(self.router.list_workers(), [])

    def test_list_returns_endpoints(self):
        w1 = _make_worker(worker_id="a", host="10.0.0.1", port=13337)
        w2 = _make_worker(worker_id="b", host="10.0.0.2", port=13337)
        self.registry.register(w1)
        self.registry.register(w2)

        endpoints = self.router.list_workers()
        ids = {ep.worker_id for ep in endpoints}
        self.assertEqual(ids, {"a", "b"})
        for ep in endpoints:
            self.assertIsInstance(ep, WorkerEndpoint)

    def test_list_workers_cached(self):
        """list_workers() result is cached for ~1 second."""
        w = _make_worker(worker_id="cached-worker", port=13337)
        self.registry.register(w)

        # First call populates cache
        eps1 = self.router.list_workers()
        self.assertEqual(len(eps1), 1)

        # Deregister via registry directly; cache should still have old result
        self.registry.deregister("cached-worker")
        eps2 = self.router.list_workers()
        # Cache is still valid — should still return 1 worker
        self.assertEqual(len(eps2), 1)

    def test_list_workers_cache_expires(self):
        """After cache TTL expires, a fresh fetch is performed."""
        import ida_pro_mcp.distributed.router as router_module

        original_ttl = router_module._LIST_WORKERS_CACHE_TTL
        try:
            # Set a very short TTL
            router_module._LIST_WORKERS_CACHE_TTL = 0.05
            router = RegistryRouter(self.registry)

            w = _make_worker(worker_id="short-ttl", port=13337)
            self.registry.register(w)

            eps1 = router.list_workers()
            self.assertEqual(len(eps1), 1)

            # Deregister and wait for cache to expire
            self.registry.deregister("short-ttl")
            time.sleep(0.1)

            eps2 = router.list_workers()
            self.assertEqual(len(eps2), 0)
        finally:
            router_module._LIST_WORKERS_CACHE_TTL = original_ttl


# ---------------------------------------------------------------------------
# Tests: NoWorkerAvailableError raised by RegistryRouter
# ---------------------------------------------------------------------------


class TestNoWorkerAvailableError(unittest.TestCase):
    def test_is_exception_subclass(self):
        err = NoWorkerAvailableError("test")
        self.assertIsInstance(err, Exception)

    def test_message_preserved(self):
        err = NoWorkerAvailableError("no workers here")
        self.assertIn("no workers here", str(err))

    def test_raised_on_empty_registry(self):
        registry = _fake_registry()
        router = RegistryRouter(registry)
        with self.assertRaises(NoWorkerAvailableError) as ctx:
            router.select_worker("tools/call", {})
        self.assertIn("No workers", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
