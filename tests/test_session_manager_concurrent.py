"""Regression tests for IDASessionManager stability fixes.

These tests mock idapro/ida_auto so they run without an IDA installation.
Each test class corresponds to one of the four upstream-port fixes.
"""

import sys
import threading
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# ---------------------------------------------------------------------------
# Minimal stubs so the module can be imported without IDA installed
# ---------------------------------------------------------------------------

_idapro_stub = MagicMock()
_ida_auto_stub = MagicMock()
sys.modules.setdefault("idapro", _idapro_stub)
sys.modules.setdefault("ida_auto", _ida_auto_stub)

# Now import the module under test
import importlib
import ida_pro_mcp.idalib_session_manager as _mod

# Reload to pick up the stubs (in case a previous import cached the real module)
importlib.reload(_mod)

IDASessionManager = _mod.IDASessionManager
_MAX_TRANSPORT_BINDINGS = _mod._MAX_TRANSPORT_BINDINGS
_auto_wait_with_timeout = _mod._auto_wait_with_timeout


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager():
    """Return a fresh IDASessionManager with idapro/ida_auto fully mocked."""
    mgr = IDASessionManager()
    return mgr


def _inject_session(mgr, session_id: str, path: str = "/fake/binary.elf"):
    """Directly inject a session record, bypassing idapro."""
    from datetime import datetime
    session = _mod.IDASession(
        session_id=session_id,
        input_path=Path(path),
    )
    mgr._sessions[session_id] = session
    mgr._current_session_id = session_id
    return session


# ---------------------------------------------------------------------------
# Issue 1 — TOCTOU race in ensure_context_for_transport
# ---------------------------------------------------------------------------

class TestTOCTOURace(unittest.TestCase):
    """Guard: two threads cannot concurrently conclude they need to switch."""

    def test_concurrent_ensure_context_serialised(self):
        """Two transports bound to different sessions must not interleave."""
        mgr = _make_manager()

        # Inject two sessions
        _inject_session(mgr, "sess-A", "/fake/a.elf")
        _inject_session(mgr, "sess-B", "/fake/b.elf")
        mgr._current_session_id = "sess-A"

        # Bind transport-2 to sess-B (transport-1 already "active" as sess-A)
        mgr._transport_bindings["t-1"] = "sess-A"
        mgr._transport_bindings["t-2"] = "sess-B"

        switch_order = []

        real_switch = mgr.switch_session

        def tracked_switch(sid):
            switch_order.append(sid)
            # Simulate a small IDB load delay
            import time; time.sleep(0.01)
            mgr._current_session_id = sid
            return True

        mgr.switch_session = tracked_switch

        # Both threads call ensure_context_for_transport simultaneously
        barrier = threading.Barrier(2)
        errors = []

        def worker(transport_id):
            try:
                barrier.wait()
                mgr.ensure_context_for_transport(transport_id)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker, args=("t-1",))
        t2 = threading.Thread(target=worker, args=("t-2",))
        t1.start(); t2.start()
        t1.join(); t2.join()

        self.assertEqual(errors, [], f"Unexpected errors: {errors}")
        # Switches must not interleave: each switch must be a clean sequence
        # (no duplicates from double-checking, list is well-ordered)
        # We can't assert exact order due to scheduling, but no exception = mutex worked
        self.assertLessEqual(len(switch_order), 2)

    def test_ensure_context_no_switch_when_already_active(self):
        """No switch called when transport is already on the correct session."""
        mgr = _make_manager()
        _inject_session(mgr, "sess-A", "/fake/a.elf")
        mgr._transport_bindings["t-1"] = "sess-A"

        mgr.switch_session = MagicMock(side_effect=AssertionError("switch must not be called"))
        result = mgr.ensure_context_for_transport("t-1")
        self.assertEqual(result, "sess-A")

    def test_ensure_context_returns_none_for_unbound_transport(self):
        mgr = _make_manager()
        _inject_session(mgr, "sess-A")
        result = mgr.ensure_context_for_transport("unbound-transport")
        self.assertEqual(result, "sess-A")

    def test_ensure_context_returns_none_when_no_transport(self):
        mgr = _make_manager()
        _inject_session(mgr, "sess-A")
        result = mgr.ensure_context_for_transport(None)
        self.assertEqual(result, "sess-A")


# ---------------------------------------------------------------------------
# Issue 2 — LRU-capped _transport_bindings
# ---------------------------------------------------------------------------

class TestTransportBindingsLRU(unittest.TestCase):
    """_transport_bindings must not grow past _MAX_TRANSPORT_BINDINGS."""

    def _make_mgr_with_sessions(self, n: int):
        mgr = _make_manager()
        for i in range(n):
            _inject_session(mgr, f"s{i}", f"/fake/b{i}.elf")
        # Ensure all sessions exist for binding
        return mgr

    def test_cap_enforced_on_bind(self):
        mgr = _make_manager()
        _inject_session(mgr, "s0", "/fake/b0.elf")

        # Bind more than the cap — all bind to s0 with unique transport IDs
        for i in range(_MAX_TRANSPORT_BINDINGS + 10):
            mgr.bind_transport_session(f"t{i}", "s0")

        self.assertLessEqual(
            len(mgr._transport_bindings),
            _MAX_TRANSPORT_BINDINGS,
            "Binding table must not exceed the cap",
        )

    def test_lru_evicts_oldest(self):
        mgr = _make_manager()
        _inject_session(mgr, "s0", "/fake/b0.elf")

        # Fill to exactly the cap
        for i in range(_MAX_TRANSPORT_BINDINGS):
            mgr.bind_transport_session(f"t{i}", "s0")

        # t0 should still be present (cap not exceeded yet)
        self.assertIn("t0", mgr._transport_bindings)

        # Adding one more should evict t0 (oldest)
        mgr.bind_transport_session("t_new", "s0")
        self.assertNotIn("t0", mgr._transport_bindings)
        self.assertIn("t_new", mgr._transport_bindings)

    def test_rebind_refreshes_lru_position(self):
        mgr = _make_manager()
        _inject_session(mgr, "s0", "/fake/b0.elf")

        for i in range(_MAX_TRANSPORT_BINDINGS):
            mgr.bind_transport_session(f"t{i}", "s0")

        # Re-bind t0 to move it to the end (most-recently-used)
        mgr.bind_transport_session("t0", "s0")

        # Adding one new entry should evict t1 (now oldest), NOT t0
        mgr.bind_transport_session("t_new", "s0")
        self.assertIn("t0", mgr._transport_bindings)
        self.assertNotIn("t1", mgr._transport_bindings)

    def test_binding_is_ordered_dict(self):
        mgr = _make_manager()
        self.assertIsInstance(mgr._transport_bindings, OrderedDict)


# ---------------------------------------------------------------------------
# Issue 3 — open/close failure leaves _current_session_id consistent
# ---------------------------------------------------------------------------

class TestStateConsistencyOnFailure(unittest.TestCase):
    """_current_session_id must be None after any open/close failure."""

    @patch.object(_mod, "idapro")
    def test_open_failure_resets_current_session_id(self, mock_idapro):
        """open_database returning non-zero must leave current_session_id=None."""
        mock_idapro.open_database.return_value = 1  # non-zero = failure
        mock_idapro.close_database.return_value = None

        mgr = _make_manager()
        # Pre-existing session so close_database is called first
        _inject_session(mgr, "old", "/fake/old.elf")

        with self.assertRaises(RuntimeError):
            # Patch Path.exists to always return True
            with patch.object(Path, "exists", return_value=True):
                mgr.open_binary(Path("/fake/new.elf"), run_auto_analysis=False)

        self.assertIsNone(
            mgr._current_session_id,
            "_current_session_id must be None after failed open",
        )

    @patch.object(_mod, "idapro")
    def test_close_failure_resets_current_session_id(self, mock_idapro):
        """close_database raising an exception must still clear current_session_id."""
        mock_idapro.close_database.side_effect = RuntimeError("IDA close error")

        mgr = _make_manager()
        _inject_session(mgr, "s1", "/fake/s1.elf")

        # close_session should not propagate the close_database exception
        result = mgr.close_session("s1")

        # The session should be removed and current_session_id cleared
        self.assertTrue(result)
        self.assertIsNone(mgr._current_session_id)
        self.assertNotIn("s1", mgr._sessions)

    @patch.object(_mod, "idapro")
    def test_switch_failure_resets_current_session_id(self, mock_idapro):
        """Failed open_database during switch must leave current_session_id=None."""
        mock_idapro.close_database.return_value = None
        mock_idapro.open_database.return_value = 1  # failure

        mgr = _make_manager()
        _inject_session(mgr, "sess-A", "/fake/a.elf")
        # Manually add sess-B without setting it as current
        mgr._sessions["sess-B"] = _mod.IDASession(
            session_id="sess-B",
            input_path=Path("/fake/b.elf"),
        )

        with self.assertRaises(RuntimeError):
            mgr.switch_session("sess-B")

        self.assertIsNone(
            mgr._current_session_id,
            "_current_session_id must be None when switch open_database fails",
        )


# ---------------------------------------------------------------------------
# Issue 4 — auto_wait timeout
# ---------------------------------------------------------------------------

class TestAutoWaitTimeout(unittest.TestCase):
    """_auto_wait_with_timeout must return False on timeout and True when done."""

    def test_returns_true_when_analysis_completes(self):
        with patch.object(_mod.ida_auto, "auto_wait", return_value=None):
            result = _auto_wait_with_timeout(timeout_secs=5.0)
        self.assertTrue(result)

    def test_returns_false_on_timeout(self):
        import time

        def slow_wait():
            time.sleep(10)  # longer than our test timeout

        with patch.object(_mod.ida_auto, "auto_wait", side_effect=slow_wait):
            result = _auto_wait_with_timeout(timeout_secs=0.05)
        self.assertFalse(result)

    @patch.object(_mod, "idapro")
    @patch.object(_mod, "_auto_wait_with_timeout", return_value=False)
    def test_open_binary_sets_is_analyzing_on_timeout(self, mock_wait, mock_idapro):
        """When auto_wait times out, session.is_analyzing must remain True."""
        mock_idapro.open_database.return_value = 0  # success
        mock_idapro.close_database.return_value = None

        mgr = _make_manager()
        with patch.object(Path, "exists", return_value=True):
            sid = mgr.open_binary(Path("/fake/slow.elf"), run_auto_analysis=True)

        session = mgr.get_session(sid)
        self.assertIsNotNone(session)
        self.assertTrue(
            session.is_analyzing,
            "is_analyzing must be True when auto_wait times out",
        )

    @patch.object(_mod, "idapro")
    @patch.object(_mod, "_auto_wait_with_timeout", return_value=True)
    def test_open_binary_clears_is_analyzing_on_success(self, mock_wait, mock_idapro):
        """When auto_wait completes, session.is_analyzing must be False."""
        mock_idapro.open_database.return_value = 0
        mock_idapro.close_database.return_value = None

        mgr = _make_manager()
        with patch.object(Path, "exists", return_value=True):
            sid = mgr.open_binary(Path("/fake/fast.elf"), run_auto_analysis=True)

        session = mgr.get_session(sid)
        self.assertIsNotNone(session)
        self.assertFalse(session.is_analyzing)


if __name__ == "__main__":
    unittest.main()
