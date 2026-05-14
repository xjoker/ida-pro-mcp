"""
Unit tests for the IDA Pro MCP Coordinator (Wave 1A).

All tests use stdlib unittest and mock/patch — no IDA dependency.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Import targets
# ---------------------------------------------------------------------------

from ida_pro_mcp.coordinator import CoordinatorServer
from ida_pro_mcp.distributed.forwarder import forward_request
from ida_pro_mcp.distributed.router import MockRouter, Router, WorkerEndpoint


# ---------------------------------------------------------------------------
# Helper: tiny in-process HTTP stub server
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _StubWorkerHandler(BaseHTTPRequestHandler):
    """Stub HTTP server that echoes a canned JSON response."""

    # Populated before instantiation
    response_body: bytes = b'{"jsonrpc":"2.0","result":{},"id":1}'
    response_status: int = 200

    def log_message(self, fmt: str, *args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        body = self.__class__.response_body
        self.send_response(self.__class__.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_stub_server(response_body: bytes, status: int = 200) -> tuple[HTTPServer, int]:
    """Start a stub HTTP server and return (server, port)."""
    port = _find_free_port()

    class _Handler(_StubWorkerHandler):
        pass

    _Handler.response_body = response_body
    _Handler.response_status = status

    srv = HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# ===========================================================================
# Tests: WorkerEndpoint
# ===========================================================================


class TestWorkerEndpoint(unittest.TestCase):
    def test_from_string_basic(self):
        ep = WorkerEndpoint.from_string("127.0.0.1:13337")
        self.assertEqual(ep.host, "127.0.0.1")
        self.assertEqual(ep.port, 13337)
        self.assertEqual(ep.worker_id, "127.0.0.1:13337")

    def test_from_string_with_id(self):
        ep = WorkerEndpoint.from_string("10.0.0.1:13337:myworker")
        self.assertEqual(ep.worker_id, "myworker")

    def test_from_string_invalid_port(self):
        with self.assertRaises(ValueError):
            WorkerEndpoint.from_string("127.0.0.1:notaport")

    def test_from_string_missing_port(self):
        with self.assertRaises(ValueError):
            WorkerEndpoint.from_string("127.0.0.1")

    def test_base_url(self):
        ep = WorkerEndpoint(host="192.168.1.1", port=8080)
        self.assertEqual(ep.base_url, "http://192.168.1.1:8080")

    def test_str(self):
        ep = WorkerEndpoint(host="localhost", port=9001, worker_id="w1")
        self.assertEqual(str(ep), "w1")


# ===========================================================================
# Tests: MockRouter
# ===========================================================================


class TestMockRouter(unittest.TestCase):
    def test_round_robin_two_workers(self):
        ep1 = WorkerEndpoint("127.0.0.1", 13337)
        ep2 = WorkerEndpoint("127.0.0.1", 13338)
        router = MockRouter(workers=[ep1, ep2])

        # First call → ep1
        result1 = router.select_worker("tools/call", None)
        # Second call → ep2
        result2 = router.select_worker("tools/call", None)
        # Third call → wraps back to ep1
        result3 = router.select_worker("tools/call", None)

        self.assertEqual(result1, ep1)
        self.assertEqual(result2, ep2)
        self.assertEqual(result3, ep1)

    def test_round_robin_single_worker(self):
        ep = WorkerEndpoint("127.0.0.1", 13337)
        router = MockRouter(workers=[ep])
        for _ in range(5):
            self.assertEqual(router.select_worker("ping", {}), ep)

    def test_no_workers_raises(self):
        router = MockRouter()
        with self.assertRaises(RuntimeError):
            router.select_worker("tools/call", None)

    def test_list_workers(self):
        eps = [WorkerEndpoint("127.0.0.1", p) for p in (13337, 13338, 13339)]
        router = MockRouter(workers=eps)
        self.assertEqual(router.list_workers(), eps)

    def test_add_worker(self):
        router = MockRouter()
        ep = WorkerEndpoint("127.0.0.1", 13337)
        router.add_worker(ep)
        self.assertEqual(router.select_worker("ping", None), ep)

    def test_router_is_abc(self):
        """MockRouter implements the Router ABC."""
        self.assertIsInstance(MockRouter(), Router)


# ===========================================================================
# Tests: forwarder.forward_request
# ===========================================================================


class TestForwardRequest(unittest.TestCase):
    def test_successful_forward(self):
        canned = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}
        srv, port = _start_stub_server(json.dumps(canned).encode())
        try:
            ep = WorkerEndpoint("127.0.0.1", port)
            body = json.dumps(
                {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
            ).encode()
            result = forward_request(ep, body, timeout=5.0)
            self.assertEqual(result, canned)
        finally:
            srv.shutdown()

    def test_connection_refused_returns_error(self):
        """When the worker is not reachable, a JSON-RPC error dict is returned."""
        port = _find_free_port()  # nothing listening here
        ep = WorkerEndpoint("127.0.0.1", port)
        body = json.dumps(
            {"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 99}
        ).encode()
        result = forward_request(ep, body, timeout=1.0)
        self.assertIn("error", result)
        self.assertEqual(result["id"], 99)
        self.assertEqual(result["error"]["code"], -32000)

    def test_invalid_json_response_returns_error(self):
        srv, port = _start_stub_server(b"NOT JSON AT ALL")
        try:
            ep = WorkerEndpoint("127.0.0.1", port)
            body = json.dumps(
                {"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 7}
            ).encode()
            result = forward_request(ep, body, timeout=5.0)
            self.assertIn("error", result)
            self.assertEqual(result["error"]["code"], -32700)
            self.assertEqual(result["id"], 7)
        finally:
            srv.shutdown()

    def test_extra_headers_forwarded(self):
        """Extra headers (e.g. Mcp-Session-Id) are forwarded to the worker."""
        received_headers: dict[str, str] = {}

        class _HeaderCapture(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self) -> None:  # noqa: N802
                received_headers["Mcp-Session-Id"] = self.headers.get(
                    "Mcp-Session-Id", ""
                )
                content_length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(content_length)
                body = b'{"jsonrpc":"2.0","result":{},"id":1}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        capture_port = _find_free_port()
        srv = HTTPServer(("127.0.0.1", capture_port), _HeaderCapture)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            ep = WorkerEndpoint("127.0.0.1", capture_port)
            body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode()
            forward_request(
                ep, body, extra_headers={"Mcp-Session-Id": "abc-123"}, timeout=5.0
            )
            self.assertEqual(received_headers.get("Mcp-Session-Id"), "abc-123")
        finally:
            srv.shutdown()


# ===========================================================================
# Tests: CLI argument parsing
# ===========================================================================


class TestCliArgParsing(unittest.TestCase):
    def _parse(self, argv: list[str]) -> argparse.Namespace:
        # Re-run just the argparse portion of main() in isolation.
        parser = argparse.ArgumentParser()
        parser.add_argument("--host", default="0.0.0.0")
        parser.add_argument("--port", type=int, default=9000)
        parser.add_argument("--worker", dest="workers", action="append", default=[])
        parser.add_argument("--registry-url", default=None)
        parser.add_argument("--timeout", type=float, default=180.0)
        return parser.parse_args(argv)

    def test_default_values(self):
        args = self._parse([])
        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 9000)
        self.assertEqual(args.workers, [])
        self.assertIsNone(args.registry_url)
        self.assertEqual(args.timeout, 180.0)

    def test_single_worker(self):
        args = self._parse(["--worker", "127.0.0.1:13337"])
        self.assertEqual(args.workers, ["127.0.0.1:13337"])

    def test_multiple_workers(self):
        args = self._parse(
            ["--worker", "127.0.0.1:13337", "--worker", "127.0.0.1:13338"]
        )
        self.assertEqual(len(args.workers), 2)

    def test_custom_port_and_host(self):
        args = self._parse(["--host", "192.168.1.1", "--port", "8000"])
        self.assertEqual(args.host, "192.168.1.1")
        self.assertEqual(args.port, 8000)

    def test_registry_url_parsed(self):
        args = self._parse(["--registry-url", "redis://localhost:6379"])
        self.assertEqual(args.registry_url, "redis://localhost:6379")


# ===========================================================================
# Tests: CoordinatorServer health endpoint
# ===========================================================================


class TestCoordinatorHealthEndpoint(unittest.TestCase):
    def test_health_returns_json(self):
        """GET /coordinator/health returns a valid JSON status document."""
        import urllib.request

        port = _find_free_port()
        router = MockRouter()
        server = CoordinatorServer(host="127.0.0.1", port=port, router=router)
        server.serve(background=True)
        # Give the server a moment to start
        time.sleep(0.15)
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/coordinator/health", timeout=5
            ) as resp:
                data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "ok")
            self.assertIn("workers", data)
            self.assertIn("uptime_seconds", data)
        finally:
            server.stop()

    def test_health_lists_workers(self):
        """Health endpoint lists workers even when they are unreachable."""
        import urllib.request

        dead_port = _find_free_port()  # nothing listening
        ep = WorkerEndpoint("127.0.0.1", dead_port)
        router = MockRouter(workers=[ep])

        coord_port = _find_free_port()
        server = CoordinatorServer(host="127.0.0.1", port=coord_port, router=router)
        server.serve(background=True)
        time.sleep(0.15)
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{coord_port}/coordinator/health", timeout=5
            ) as resp:
                data = json.loads(resp.read().decode())
            self.assertEqual(data["worker_count"], 1)
            self.assertEqual(data["workers"][0]["alive"], False)
        finally:
            server.stop()


# ===========================================================================
# Tests: CoordinatorServer MCP forwarding
# ===========================================================================


class TestCoordinatorForwarding(unittest.TestCase):
    def test_forwards_request_to_worker(self):
        """POST /mcp is transparently forwarded to the worker."""
        import urllib.request

        canned = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 42}
        worker_srv, worker_port = _start_stub_server(json.dumps(canned).encode())

        coord_port = _find_free_port()
        ep = WorkerEndpoint("127.0.0.1", worker_port)
        router = MockRouter(workers=[ep])
        server = CoordinatorServer(host="127.0.0.1", port=coord_port, router=router)
        server.serve(background=True)
        time.sleep(0.15)
        try:
            req_body = json.dumps(
                {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 42}
            ).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{coord_port}/mcp",
                data=req_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            self.assertEqual(data, canned)
        finally:
            server.stop()
            worker_srv.shutdown()

    def test_no_workers_returns_error(self):
        """POST /mcp with no workers returns a JSON-RPC error."""
        import urllib.request

        coord_port = _find_free_port()
        router = MockRouter()  # no workers
        server = CoordinatorServer(host="127.0.0.1", port=coord_port, router=router)
        server.serve(background=True)
        time.sleep(0.15)
        try:
            req_body = json.dumps(
                {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 5}
            ).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{coord_port}/mcp",
                data=req_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            self.assertIn("error", data)
            self.assertEqual(data["id"], 5)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
