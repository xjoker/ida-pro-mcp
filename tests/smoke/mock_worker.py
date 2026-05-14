"""Mock IDA worker for v1.5 smoke testing.

Simulates an idalib-mcp worker WITHOUT requiring IDA Pro installed:
- Registers to Redis Registry (uses our Wave 1B Registry code)
- Sends heartbeats every 5s (uses Wave 2A WorkerLifecycle)
- Exposes a fake HTTP/MCP endpoint that replies with mock responses
- Allows testing the full v1.4 multi-host flow end-to-end

Usage:
    # Single mock worker:
    python tests/smoke/mock_worker.py --redis redis://localhost:6379/0 \\
        --advertise-host localhost --port 13337 --loaded-idb /demo/example.idb

    # Inside docker-compose (auto-uses service-name):
    python tests/smoke/mock_worker.py --redis redis://redis:6379/0 \\
        --advertise-host mock-worker --port 13337
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Make src/ importable when run directly (no install needed).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ida_pro_mcp.distributed.registry import Registry  # noqa: E402
from ida_pro_mcp.distributed.worker_lifecycle import WorkerLifecycle  # noqa: E402

logger = logging.getLogger("mock_worker")


class MockMcpHandler(BaseHTTPRequestHandler):
    """Replies to MCP-like JSON-RPC requests with canned responses."""

    server_version = "MockIdaWorker/1.0"

    # Captured by main() and set on the class before serve_forever.
    worker_id: str = ""
    loaded_idb: str | None = None

    def log_message(self, format: str, *args) -> None:
        logger.info("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:
        if self.path == "/health":
            body = {
                "status": "ok",
                "worker_id": self.worker_id,
                "loaded_idb": self.loaded_idb,
                "mock": True,
            }
            self._send_json(200, body)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b""
            req = json.loads(raw) if raw else {}
        except (ValueError, json.JSONDecodeError) as e:
            self._send_json(400, {"error": f"bad request: {e}"})
            return

        method = req.get("method", "")
        req_id = req.get("id")

        # Canned responses for common MCP methods
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": f"mock-ida-worker-{self.worker_id[:8]}",
                    "version": "1.0.0-smoke",
                },
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "mock_decompile",
                        "description": "Mock decompile (returns canned C code)",
                    },
                    {
                        "name": "mock_disasm",
                        "description": "Mock disassembly",
                    },
                ]
            }
        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "?")
            args = req.get("params", {}).get("arguments", {})
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": f"[mock-worker {self.worker_id[:8]}] {tool_name}({args}) → ok",
                    }
                ]
            }
        else:
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"unknown method: {method}"},
                },
            )
            return

        self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--redis",
        default="redis://localhost:6379/0",
        help="Redis URL for Registry (default: redis://localhost:6379/0)",
    )
    parser.add_argument(
        "--namespace",
        default="idamcp",
        help="Registry namespace (default: idamcp)",
    )
    parser.add_argument(
        "--advertise-host",
        default="localhost",
        help="Host to advertise in Registry (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=13337,
        help="HTTP port to bind (default: 13337)",
    )
    parser.add_argument(
        "--loaded-idb",
        default=None,
        help="Simulate having an IDB loaded (for affinity-routing tests)",
    )
    parser.add_argument(
        "--capabilities",
        default="mock,idalib,headless",
        help="Capabilities CSV (default: mock,idalib,headless)",
    )
    parser.add_argument(
        "--heartbeat",
        type=float,
        default=5.0,
        help="Heartbeat interval in seconds (default: 5.0)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    capabilities = tuple(c.strip() for c in args.capabilities.split(",") if c.strip())

    logger.info("Connecting to Redis: %s (namespace=%s)", args.redis, args.namespace)
    registry = Registry(args.redis, namespace=args.namespace)

    lifecycle = WorkerLifecycle(
        registry=registry,
        host=args.advertise_host,
        port=args.port,
        capabilities=capabilities,
        heartbeat_interval=args.heartbeat,
    )

    if args.loaded_idb:
        lifecycle.update_loaded_idb(args.loaded_idb)

    logger.info(
        "Starting mock worker: id=%s host=%s port=%d caps=%s loaded_idb=%s",
        lifecycle.worker_id,
        args.advertise_host,
        args.port,
        capabilities,
        args.loaded_idb,
    )

    lifecycle.start()

    # Configure handler class-level attrs (BaseHTTPRequestHandler instances are short-lived).
    MockMcpHandler.worker_id = lifecycle.worker_id
    MockMcpHandler.loaded_idb = args.loaded_idb

    server = ThreadingHTTPServer((args.advertise_host if args.advertise_host != "localhost" else "0.0.0.0", args.port), MockMcpHandler)
    logger.info("Mock HTTP server listening on %s:%d", server.server_address[0], server.server_address[1])

    shutdown_event = threading.Event()

    def handle_signal(signum, _frame):
        logger.info("Received signal %d, shutting down…", signum)
        shutdown_event.set()
        server.shutdown()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        logger.info("Stopping lifecycle (deregister)…")
        lifecycle.stop()
        server.server_close()
        logger.info("Mock worker exited cleanly.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
