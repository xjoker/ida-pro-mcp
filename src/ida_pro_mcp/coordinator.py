"""
IDA Pro MCP Coordinator — multi-machine deployment entry point.

The coordinator is a single MCP server that accepts connections from MCP
clients and transparently forwards every request to one of the registered
IDA/idalib worker processes.  Clients are unaware of the worker pool; they
see a single MCP server endpoint.

Usage
-----
    ida-mcp-coordinator --host 0.0.0.0 --port 9000 \\
        --worker 127.0.0.1:13337 --worker 127.0.0.1:13338

The --registry-url flag is reserved for Wave 2B (Redis-backed registry).
When omitted the coordinator uses a simple round-robin MockRouter seeded
from the --worker arguments.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from ida_pro_mcp.distributed.forwarder import DEFAULT_TIMEOUT, forward_request
from ida_pro_mcp.distributed.router import MockRouter, Router, WorkerEndpoint

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SERVER_NAME = "ida-mcp-coordinator"
_SERVER_VERSION = "1.4.0-dev"

# Probe timeout when checking worker liveness for /coordinator/health.
_HEALTH_PROBE_TIMEOUT: float = 2.0


# ---------------------------------------------------------------------------
# Worker liveness probe
# ---------------------------------------------------------------------------


def _probe_worker(endpoint: WorkerEndpoint, timeout: float = _HEALTH_PROBE_TIMEOUT) -> bool:
    """Return True if the worker at *endpoint* responds to a ping."""
    try:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "ping",
                "params": {},
                "id": 1,
            }
        ).encode("utf-8")
        conn = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)
        conn.request("POST", "/mcp", body, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()  # drain
        conn.close()
        return resp.status < 500
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class CoordinatorRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for coordinator requests.

    Routes:
        POST /mcp                 — forward JSON-RPC to a worker
        GET  /coordinator/health  — liveness / readiness check
        *                         — 404
    """

    server_version = f"zeromcp-coordinator/{_SERVER_VERSION}"
    error_message_format = "%(code)d - %(message)s"
    error_content_type = "text/plain"

    # Injected by CoordinatorServer.serve()
    coordinator: "CoordinatorServer"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        # Delegate to coordinator logger so output can be controlled centrally.
        self.coordinator._log(fmt % args)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"{message or code}\n".encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/coordinator/health":
            self._handle_health()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/mcp":
            self._handle_mcp_post()
        else:
            self.send_error(404, "Not Found")

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    # ------------------------------------------------------------------
    # /coordinator/health
    # ------------------------------------------------------------------

    def _handle_health(self) -> None:
        workers_status = []
        for endpoint in self.coordinator.router.list_workers():
            alive = _probe_worker(endpoint)
            workers_status.append(
                {
                    "endpoint": str(endpoint),
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "alive": alive,
                }
            )

        payload = {
            "status": "ok",
            "server": _SERVER_NAME,
            "version": _SERVER_VERSION,
            "uptime_seconds": round(time.monotonic() - self.coordinator.start_time, 1),
            "workers": workers_status,
            "worker_count": len(workers_status),
            "alive_count": sum(1 for w in workers_status if w["alive"]),
        }
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # POST /mcp  — transparent forward to a worker
    # ------------------------------------------------------------------

    def _handle_mcp_post(self) -> None:
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Collect headers that should be forwarded verbatim.
        extra_headers: dict[str, str] = {}
        for hdr in ("Authorization", "Mcp-Session-Id", "Mcp-Protocol-Version"):
            val = self.headers.get(hdr)
            if val:
                extra_headers[hdr] = val

        # Parse method + id for routing / error correlation.
        request_method = ""
        request_params: dict | None = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                request_method = parsed.get("method", "")
                request_params = parsed.get("params")
        except Exception:
            pass

        # Select worker
        try:
            endpoint = self.coordinator.router.select_worker(request_method, request_params)
        except RuntimeError as exc:
            self._send_jsonrpc_error(-32000, str(exc), body)
            return

        # Forward
        response_dict = forward_request(
            endpoint,
            body,
            extra_headers=extra_headers,
            timeout=self.coordinator.forward_timeout,
        )

        response_bytes = json.dumps(response_dict).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_jsonrpc_error(self, code: int, message: str, raw_body: bytes) -> None:
        """Send a JSON-RPC error response derived from the incoming request body."""
        req_id = None
        try:
            parsed = json.loads(raw_body)
            if isinstance(parsed, dict):
                req_id = parsed.get("id")
        except Exception:
            pass

        error_response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }
        body = json.dumps(error_response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Coordinator server
# ---------------------------------------------------------------------------


class CoordinatorServer:
    """Manages the HTTP lifecycle of the coordinator process."""

    def __init__(
        self,
        host: str,
        port: int,
        router: Router,
        forward_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.router = router
        self.forward_timeout = forward_timeout
        self.start_time: float = time.monotonic()

        self._http_server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def serve(self, *, background: bool = True) -> None:
        """Bind the port and start serving requests."""
        if self._running:
            self._log("Server is already running")
            return

        # Build a request handler class that has a reference to *this* server.
        coordinator_ref = self

        class _Handler(CoordinatorRequestHandler):
            coordinator = coordinator_ref

        self._http_server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._http_server.allow_reuse_address = True
        self._running = True

        workers = self.router.list_workers()
        self._log(f"Coordinator started on http://{self.host}:{self.port}/mcp")
        self._log(f"  Health: http://{self.host}:{self.port}/coordinator/health")
        self._log(f"  Workers: {[str(w) for w in workers]}")

        def _serve_forever() -> None:
            try:
                self._http_server.serve_forever()  # type: ignore[union-attr]
            except Exception as exc:
                self._log(f"Server error: {exc}")
                traceback.print_exc()
            finally:
                self._running = False

        if background:
            self._server_thread = threading.Thread(target=_serve_forever, daemon=True)
            self._server_thread.start()
        else:
            _serve_forever()

    def stop(self) -> None:
        """Shut down the HTTP server."""
        if not self._running:
            return
        self._running = False
        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
        if self._server_thread:
            self._server_thread.join(timeout=5)
            self._server_thread = None
        self._log("Coordinator stopped")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        print(f"[coordinator] {message}", flush=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ida-mcp-coordinator",
        description=(
            "IDA Pro MCP Coordinator — transparent multi-worker proxy for MCP clients. "
            "Routes incoming MCP requests to one of the registered IDA worker processes."
        ),
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host/IP to bind the coordinator server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Port to listen on (default: 9000)",
    )
    parser.add_argument(
        "--worker",
        dest="workers",
        metavar="HOST:PORT",
        action="append",
        default=[],
        help=(
            "Worker endpoint in host:port format.  "
            "May be repeated for multiple workers.  "
            "Example: --worker 127.0.0.1:13337 --worker 192.168.1.10:13337"
        ),
    )
    parser.add_argument(
        "--registry-url",
        default=None,
        metavar="URL",
        help=(
            "Registry URL for dynamic worker discovery (e.g. redis://localhost:6379).  "
            "Not implemented yet — reserved for Wave 2B."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Forward request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    args = parser.parse_args()

    # Warn if registry URL was supplied but not yet supported.
    if args.registry_url:
        print(
            f"[coordinator] WARNING: --registry-url '{args.registry_url}' is reserved "
            "for Wave 2B and will be ignored in this version.",
            file=sys.stderr,
            flush=True,
        )

    # Build the router from --worker flags.
    endpoints: list[WorkerEndpoint] = []
    for spec in args.workers:
        try:
            endpoints.append(WorkerEndpoint.from_string(spec))
        except ValueError as exc:
            print(f"[coordinator] ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

    if not endpoints:
        print(
            "[coordinator] WARNING: no --worker endpoints specified. "
            "All MCP requests will fail until workers are added.",
            file=sys.stderr,
            flush=True,
        )

    router = MockRouter(workers=endpoints)

    server = CoordinatorServer(
        host=args.host,
        port=args.port,
        router=router,
        forward_timeout=args.timeout,
    )

    server.serve(background=True)
    print(
        f"[coordinator] Listening on http://{args.host}:{args.port}  "
        "(Press Enter or Ctrl+C to stop)",
        flush=True,
    )
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
