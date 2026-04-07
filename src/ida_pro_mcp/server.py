import os
import sys
import json
import argparse
import http.client
import traceback
import threading
from queue import Queue, Empty, Full
from contextlib import contextmanager
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337


# ============================================================================
# HTTP Connection Pool
# ============================================================================


class ConnectionPool:
    """HTTP connection pool for reusing TCP connections to IDA Pro.

    Reduces TCP handshake overhead by maintaining a pool of persistent connections.
    Thread-safe implementation with automatic connection recycling.
    """

    def __init__(self, host: str, port: int, max_size: int = 10, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.max_size = max_size
        self.timeout = timeout
        self._pool: Queue = Queue(maxsize=max_size)
        self._lock = threading.Lock()
        self._created = 0

    def _create_connection(self) -> http.client.HTTPConnection:
        """Create a new HTTP connection."""
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool (context manager).

        Yields a connection from the pool or creates a new one if pool is empty.
        Returns connection to pool on success, discards on error.
        """
        conn = None
        reused = False

        # Try to get from pool first (non-blocking)
        try:
            conn = self._pool.get_nowait()
            reused = True
        except Empty:
            # Pool empty, try to create new connection
            with self._lock:
                if self._created < self.max_size:
                    conn = self._create_connection()
                    self._created += 1

        # If still no connection, wait for one from pool
        if conn is None:
            try:
                conn = self._pool.get(timeout=self.timeout)
                reused = True
            except Empty:
                # Timeout waiting for connection, create one anyway
                conn = self._create_connection()

        try:
            # Verify connection is still alive if reused
            if reused:
                try:
                    # Check if connection is still valid
                    conn.sock  # Access sock to verify connection state
                except Exception:
                    # Connection broken, create new one
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = self._create_connection()

            yield conn

            # Return connection to pool on success
            try:
                self._pool.put_nowait(conn)
            except Full:
                # Pool full, close this connection
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception:
            # Error occurred, close and discard connection
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                if self._created > 0:
                    self._created -= 1
            raise

    def close_all(self):
        """Close all connections in the pool."""
        while True:
            try:
                conn = self._pool.get_nowait()
                try:
                    conn.close()
                except Exception:
                    pass
            except Empty:
                break
        with self._lock:
            self._created = 0


_connection_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def _get_connection_pool() -> ConnectionPool:
    """Get or create the global connection pool (thread-safe singleton)."""
    global _connection_pool
    if _connection_pool is None:
        with _pool_lock:
            if _connection_pool is None:
                _connection_pool = ConnectionPool(IDA_HOST, IDA_PORT)
    return _connection_pool


def _reset_connection_pool():
    """Reset the connection pool (called when IDA host/port changes)."""
    global _connection_pool
    with _pool_lock:
        if _connection_pool is not None:
            _connection_pool.close_all()
            _connection_pool = None


mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry.

    Uses connection pooling for improved performance.
    """
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    elif request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    pool = _get_connection_pool()
    try:
        if isinstance(request, dict):
            request_bytes = json.dumps(request).encode("utf-8")
        elif isinstance(request, str):
            request_bytes = request.encode("utf-8")
        else:
            request_bytes = request

        with pool.get_connection() as conn:
            conn.request(
                "POST", "/mcp", request_bytes, {"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
    except Exception as e:
        full_info = traceback.format_exc()
        id = request_obj.get("id")
        if id is None:
            return None  # Notification, no response needed

        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP Server to start the server?\n{full_info}",
                    "data": str(e),
                },
                "id": id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


def main():
    from ida_pro_mcp.installer import (
        install_ida_plugin,
        install_mcp_servers,
        print_mcp_config,
    )

    global IDA_HOST, IDA_PORT
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    # Reset connection pool if host/port changed
    _reset_connection_pool()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(
            stdio=(args.transport == "stdio"),
            ida_host=IDA_HOST,
            ida_port=IDA_PORT,
        )
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True, ida_host=IDA_HOST, ida_port=IDA_PORT)
        return

    if args.config:
        print_mcp_config(IDA_HOST, IDA_PORT)
        return

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
