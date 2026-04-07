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


# ============================================================================
# Per-Instance Connection Pool Management
# ============================================================================

_instance_pools: dict[tuple[str, int], ConnectionPool] = {}
_pool_lock = threading.Lock()

# Session-to-instance routing: transport_session_id -> (host, port)
# Bounded to prevent memory leaks from SSE reconnections
_MAX_SESSION_ROUTES = 1000
_session_routes: dict[str, tuple[str, int]] = {}
_routes_lock = threading.Lock()


def _get_pool_for(host: str, port: int) -> ConnectionPool:
    """Get or create a connection pool for a specific IDA instance."""
    key = (host, port)
    if key not in _instance_pools:
        with _pool_lock:
            if key not in _instance_pools:
                _instance_pools[key] = ConnectionPool(host, port)
    return _instance_pools[key]


def _reset_all_pools():
    """Close all connection pools."""
    with _pool_lock:
        for pool in _instance_pools.values():
            pool.close_all()
        _instance_pools.clear()


def _probe_instance(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """Probe an IDA instance via health check. Returns metadata or None."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        request_body = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1.0"},
            },
            "id": 1,
        }).encode("utf-8")
        conn.request("POST", "/mcp", request_body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        conn.close()
        if "result" in data:
            return data["result"].get("serverInfo", {})
        return {}
    except Exception:
        return None


# ============================================================================
# MCP Server & Local Tools
# ============================================================================

# Local tool names — handled directly, not proxied to IDA
_LOCAL_TOOLS: set[str] = set()

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


@mcp.tool
def list_instances(
    host: str = "127.0.0.1",
    port_range_start: int = 13337,
    port_range_end: int = 13347,
) -> dict:
    """Discover running IDA Pro instances by scanning ports"""
    instances = []
    for port in range(port_range_start, port_range_end):
        info = _probe_instance(host, port)
        if info is not None:
            instances.append({
                "host": host,
                "port": port,
                "server_info": info,
                "url": f"http://{host}:{port}/mcp",
            })
    return {
        "instances": instances,
        "count": len(instances),
        "_ai_instruction": "Use select_instance(port=N) to route subsequent calls to a specific IDA instance.",
    }


@mcp.tool
def select_instance(
    port: int,
    host: str = "127.0.0.1",
) -> dict:
    """Route subsequent tool calls to a specific IDA instance"""
    # Get current transport session ID
    session_id = mcp.get_current_transport_session_id() or "default"

    # Verify instance is alive
    info = _probe_instance(host, port)
    if info is None:
        return {"error": f"No IDA instance at {host}:{port}", "selected": False}

    with _routes_lock:
        # Evict oldest entries if over limit
        if len(_session_routes) >= _MAX_SESSION_ROUTES:
            oldest = next(iter(_session_routes))
            del _session_routes[oldest]
        _session_routes[session_id] = (host, port)

    return {
        "host": host,
        "port": port,
        "session_id": session_id,
        "server_info": info,
        "selected": True,
    }


_LOCAL_TOOLS.update({"list_instances", "select_instance"})


def _get_target_for_session() -> tuple[str, int]:
    """Resolve the target IDA instance for the current transport session."""
    session_id = mcp.get_current_transport_session_id()
    if session_id:
        with _routes_lock:
            route = _session_routes.get(session_id)
            if route:
                return route
    return (IDA_HOST, IDA_PORT)


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests, routing to the selected IDA instance.

    Local tools (list_instances, select_instance) are handled directly.
    All other requests are proxied to the target IDA instance.
    """
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]

    # Handle locally: initialize, notifications
    if method == "initialize" or method.startswith("notifications/"):
        return dispatch_original(request)

    # tools/list: merge local + remote tool lists
    if method == "tools/list":
        local_response = dispatch_original(request)
        target_host, target_port = _get_target_for_session()
        try:
            pool = _get_pool_for(target_host, target_port)
            request_bytes = json.dumps(request_obj).encode("utf-8")
            with pool.get_connection() as conn:
                conn.request("POST", "/mcp", request_bytes, {"Content-Type": "application/json"})
                response = conn.getresponse()
                remote_response = json.loads(response.read().decode())
            # Merge: local tools + remote tools (skip duplicates)
            if local_response and "result" in local_response:
                local_tools = local_response["result"].get("tools", [])
                remote_tools = remote_response.get("result", {}).get("tools", []) if remote_response else []
                local_names = {t["name"] for t in local_tools}
                merged = local_tools + [t for t in remote_tools if t["name"] not in local_names]
                local_response["result"]["tools"] = merged
            return local_response
        except Exception:
            return dispatch_original(request)  # fallback: local tools only

    # tools/call: route local tools directly, proxy the rest
    if method == "tools/call":
        tool_name = request_obj.get("params", {}).get("name", "")
        if tool_name in _LOCAL_TOOLS:
            return dispatch_original(request)

    # Resolve target IDA instance for this session
    target_host, target_port = _get_target_for_session()
    pool = _get_pool_for(target_host, target_port)

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
        req_id = request_obj.get("id")
        if req_id is None:
            return None

        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to connect to IDA Pro at {target_host}:{target_port}! "
                               f"Did you run Edit -> Plugins -> MCP Server?\n{full_info}",
                    "data": str(e),
                },
                "id": req_id,
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
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    args = parser.parse_args()

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port

    # Reset connection pools if host/port changed
    _reset_all_pools()

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

    # Enable unsafe tools if requested
    if args.unsafe:
        mcp.set_unsafe_enabled(True)

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
