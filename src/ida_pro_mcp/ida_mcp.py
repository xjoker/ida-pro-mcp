"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Features:
- Web-based configuration at http://host:port/config.html
- Bilingual interface (English/中文)
- Server restart on config change
"""

import sys
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP Server for LLM-assisted reverse engineering"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp = None
        self._current_host = None
        self._current_port = None
        return idaapi.PLUGIN_KEEP

    def _restart_server(self, new_host: str, new_port: int):
        """Callback to restart the server with new configuration."""
        print(f"[MCP] Restarting server on {new_host}:{new_port}...")

        # Stop current server
        if self.mcp:
            try:
                self.mcp.stop()
            except Exception as e:
                print(f"[MCP] Error stopping server: {e}")
            self.mcp = None

        # Small delay to ensure port is released
        import time
        time.sleep(0.2)

        # Reload package and start new server
        unload_package("ida_mcp")

        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Set restart callback
        set_server_restart_callback(self._restart_server)

        try:
            MCP_SERVER.serve(new_host, new_port, request_handler=IdaMcpHttpRequestHandler)
            self._current_host = new_host
            self._current_port = new_port
            print(f"[MCP] Server restarted on http://{new_host}:{new_port}")
            print(f"  Config: http://{new_host}:{new_port}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            if e.errno in (48, 98, 10048):
                print(f"[MCP] Error: Port {new_port} is already in use")
            else:
                print(f"[MCP] Error starting server: {e}")

    def run(self, arg):
        # Toggle server on/off
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            print("[MCP] Server stopped")
            return

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback, get_server_config
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback, get_server_config

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Set restart callback for web config
        set_server_restart_callback(self._restart_server)

        # Get server config from IDA database
        server_config = get_server_config()
        host = server_config.get("host", "127.0.0.1")
        port = server_config.get("port", 13337)

        try:
            MCP_SERVER.serve(host, port, request_handler=IdaMcpHttpRequestHandler)
            self._current_host = host
            self._current_port = port
            print(f"[MCP] Server started on http://{host}:{port}")
            print(f"  Config: http://{host}:{port}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            if e.errno in (48, 98, 10048):
                print(f"[MCP] Error: Port {port} is already in use")
            else:
                raise

    def term(self):
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
