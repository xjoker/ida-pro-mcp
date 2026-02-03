"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Supports:
- Multiple server instances with different hosts/ports
- API Key authentication
- Native IDA configuration UI (Ctrl+Shift+M)
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
        print("[MCP] Use Ctrl+Shift+M to open configuration dialog")

        self._server_manager = None
        self._ui_registered = False
        self._mcp_server = None

        return idaapi.PLUGIN_KEEP

    def _ensure_loaded(self):
        """Ensure ida_mcp package is loaded and return required modules."""
        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")

        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from .ida_mcp.config import get_config, ServerInstanceConfig
            from .ida_mcp.server_manager import get_server_manager
            from .ida_mcp.ui import register_actions, show_config_dialog
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from ida_mcp.config import get_config, ServerInstanceConfig
            from ida_mcp.server_manager import get_server_manager
            from ida_mcp.ui import register_actions, show_config_dialog

        return {
            "MCP_SERVER": MCP_SERVER,
            "IdaMcpHttpRequestHandler": IdaMcpHttpRequestHandler,
            "init_caches": init_caches,
            "get_config": get_config,
            "ServerInstanceConfig": ServerInstanceConfig,
            "get_server_manager": get_server_manager,
            "register_actions": register_actions,
            "show_config_dialog": show_config_dialog,
        }

    def run(self, arg):
        modules = self._ensure_loaded()

        MCP_SERVER = modules["MCP_SERVER"]
        IdaMcpHttpRequestHandler = modules["IdaMcpHttpRequestHandler"]
        init_caches = modules["init_caches"]
        get_config = modules["get_config"]
        ServerInstanceConfig = modules["ServerInstanceConfig"]
        get_server_manager = modules["get_server_manager"]
        register_actions = modules["register_actions"]

        # Register UI actions if not already done
        if not self._ui_registered:
            register_actions()
            self._ui_registered = True

        # Initialize caches
        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Get server manager and config
        manager = get_server_manager()
        config = get_config()

        # Set up server factory
        def create_server():
            return MCP_SERVER

        manager.set_server_factory(create_server)
        manager.set_request_handler(IdaMcpHttpRequestHandler)

        # Load servers from config
        if len(manager) == 0:
            manager.load_from_config(config)

        # If no servers configured, add a default one
        if len(manager) == 0:
            default_config = ServerInstanceConfig(
                instance_id="local",
                host="127.0.0.1",
                port=13337,
            )
            manager.add_server(default_config)

        # Start the first server (or all auto-start servers)
        started = manager.start_auto_servers()
        if started == 0:
            # No auto-start servers, start the first one
            status = manager.get_status()
            if status:
                first_id = list(status.keys())[0]
                instance = manager.get_instance(first_id)
                if instance and not instance.is_running:
                    if manager.start_server(first_id):
                        print(f"  Config: http://{instance.config.host}:{instance.config.port}/config.html")

        self._server_manager = manager
        self._mcp_server = MCP_SERVER

    def term(self):
        if self._server_manager:
            self._server_manager.stop_all()
            self._server_manager = None

        if self._ui_registered:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.ui import unregister_actions
                else:
                    from ida_mcp.ui import unregister_actions
                unregister_actions()
            except ImportError:
                pass
            self._ui_registered = False


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
