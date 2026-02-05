"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Features:
- Web-based configuration at http://host:port/config.html
- Bilingual interface (English/中文)
- Server restart on config change
- Auto port increment on conflict
"""

import logging
import sys
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ida_mcp.zeromcp.mcp import McpServer

# Configure logging to stdout (IDA console)
logging.basicConfig(
    level=logging.INFO,
    format="[MCP] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def unload_package(package_name: str) -> None:
    """Remove every module that belongs to the package from sys.modules.

    Args:
        package_name: The package name to unload (e.g., 'ida_mcp')
    """
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(idaapi.plugin_t):
    """IDA Pro MCP Plugin for LLM-assisted reverse engineering.

    Provides an MCP (Model Context Protocol) server that allows AI assistants
    to interact with IDA Pro's disassembler and decompiler.

    Attributes:
        flags: Plugin flags for IDA
        comment: Plugin description
        help: Help text
        wanted_name: Menu item name
        wanted_hotkey: Keyboard shortcut (empty = none)
    """

    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Server for LLM-assisted reverse engineering"
    help = "Start/Stop MCP Server for AI assistants like Claude"
    wanted_name = "MCP Server"  # Menu name: Edit -> Plugins -> MCP Server
    wanted_hotkey = ""  # No hotkey

    def init(self) -> int:
        """Initialize the plugin when IDA loads it.

        Returns:
            PLUGIN_KEEP to keep the plugin loaded
        """
        logger.info("Plugin loaded, use Edit -> Plugins -> MCP Server to toggle")
        self.mcp: McpServer | None = None
        self._current_host: str | None = None
        self._current_port: int | None = None

        # Auto-start server on IDA launch
        self._auto_start()

        return idaapi.PLUGIN_KEEP

    def _auto_start(self) -> None:
        """Auto-start server when IDA loads a database.

        Uses a timer to delay startup until IDA is fully initialized.
        """
        def delayed_start() -> int:
            if self.mcp is None:
                self._start_server()
            return -1  # Don't repeat

        # Delay 1 second to ensure IDA is ready
        idaapi.register_timer(1000, delayed_start)

    def _start_server(self) -> None:
        """Start the MCP server with automatic port retry on conflict."""
        if self.mcp:
            return  # Already running

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback, get_server_config
            from .ida_mcp.port_utils import try_serve_with_port_retry, format_port_exhausted_message
            from .ida_mcp.rpc import set_download_base_url
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback, get_server_config
            from ida_mcp.port_utils import try_serve_with_port_retry, format_port_exhausted_message
            from ida_mcp.rpc import set_download_base_url

        try:
            init_caches()
        except Exception as e:
            logger.warning(f"Cache init failed: {e}")

        # Set restart callback for web config
        set_server_restart_callback(self._restart_server)

        # Get server config from IDA database
        server_config = get_server_config()
        host = server_config.get("host", "127.0.0.1")
        port = server_config.get("port", 13337)

        try:
            actual_port, failed_ports = try_serve_with_port_retry(
                MCP_SERVER, host, port, request_handler=IdaMcpHttpRequestHandler
            )
            if failed_ports:
                logger.info(f"Port {port} was in use, auto-selected port {actual_port}")
            self._current_host = host
            self._current_port = actual_port
            self.mcp = MCP_SERVER
            set_download_base_url(f"http://{host}:{actual_port}")
            logger.info(f"Server started on http://{host}:{actual_port}")
            logger.info(f"  Config: http://{host}:{actual_port}/config.html")
        except OSError as e:
            if e.errno in (48, 98, 10048):
                logger.error(format_port_exhausted_message(host, port, list(range(port, port + 10))))
            else:
                logger.error(f"Error starting server: {e}")

    def _restart_server(self, new_host: str, new_port: int) -> None:
        """Restart the server with new configuration.

        This is called from a background thread, so we use execute_sync
        to run the actual restart on IDA's main thread.

        Args:
            new_host: New host address to bind
            new_port: New port number to bind
        """
        def do_restart() -> int:
            logger.info(f"Restarting server on {new_host}:{new_port}...")

            # Stop current server
            if self.mcp:
                try:
                    self.mcp.stop()
                except Exception as e:
                    logger.error(f"Error stopping server: {e}")
                self.mcp = None

            # Reload package and start new server
            unload_package("ida_mcp")

            if TYPE_CHECKING:
                from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback
                from .ida_mcp.port_utils import try_serve_with_port_retry, format_port_exhausted_message
                from .ida_mcp.rpc import set_download_base_url
            else:
                from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_server_restart_callback
                from ida_mcp.port_utils import try_serve_with_port_retry, format_port_exhausted_message
                from ida_mcp.rpc import set_download_base_url

            try:
                init_caches()
            except Exception as e:
                logger.warning(f"Cache init failed: {e}")

            # Set restart callback
            set_server_restart_callback(self._restart_server)

            try:
                actual_port, failed_ports = try_serve_with_port_retry(
                    MCP_SERVER, new_host, new_port, request_handler=IdaMcpHttpRequestHandler
                )
                if failed_ports:
                    logger.info(f"Port {new_port} was in use, auto-selected port {actual_port}")
                self._current_host = new_host
                self._current_port = actual_port
                self.mcp = MCP_SERVER
                set_download_base_url(f"http://{new_host}:{actual_port}")
                logger.info(f"Server restarted on http://{new_host}:{actual_port}")
                logger.info(f"  Config: http://{new_host}:{actual_port}/config.html")
            except OSError as e:
                if e.errno in (48, 98, 10048):
                    logger.error(format_port_exhausted_message(new_host, new_port, list(range(new_port, new_port + 10))))
                else:
                    logger.error(f"Error starting server: {e}")

            return 1  # Required for execute_sync callback

        # Execute on IDA's main thread
        idaapi.execute_sync(do_restart, idaapi.MFF_WRITE)

    def run(self, arg: int) -> None:
        """Toggle server on/off via menu.

        Args:
            arg: Plugin argument (unused)
        """
        if self.mcp:
            self.mcp.stop()
            self.mcp = None
            logger.info("Server stopped")
        else:
            self._start_server()

    def term(self) -> None:
        """Cleanup when plugin is unloaded."""
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY() -> MCP:
    """IDA plugin entry point.

    Returns:
        Plugin instance
    """
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
