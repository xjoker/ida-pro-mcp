"""IDA MCP Server Manager

Manages multiple MCP server instances with support for:
- Starting/stopping individual servers
- Status monitoring
- Configuration-based server management
"""

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable, TYPE_CHECKING

from .config import ServerInstanceConfig, McpConfig, get_config
from .auth import AuthMiddleware
from .port_utils import try_serve_with_port_retry

if TYPE_CHECKING:
    from .zeromcp.mcp import McpServer

logger = logging.getLogger(__name__)


@dataclass
class ServerInstance:
    """Represents a running server instance"""

    config: ServerInstanceConfig
    server: Optional["McpServer"] = None
    auth: AuthMiddleware = field(default_factory=AuthMiddleware)
    error: Optional[str] = None
    _actual_port: Optional[int] = field(default=None, repr=False)

    @property
    def actual_port(self) -> int:
        """实际绑定的端口（可能因端口冲突自动递增）。"""
        if self._actual_port is not None:
            return self._actual_port
        return self.config.port

    @property
    def is_running(self) -> bool:
        return self.server is not None and self.server._running

    @property
    def status(self) -> str:
        if self.error:
            return f"error: {self.error}"
        if self.is_running:
            return "running"
        return "stopped"

    def to_status_dict(self) -> dict:
        result = {
            "instance_id": self.config.instance_id,
            "host": self.config.host,
            "port": self.config.port,
            "status": self.status,
            "auth_enabled": self.config.auth_enabled,
            "address": self.config.address,
        }
        if self._actual_port is not None and self._actual_port != self.config.port:
            result["actual_port"] = self._actual_port
            result["address"] = f"{self.config.host}:{self._actual_port}"
        return result


class ServerManager:
    """Manages multiple MCP server instances.

    Thread-safe manager for starting, stopping, and monitoring
    multiple MCP server instances.
    """

    def __init__(self, create_server_func: Optional[Callable[[], "McpServer"]] = None):
        """Initialize the server manager.

        Args:
            create_server_func: Factory function to create new McpServer instances.
                               If None, uses default McpServer constructor.
        """
        self._instances: dict[str, ServerInstance] = {}
        self._lock = threading.RLock()
        self._create_server = create_server_func
        self._request_handler_class: Optional[type] = None

    def set_server_factory(self, factory: Callable[[], "McpServer"]) -> None:
        """Set the server factory function."""
        self._create_server = factory

    def set_request_handler(self, handler_class: type) -> None:
        """Set the request handler class for new servers."""
        self._request_handler_class = handler_class

    def _create_server_instance(self, config: ServerInstanceConfig) -> ServerInstance:
        """Create a new server instance from configuration."""
        instance = ServerInstance(
            config=config,
            auth=AuthMiddleware(config.api_key, config.auth_enabled),
        )
        return instance

    def add_server(self, config: ServerInstanceConfig) -> str:
        """Add a new server configuration.

        Args:
            config: Server instance configuration

        Returns:
            The instance ID

        Raises:
            ValueError: If instance ID already exists
        """
        with self._lock:
            if config.instance_id in self._instances:
                raise ValueError(f"Server instance '{config.instance_id}' already exists")

            instance = self._create_server_instance(config)
            self._instances[config.instance_id] = instance
            return config.instance_id

    def remove_server(self, instance_id: str) -> bool:
        """Remove a server instance (stops it first if running).

        Args:
            instance_id: The instance ID to remove

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if instance_id not in self._instances:
                return False

            # Stop if running
            self.stop_server(instance_id)

            del self._instances[instance_id]
            return True

    def start_server(self, instance_id: str) -> bool:
        """Start a server instance.

        Args:
            instance_id: The instance ID to start

        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            instance = self._instances.get(instance_id)
            if not instance:
                logger.error(f"Server instance '{instance_id}' not found")
                return False

            if instance.is_running:
                logger.info(f"Server '{instance_id}' is already running")
                return True

            if not self._create_server:
                logger.error("No server factory configured")
                return False

            try:
                # Create new server
                server = self._create_server()

                # Configure authentication
                if hasattr(server, '_auth'):
                    server._auth = instance.auth

                # Start the server with port retry
                kwargs = {}
                if self._request_handler_class:
                    kwargs["request_handler"] = self._request_handler_class

                actual_port, failed_ports = try_serve_with_port_retry(
                    server,
                    instance.config.host,
                    instance.config.port,
                    **kwargs,
                )

                instance.server = server
                instance.error = None
                instance._actual_port = actual_port if actual_port != instance.config.port else None

                if failed_ports:
                    logger.info(
                        f"Server '{instance_id}': port {instance.config.port} in use, "
                        f"auto-selected port {actual_port}"
                    )
                logger.info(
                    f"Started server '{instance_id}' on {instance.config.host}:{actual_port}"
                )
                return True

            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    instance.error = (
                        f"All ports {instance.config.port}-{instance.config.port + 9} are in use"
                    )
                else:
                    instance.error = str(e)
                logger.error(f"Failed to start server '{instance_id}': {instance.error}")
                return False
            except Exception as e:
                instance.error = str(e)
                logger.error(f"Failed to start server '{instance_id}': {e}")
                return False

    def stop_server(self, instance_id: str) -> bool:
        """Stop a server instance.

        Args:
            instance_id: The instance ID to stop

        Returns:
            True if stopped, False if not found or not running
        """
        with self._lock:
            instance = self._instances.get(instance_id)
            if not instance:
                return False

            if not instance.is_running:
                return True

            try:
                instance.server.stop()
                instance.server = None
                instance.error = None
                logger.info(f"Stopped server '{instance_id}'")
                return True
            except Exception as e:
                instance.error = str(e)
                logger.error(f"Error stopping server '{instance_id}': {e}")
                return False

    def restart_server(self, instance_id: str) -> bool:
        """Restart a server instance.

        Args:
            instance_id: The instance ID to restart

        Returns:
            True if restarted successfully
        """
        self.stop_server(instance_id)
        return self.start_server(instance_id)

    def get_status(self) -> dict[str, dict]:
        """Get status of all server instances.

        Returns:
            Dictionary mapping instance IDs to their status
        """
        with self._lock:
            return {
                instance_id: instance.to_status_dict()
                for instance_id, instance in self._instances.items()
            }

    def get_instance(self, instance_id: str) -> Optional[ServerInstance]:
        """Get a server instance by ID.

        Args:
            instance_id: The instance ID

        Returns:
            The server instance or None
        """
        with self._lock:
            return self._instances.get(instance_id)

    def load_from_config(self, config: Optional[McpConfig] = None) -> None:
        """Load server instances from configuration.

        Args:
            config: Configuration to load from (uses global config if None)
        """
        if config is None:
            config = get_config()

        with self._lock:
            # Stop and remove existing instances
            for instance_id in list(self._instances.keys()):
                self.remove_server(instance_id)

            # Add instances from config
            for server_config in config.servers:
                if server_config.enabled:
                    self.add_server(server_config)

    def start_auto_servers(self) -> int:
        """Start all servers marked with auto_start.

        Returns:
            Number of servers started
        """
        count = 0
        with self._lock:
            for instance_id, instance in self._instances.items():
                if instance.config.auto_start and not instance.is_running:
                    if self.start_server(instance_id):
                        count += 1
        return count

    def stop_all(self) -> None:
        """Stop all running server instances."""
        with self._lock:
            for instance_id in list(self._instances.keys()):
                self.stop_server(instance_id)

    def __len__(self) -> int:
        return len(self._instances)

    def __contains__(self, instance_id: str) -> bool:
        return instance_id in self._instances


# Global server manager instance
_manager: Optional[ServerManager] = None


def get_server_manager() -> ServerManager:
    """Get the global server manager instance."""
    global _manager
    if _manager is None:
        _manager = ServerManager()
    return _manager


__all__ = [
    "ServerInstance",
    "ServerManager",
    "get_server_manager",
]
