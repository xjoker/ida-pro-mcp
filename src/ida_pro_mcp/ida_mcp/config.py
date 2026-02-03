"""IDA MCP Configuration System

Provides configuration management for MCP server instances with support for:
- Multiple server instances (different hosts/ports)
- API Key authentication
- Persistent configuration storage
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration directory
CONFIG_DIR = Path.home() / ".ida_mcp"
CONFIG_FILE = CONFIG_DIR / "config.toml"


@dataclass
class ServerInstanceConfig:
    """Configuration for a single MCP server instance"""

    instance_id: str
    host: str = "127.0.0.1"
    port: int = 13337
    enabled: bool = True
    auth_enabled: bool = False
    api_key: Optional[str] = None
    auto_start: bool = False

    def __post_init__(self):
        # Resolve environment variable references in api_key
        if self.api_key and self.api_key.startswith("${") and self.api_key.endswith("}"):
            env_var = self.api_key[2:-1]
            self.api_key = os.environ.get(env_var)

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "host": self.host,
            "port": self.port,
            "enabled": self.enabled,
            "auth_enabled": self.auth_enabled,
            "api_key": self.api_key,
            "auto_start": self.auto_start,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ServerInstanceConfig":
        return cls(
            instance_id=data.get("instance_id", "default"),
            host=data.get("host", "127.0.0.1"),
            port=data.get("port", 13337),
            enabled=data.get("enabled", True),
            auth_enabled=data.get("auth_enabled", False),
            api_key=data.get("api_key"),
            auto_start=data.get("auto_start", False),
        )


@dataclass
class McpConfig:
    """Main configuration container"""

    version: int = 1
    servers: list[ServerInstanceConfig] = field(default_factory=list)
    tool_timeout_sec: float = 15.0
    debug: bool = False

    def __post_init__(self):
        # Ensure at least one default server exists
        if not self.servers:
            self.servers.append(ServerInstanceConfig(instance_id="local"))

    def get_server(self, instance_id: str) -> Optional[ServerInstanceConfig]:
        for server in self.servers:
            if server.instance_id == instance_id:
                return server
        return None

    def add_server(self, config: ServerInstanceConfig) -> bool:
        if self.get_server(config.instance_id):
            return False
        self.servers.append(config)
        return True

    def remove_server(self, instance_id: str) -> bool:
        for i, server in enumerate(self.servers):
            if server.instance_id == instance_id:
                self.servers.pop(i)
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "tool_timeout_sec": self.tool_timeout_sec,
            "debug": self.debug,
            "servers": [s.to_dict() for s in self.servers],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "McpConfig":
        servers = [
            ServerInstanceConfig.from_dict(s) for s in data.get("servers", [])
        ]
        return cls(
            version=data.get("version", 1),
            servers=servers,
            tool_timeout_sec=data.get("tool_timeout_sec", 15.0),
            debug=data.get("debug", False),
        )


def _ensure_config_dir() -> None:
    """Create configuration directory if it doesn't exist"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> McpConfig:
    """Load configuration from TOML file"""
    if not CONFIG_FILE.exists():
        return McpConfig()

    try:
        # Python 3.11+ has tomllib in stdlib
        import tomllib

        with open(CONFIG_FILE, "rb") as f:
            data = tomllib.load(f)
        return McpConfig.from_dict(data)
    except ImportError:
        # Fallback: try toml package
        try:
            import toml

            data = toml.load(CONFIG_FILE)
            return McpConfig.from_dict(data)
        except ImportError:
            logger.warning("No TOML parser available, using defaults")
            return McpConfig()
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return McpConfig()


def save_config(config: McpConfig) -> bool:
    """Save configuration to TOML file"""
    _ensure_config_dir()

    try:
        # Try toml package for writing (tomllib is read-only)
        try:
            import toml

            with open(CONFIG_FILE, "w") as f:
                toml.dump(config.to_dict(), f)
            return True
        except ImportError:
            # Manual TOML generation for simple config
            return _write_toml_manual(config)
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return False


def _write_toml_manual(config: McpConfig) -> bool:
    """Write config as TOML without external dependencies"""
    lines = [
        f"version = {config.version}",
        f"tool_timeout_sec = {config.tool_timeout_sec}",
        f"debug = {'true' if config.debug else 'false'}",
        "",
    ]

    for server in config.servers:
        lines.append("[[servers]]")
        lines.append(f'instance_id = "{server.instance_id}"')
        lines.append(f'host = "{server.host}"')
        lines.append(f"port = {server.port}")
        lines.append(f"enabled = {'true' if server.enabled else 'false'}")
        lines.append(f"auth_enabled = {'true' if server.auth_enabled else 'false'}")
        if server.api_key:
            lines.append(f'api_key = "{server.api_key}"')
        lines.append(f"auto_start = {'true' if server.auto_start else 'false'}")
        lines.append("")

    with open(CONFIG_FILE, "w") as f:
        f.write("\n".join(lines))
    return True


# Global config instance (lazy loaded)
_config: Optional[McpConfig] = None


def get_config() -> McpConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> McpConfig:
    """Force reload configuration from disk"""
    global _config
    _config = load_config()
    return _config


__all__ = [
    "ServerInstanceConfig",
    "McpConfig",
    "load_config",
    "save_config",
    "get_config",
    "reload_config",
    "CONFIG_DIR",
    "CONFIG_FILE",
]
