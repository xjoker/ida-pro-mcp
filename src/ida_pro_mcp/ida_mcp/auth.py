"""IDA MCP API Key Authentication

Provides authentication middleware for MCP server with support for:
- Bearer token authentication (Authorization: Bearer <key>)
- X-API-Key header authentication
- Environment variable expansion (${ENV_VAR} syntax)
- Timing-attack resistant comparison
"""

import hmac
import logging
import os
import re
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Paths that don't require authentication
AUTH_EXEMPT_PATHS = frozenset({
    "/health",
    "/config.html",
})

# Pattern to match ${ENV_VAR} syntax
_ENV_VAR_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def resolve_env_var(value: Optional[str]) -> Optional[str]:
    """Resolve environment variable reference in ${VAR} format.

    Args:
        value: The value to resolve, may be a literal or ${ENV_VAR} reference

    Returns:
        The resolved value (from environment) or the original value if not a reference
    """
    if not value:
        return value

    match = _ENV_VAR_PATTERN.match(value.strip())
    if match:
        env_name = match.group(1)
        env_value = os.environ.get(env_name)
        if env_value:
            return env_value
        else:
            logger.warning(f"Environment variable '{env_name}' not found, using literal value")
            return None  # Env var not set, disable auth
    return value


def check_api_key(provided_key: Optional[str], expected_key: Optional[str]) -> bool:
    """Compare API keys using constant-time comparison to prevent timing attacks.

    Args:
        provided_key: The key provided by the client
        expected_key: The expected API key from configuration

    Returns:
        True if keys match, False otherwise
    """
    if not expected_key:
        # No key configured = authentication disabled
        return True

    if not provided_key:
        return False

    # Use hmac.compare_digest for constant-time comparison
    return hmac.compare_digest(provided_key.encode("utf-8"), expected_key.encode("utf-8"))


def extract_api_key_from_headers(headers: dict) -> Optional[str]:
    """Extract API key from request headers.

    Supports two formats:
    - Authorization: Bearer <key>
    - X-API-Key: <key>

    Args:
        headers: Dictionary of HTTP headers (case-insensitive keys)

    Returns:
        The extracted API key or None
    """
    # Try Authorization header first (Bearer token)
    auth_header = headers.get("Authorization") or headers.get("authorization")
    if auth_header:
        parts = auth_header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    # Try X-API-Key header
    api_key = headers.get("X-API-Key") or headers.get("x-api-key")
    if api_key:
        return api_key.strip()

    return None


def is_path_exempt(path: str) -> bool:
    """Check if a path is exempt from authentication.

    Args:
        path: The request path (e.g., "/health", "/mcp")

    Returns:
        True if the path doesn't require authentication
    """
    # Remove query string if present
    if "?" in path:
        path = path.split("?", 1)[0]

    return path in AUTH_EXEMPT_PATHS


class AuthMiddleware:
    """Authentication middleware for HTTP request handlers.

    Usage:
        auth = AuthMiddleware(api_key="secret")

        # In request handler:
        if not auth.authenticate(request):
            return send_401_response()
    """

    def __init__(self, api_key: Optional[str] = None, enabled: bool = False):
        """Initialize authentication middleware.

        Args:
            api_key: The expected API key (None = no authentication)
                     Supports ${ENV_VAR} syntax to reference environment variables
            enabled: Whether authentication is enabled
        """
        self._api_key_raw = api_key  # Store original value (may be ${ENV_VAR})
        self._enabled = enabled and api_key is not None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def _api_key(self) -> Optional[str]:
        """Get the resolved API key (expands ${ENV_VAR} references)."""
        return resolve_env_var(self._api_key_raw)

    def update_key(self, api_key: Optional[str], enabled: bool = True) -> None:
        """Update the API key configuration.

        Args:
            api_key: New API key (supports ${ENV_VAR} syntax)
            enabled: Whether to enable authentication
        """
        self._api_key_raw = api_key
        self._enabled = enabled and api_key is not None

    def authenticate(self, path: str, headers: dict) -> bool:
        """Authenticate a request.

        Args:
            path: Request path
            headers: Request headers dictionary

        Returns:
            True if authenticated, False if authentication failed
        """
        # Skip if authentication is disabled
        if not self._enabled:
            return True

        # Check if path is exempt
        if is_path_exempt(path):
            return True

        # Extract and verify API key
        provided_key = extract_api_key_from_headers(headers)
        return check_api_key(provided_key, self._api_key)


def create_auth_check(api_key: Optional[str], enabled: bool = False) -> Callable[[str, dict], bool]:
    """Create a simple authentication check function.

    Args:
        api_key: The expected API key
        enabled: Whether authentication is enabled

    Returns:
        A function that takes (path, headers) and returns True if authenticated
    """
    middleware = AuthMiddleware(api_key, enabled)
    return middleware.authenticate


__all__ = [
    "check_api_key",
    "extract_api_key_from_headers",
    "is_path_exempt",
    "resolve_env_var",
    "AuthMiddleware",
    "create_auth_check",
    "AUTH_EXEMPT_PATHS",
]
