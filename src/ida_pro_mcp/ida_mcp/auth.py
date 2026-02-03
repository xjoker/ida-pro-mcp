"""IDA MCP API Key Authentication

Provides authentication middleware for MCP server with support for:
- Bearer token authentication (Authorization: Bearer <key>)
- X-API-Key header authentication
- Timing-attack resistant comparison
"""

import hmac
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Paths that don't require authentication
AUTH_EXEMPT_PATHS = frozenset({
    "/health",
    "/config.html",
})


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
            enabled: Whether authentication is enabled
        """
        self._api_key = api_key
        self._enabled = enabled and api_key is not None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def update_key(self, api_key: Optional[str], enabled: bool = True) -> None:
        """Update the API key configuration.

        Args:
            api_key: New API key
            enabled: Whether to enable authentication
        """
        self._api_key = api_key
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
    "AuthMiddleware",
    "create_auth_check",
    "AUTH_EXEMPT_PATHS",
]
