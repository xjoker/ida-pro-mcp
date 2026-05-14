"""
HTTP forward logic for the IDA Pro MCP Coordinator.

forward_request() sends a JSON-RPC request body to a remote WorkerEndpoint
using stdlib http.client and returns the parsed JSON response dict, or a
well-formed JSON-RPC error dict if anything goes wrong.
"""

from __future__ import annotations

import http.client
import json
import traceback
from typing import Any

from .router import WorkerEndpoint

# Default request timeout in seconds — mirrors server.py's connection pool.
DEFAULT_TIMEOUT: float = 180.0

# Maximum response body size (10 MB) to match zeromcp's post_body_limit.
MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024


def forward_request(
    endpoint: WorkerEndpoint,
    request_body: bytes,
    extra_headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Forward a raw JSON-RPC request body to *endpoint* and return the response.

    On network or protocol error, returns a JSON-RPC error object with
    code -32000 so the coordinator can pass it straight back to the client.

    Args:
        endpoint: Target worker.
        request_body: UTF-8 encoded JSON-RPC request bytes.
        extra_headers: Optional extra HTTP headers to include (e.g. forwarded
            Authorization or Mcp-Session-Id headers).
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed JSON dict (either the worker's response or a synthetic error).
    """
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Content-Length": str(len(request_body)),
    }
    if extra_headers:
        headers.update(extra_headers)

    # Extract request id for error responses (best-effort; may be None).
    req_id: Any = None
    try:
        parsed = json.loads(request_body)
        req_id = parsed.get("id") if isinstance(parsed, dict) else None
    except Exception:
        pass

    try:
        conn = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)
        try:
            conn.request("POST", "/mcp", request_body, headers)
            response = conn.getresponse()

            raw = response.read(MAX_RESPONSE_BYTES)
            if len(raw) == MAX_RESPONSE_BYTES:
                # Body exceeded our safety limit — treat as error.
                return _make_error(
                    req_id,
                    -32000,
                    f"Response from worker {endpoint} exceeded {MAX_RESPONSE_BYTES} bytes",
                )

            return json.loads(raw.decode("utf-8"))
        finally:
            conn.close()

    except json.JSONDecodeError as exc:
        return _make_error(
            req_id,
            -32700,
            f"Worker {endpoint} returned invalid JSON: {exc}",
        )
    except (http.client.HTTPException, OSError, TimeoutError) as exc:
        detail = traceback.format_exc()
        return _make_error(
            req_id,
            -32000,
            f"Failed to connect to worker {endpoint}: {exc}\n{detail}",
            data=str(exc),
        )
    except Exception as exc:
        detail = traceback.format_exc()
        return _make_error(
            req_id,
            -32000,
            f"Unexpected error forwarding to worker {endpoint}: {exc}\n{detail}",
            data=str(exc),
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_error(
    req_id: Any,
    code: int,
    message: str,
    data: str | None = None,
) -> dict[str, Any]:
    """Build a minimal JSON-RPC 2.0 error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {
        "jsonrpc": "2.0",
        "error": error,
        "id": req_id,
    }
