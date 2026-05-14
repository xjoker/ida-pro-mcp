"""Async task queue for long-running IDA operations.

Instead of blocking the HTTP connection, submit heavy tools as background tasks
and poll for completion every few seconds.

Typical workflow:
  1. task_submit("decompile", {"addr": "0x401000"}) → {"task_id": "a1b2c3d4"}
  2. task_poll("a1b2c3d4") every 2-3 s  → {"status": "running"|"done"|"error"}
  3. When status == "done", result is in the response

Backend selection (env vars):
  IDA_MCP_TASKS_BACKEND=memory   (default) – in-process InMemoryTaskBackend
  IDA_MCP_TASKS_BACKEND=redis    – RedisTaskBackend; reads URL from
                                   IDA_MCP_REGISTRY_REDIS_URL
"""
import os
import threading
import time
import uuid
from typing import Annotated

from .rpc import tool, MCP_SERVER
from .task_backend import InMemoryTaskBackend, RedisTaskBackend, TaskBackend

# ── Backend initialisation ────────────────────────────────────────────────────

_TASK_TTL_SEC = 300  # expire done/error tasks after 5 minutes


def _init_backend() -> TaskBackend:
    backend_name = os.environ.get("IDA_MCP_TASKS_BACKEND", "memory").lower().strip()
    if backend_name == "redis":
        redis_url = os.environ.get(
            "IDA_MCP_REGISTRY_REDIS_URL", "redis://localhost:6379/0"
        )
        return RedisTaskBackend(redis_url)
    return InMemoryTaskBackend()


_backend: TaskBackend = _init_backend()

# ── Helpers ───────────────────────────────────────────────────────────────────


def _cleanup_expired() -> None:
    _backend.delete_expired(_TASK_TTL_SEC)


# ── Tools ─────────────────────────────────────────────────────────────────────

@tool
def task_submit(
    tool_name: Annotated[str, "Tool to run in the background (e.g. 'decompile', 'analyze_funcs')"],
    arguments: Annotated[dict | None, "Tool arguments as a dict (same as you would pass directly)"] = None,
) -> dict:
    """Submit a tool call as a background task and return a task_id immediately.

    Use this for heavy operations (decompile, analyze_funcs, find_paths, callgraph, …)
    that may block the IDA main thread for a long time. After submitting, poll with
    task_poll(task_id) every 2-3 seconds until status is 'done' or 'error'."""
    if tool_name.startswith("task_"):
        return {"error": "Cannot submit task management tools as async tasks"}
    if tool_name not in MCP_SERVER.tools.methods:
        return {"error": f"Unknown tool: {tool_name!r}"}

    # Capture request-scoped thread-locals so the worker re-evaluates gates with
    # the *submitter's* context, not the default empty state it would see in a
    # fresh thread (otherwise e.g. ?ext=dbg submitted tasks would be rejected).
    caller_extensions: set[str] = set(
        getattr(MCP_SERVER._enabled_extensions, "data", set())
    )
    caller_session_id: str | None = getattr(
        MCP_SERVER._transport_session_id, "data", None
    )

    # Collision-safe ID; retry on the astronomically unlikely duplicate.
    # We use a temporary lock only for the ID uniqueness check against the backend.
    _id_lock = threading.Lock()
    with _id_lock:
        while True:
            task_id = uuid.uuid4().hex
            if _backend.get_task(task_id) is None:
                break
        _backend.create_task(
            task_id,
            {
                "task_id": task_id,
                "tool": tool_name,
                "status": "pending",
                "result": None,
                "error": None,
                "created_at": time.monotonic(),
                "completed_at": None,
            },
        )

    def _worker() -> None:
        # Replay captured request context on the worker thread so unsafe/extension
        # gates and per-session routing behave as they would for a synchronous call.
        MCP_SERVER._enabled_extensions.data = caller_extensions
        if caller_session_id is not None:
            MCP_SERVER._transport_session_id.data = caller_session_id

        _backend.update_state(task_id, "running")
        try:
            # Route through registry.dispatch -> tools/call so unsafe/extension gates
            # and the large-output truncation/cache in rpc.py apply identically to
            # synchronous calls.
            envelope = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments or {}},
                "id": task_id,
            }
            resp = MCP_SERVER.registry.dispatch(envelope)
            if resp and "error" in resp:
                _backend.update_state(
                    task_id,
                    "error",
                    error=resp["error"].get("message", "unknown error"),
                    completed_at=time.monotonic(),
                )
                return

            call_result = resp.get("result") if resp else None
            if isinstance(call_result, dict) and call_result.get("isError"):
                # tools/call surfaces tool-level errors inside content[].text.
                msg = "tool error"
                content = call_result.get("content") or []
                if content and isinstance(content[0], dict):
                    msg = content[0].get("text", msg)
                _backend.update_state(
                    task_id, "error", error=msg, completed_at=time.monotonic()
                )
                return

            # Keep the MCP-shaped payload so callers get structuredContent + content.
            _backend.update_state(
                task_id, "done", result=call_result, completed_at=time.monotonic()
            )
        except Exception as exc:
            _backend.update_state(
                task_id, "error", error=str(exc), completed_at=time.monotonic()
            )
        finally:
            _cleanup_expired()

    threading.Thread(target=_worker, daemon=True, name=f"mcp-task-{task_id[:8]}").start()

    return {
        "task_id": task_id,
        "status": "pending",
        "_hint": f"Poll with task_poll(task_id='{task_id}') every 2-3 seconds",
    }


@tool
def task_poll(
    task_id: Annotated[str, "Task ID returned by task_submit"],
) -> dict:
    """Poll a background task's status and retrieve the result when done.

    Call every 2-3 seconds. When status is 'done', the result field contains
    the same output that the tool would have returned synchronously."""
    _cleanup_expired()
    task = _backend.get_task(task_id)

    if task is None:
        return {"error": f"Task '{task_id}' not found (expired after 5 min or invalid ID)"}

    elapsed = round(time.monotonic() - task["created_at"], 1)
    resp: dict = {
        "task_id": task_id,
        "tool": task["tool"],
        "status": task["status"],
        "elapsed_s": elapsed,
    }

    match task["status"]:
        case "done":
            resp["result"] = task["result"]
        case "error":
            resp["error"] = task["error"]
        case _:
            resp["_hint"] = "Still running — poll again in 2-3 seconds"

    return resp


@tool
def task_list() -> list:
    """List all active or recently completed background tasks."""
    _cleanup_expired()
    return [
        {
            "task_id": t["task_id"],
            "tool": t["tool"],
            "status": t["status"],
            "elapsed_s": round(time.monotonic() - t["created_at"], 1),
        }
        for t in _backend.list_tasks()
    ]
