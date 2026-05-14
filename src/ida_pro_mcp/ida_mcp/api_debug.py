"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

import os
from typing import Annotated, TypedDict

import idc
import ida_dbg
import ida_idd
import ida_idaapi
import ida_kernwin
import ida_name
import idaapi

from .compat import get_entry_qty, get_entry_ordinal, get_entry
from .rpc import tool, unsafe, ext
from .sync import idasync, keep_batch, get_pre_call_batch, IDAError
from .utils import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


class DebugControlResult(TypedDict, total=False):
    ip: str
    started: bool
    continued: bool
    running: bool
    suspended: bool
    exited: bool
    state: str
    error: str


# ============================================================================
# Constants and Helper Functions
# ============================================================================

GENERAL_PURPOSE_REGISTERS = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}


def _get_process_state_name() -> str:
    state = ida_dbg.get_process_state()
    if state == ida_dbg.DSTATE_NOTASK:
        return "not_running"
    elif state == ida_dbg.DSTATE_SUSP:
        return "suspended"
    elif state > 0:
        return "running"
    return "unknown"


def _get_debug_state_result() -> DebugControlResult:
    state = _get_process_state_name()
    result: DebugControlResult = {"state": state}
    if state == "running":
        result["running"] = True
    elif state == "suspended":
        result["suspended"] = True
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            result["ip"] = hex(ip)
    return result


def dbg_ensure_active() -> "ida_idd.debugger_t":
    dbg = ida_idd.get_dbg()
    if not dbg or not ida_dbg.is_debugger_on():
        raise IDAError(
            "Debugger not running. Stop and ask the user to start a debugger "
            "session (call dbg_start, or have them launch from IDA) before "
            "retrying. If dbg_start has already been attempted and failed, "
            "the user must first configure the debugger and target."
        )
    return dbg


def dbg_ensure_running() -> "ida_idd.debugger_t":
    """Legacy alias kept for callers that expect IP to be available."""
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running")
    if ida_dbg.get_ip_val() is None:
        raise IDAError("Debugger not running")
    return dbg


def _get_registers_for_thread(dbg: "ida_idd.debugger_t", tid: int) -> ThreadRegisters:
    """Helper to get registers for a specific thread."""
    regs = []
    regvals: ida_idd.regvals_t = ida_dbg.get_reg_vals(tid)
    for reg_index, rv in enumerate(regvals):
        rv: ida_idd.regval_t
        reg_info = dbg.regs(reg_index)

        try:
            reg_value = rv.pyval(reg_info.dtype)
        except ValueError:
            reg_value = ida_idaapi.BADADDR

        if isinstance(reg_value, int):
            reg_value = hex(reg_value)
        if isinstance(reg_value, bytes):
            reg_value = reg_value.hex(" ")
        else:
            reg_value = str(reg_value)
        regs.append(
            RegisterValue(
                name=reg_info.name,
                value=reg_value,
            )
        )
    return ThreadRegisters(
        thread_id=tid,
        registers=regs,
    )


def _get_registers_general_for_thread(
    dbg: "ida_idd.debugger_t", tid: int
) -> ThreadRegisters:
    """Helper to get general-purpose registers for a specific thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    general_registers = [
        reg
        for reg in all_registers["registers"]
        if reg["name"] in GENERAL_PURPOSE_REGISTERS
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=general_registers,
    )


def _get_registers_specific_for_thread(
    dbg: "ida_idd.debugger_t", tid: int, register_names: list[str]
) -> ThreadRegisters:
    """Helper to get specific registers for a given thread."""
    all_registers = _get_registers_for_thread(dbg, tid)
    specific_registers = [
        reg for reg in all_registers["registers"] if reg["name"] in register_names
    ]
    return ThreadRegisters(
        thread_id=tid,
        registers=specific_registers,
    )


def list_breakpoints():
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            breakpoints.append(
                Breakpoint(
                    addr=hex(bpt.ea),
                    enabled=bpt.flags & ida_dbg.BPT_ENABLED,
                    condition=str(bpt.condition) if bpt.condition else None,
                )
            )
    return breakpoints


# ============================================================================
# Debugger Control Operations
# ============================================================================


def _get_debug_start_result() -> DebugControlResult | None:
    if not ida_dbg.is_debugger_on():
        return None
    result = _get_debug_state_result()
    result["started"] = True
    return result


# Batch-mode lifecycle for dbg_start.
#
# start_process schedules work that runs on the IDA main thread *after* our
# execute_sync returns. That work can show modal dialogs (e.g. "matching
# executable names"), so we need batch mode to remain on across the
# execute_sync boundary, and we need to be sure to turn it back off once the
# debugger has actually come up (or failed to). _DbgStartBatchHook does both.
_DBG_START_BATCH_FALLBACK_MS = 30_000  # absolute ceiling on stuck-in-batch state
_DBG_START_WAIT_TIMEOUT_SEC = 10.0
_DBG_START_WAIT_POLL_MS = 100
_DBG_START_IP_GRACE_POLL_COUNT = 5


class _DbgStartBatchHook(ida_dbg.DBG_Hooks):
    """Restore batch mode as soon as the debugger has finished STARTUP.

    "Startup" ends at dbg_process_start / dbg_process_attach — by then any
    startup dialogs (e.g. "matching executable names") are done, but the
    user is still inside an active debug session and should see normal
    dialogs from here on. dbg_process_exit / dbg_process_detach also
    restore so we don't get stuck if the process dies before fully coming
    up.
    """

    def __init__(self, restore_batch: int):
        super().__init__()
        self._restore_batch = restore_batch
        self._done = False

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self._restore()

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        self._restore()

    def dbg_process_detach(self, pid, tid, ea):
        self._restore()

    def fallback_restore(self):
        """Called by the safety timer if no debugger event ever arrives."""
        self._restore()

    def _restore(self):
        if self._done:
            return
        self._done = True
        try:
            self.unhook()
        except Exception:
            pass
        idc.batch(self._restore_batch)


_dbg_start_batch_hook: _DbgStartBatchHook | None = None


def _arm_dbg_start_batch_hook(restore_batch: int) -> None:
    """Install the batch-restore hook before start_process is invoked."""
    global _dbg_start_batch_hook
    if _dbg_start_batch_hook is not None:
        _dbg_start_batch_hook.fallback_restore()
    hook = _DbgStartBatchHook(restore_batch)
    hook.hook()
    _dbg_start_batch_hook = hook

    def _fallback():
        if _dbg_start_batch_hook is hook and not hook._done:
            hook.fallback_restore()
        return -1  # don't repeat

    ida_kernwin.register_timer(_DBG_START_BATCH_FALLBACK_MS, _fallback)


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
def dbg_start() -> DebugControlResult:
    """Start debugger session for current target.

    Requires the user to have selected a debugger (Debugger -> Select debugger)
    and configured the target (executable path, arguments, attach process,
    remote host, etc.). If this call fails, do not retry repeatedly. Stop,
    explain to the user that debugging is not yet configured, and ask them
    to set up the debugger and dismiss any IDA dialogs (e.g. "matching
    executable names") before trying again.
    """
    if len(list_breakpoints()) == 0:
        for i in range(get_entry_qty()):
            ordinal = get_entry_ordinal(i)
            addr = get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                ida_dbg.add_bpt(addr, 0, idaapi.BPT_SOFT)

    # Arm a DBG_Hooks instance to switch IDA back to its pre-call batch
    # state once the debugger has actually started. Combined with
    # @keep_batch on this function, batch mode stays on across the
    # execute_sync boundary so dialogs the debugger plugin shows during
    # initialization (e.g. "matching executable names") are auto-handled.
    # The hook restores on dbg_process_start / _attach / _exit / _detach,
    # with a register_timer fallback so we never get stuck in batch mode.
    # Capture the pre-call batch (what the caller had set before the
    # sync wrapper bumped it to 1) so headless / batch-mode workflows
    # aren't silently flipped to interactive after dbg_start.
    pre_call_batch = get_pre_call_batch()
    if pre_call_batch is None:
        pre_call_batch = 0
    _arm_dbg_start_batch_hook(restore_batch=pre_call_batch)

    # start_process is documented as asynchronous; when invoked from the
    # IDA main thread inside execute_sync the return code is unreliable
    # (often -1 even on success, because the dbg_process_start event has
    # not yet been dispatched). Trust the actual debugger state instead,
    # and only consult the return code as a tiebreaker for the error
    # message when nothing ever comes up.
    start_result = idaapi.start_process("", "", "")

    started = _get_debug_start_result()
    if started is not None:
        if started.get("running") and "ip" not in started:
            for _ in range(_DBG_START_IP_GRACE_POLL_COUNT):
                ida_dbg.wait_for_next_event(
                    ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
                    _DBG_START_WAIT_POLL_MS,
                )
                waited = _get_debug_start_result()
                if waited is None:
                    continue
                started = waited
                if started.get("suspended") or "ip" in started:
                    break
        return started

    for _ in range(int(_DBG_START_WAIT_TIMEOUT_SEC * 1000 / _DBG_START_WAIT_POLL_MS)):
        ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
            _DBG_START_WAIT_POLL_MS,
        )
        started = _get_debug_start_result()
        if started is not None:
            return started

    if start_result == 0:
        raise IDAError(
            "Debugger start was cancelled. Stop and ask the user to configure "
            "the debugger (Debugger -> Select debugger, set the target path / "
            "arguments) and dismiss any IDA dialogs before retrying."
        )
    raise IDAError(
        "Failed to start debugger. Stop and ask the user to verify that a "
        "debugger is selected (Debugger -> Select debugger), the target is "
        "configured (executable path / arguments / remote host), and any "
        "pending IDA dialogs (e.g. \"matching executable names\") have been "
        "dismissed before retrying."
    )


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_exit():
    """Exit debugger"""
    dbg_ensure_running()
    if idaapi.exit_process():
        return
    raise IDAError("Failed to exit debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_continue() -> str:
    """Continue debugger"""
    dbg_ensure_running()
    if idaapi.continue_process():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to continue debugger")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_run_to(
    addr: Annotated[str, "Address"],
):
    """Run to address"""
    dbg_ensure_running()
    ea = parse_address(addr)
    if idaapi.run_to(ea):
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError(f"Failed to run to address {hex(ea)}")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_into():
    """Step into"""
    dbg_ensure_running()
    if idaapi.step_into():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step into")


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_over():
    """Step over"""
    dbg_ensure_running()
    if idaapi.step_over():
        ip = ida_dbg.get_ip_val()
        if ip is not None:
            return hex(ip)
    raise IDAError("Failed to step over")


# ============================================================================
# Breakpoint Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_bps():
    """List breakpoints"""
    return list_breakpoints()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[list[str] | str, "Address(es) to add breakpoints at"],
) -> list[dict]:
    """Add breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
                results.append({"addr": addr, "ok": True})
            else:
                breakpoints = list_breakpoints()
                for bpt in breakpoints:
                    if bpt["addr"] == hex(ea):
                        results.append({"addr": addr, "ok": True})
                        break
                else:
                    results.append({"addr": addr, "error": "Failed to set breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_delete_bp(
    addrs: Annotated[list[str] | str, "Address(es) to delete breakpoints from"],
) -> list[dict]:
    """Delete breakpoints"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            if idaapi.del_bpt(ea):
                results.append({"addr": addr, "ok": True})
            else:
                results.append({"addr": addr, "error": "Failed to delete breakpoint"})
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_toggle_bp(items: list[BreakpointOp] | BreakpointOp) -> list[dict]:
    """Enable/disable breakpoints"""

    items = normalize_dict_list(items)

    results = []
    for item in items:
        addr = item.get("addr", "")
        enable = item.get("enabled", True)

        try:
            ea = parse_address(addr)
            if idaapi.enable_bpt(ea, enable):
                results.append({"addr": addr, "ok": True})
            else:
                results.append(
                    {
                        "addr": addr,
                        "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                    }
                )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


# ============================================================================
# Register Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_all() -> list[ThreadRegisters]:
    """Get all registers"""
    result: list[ThreadRegisters] = []
    dbg = dbg_ensure_running()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        result.append(_get_registers_for_thread(dbg, tid))
    return result


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get registers for"],
) -> list[dict]:
    """Get thread registers"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs() -> ThreadRegisters:
    """Get current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_for_thread(dbg, tid)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get GP registers for"],
) -> list[dict]:
    """Get GP registers for threads"""
    if isinstance(tids, int):
        tids = [tids]

    dbg = dbg_ensure_running()
    available_tids = [ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())]
    results = []

    for tid in tids:
        try:
            if tid not in available_tids:
                results.append(
                    {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                )
                continue
            regs = _get_registers_general_for_thread(dbg, tid)
            results.append({"tid": tid, "regs": regs})
        except Exception as e:
            results.append({"tid": tid, "regs": None, "error": str(e)})

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs() -> ThreadRegisters:
    """Get current thread GP registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    return _get_registers_general_for_thread(dbg, tid)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named_remote(
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific thread registers"""
    dbg = dbg_ensure_running()
    if thread_id not in [
        ida_dbg.getn_thread(i) for i in range(ida_dbg.get_thread_qty())
    ]:
        raise IDAError(f"Thread with ID {thread_id} not found")
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, thread_id, names)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named(
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific current thread registers"""
    dbg = dbg_ensure_running()
    tid = ida_dbg.get_current_thread()
    names = [name.strip() for name in register_names.split(",")]
    return _get_registers_specific_for_thread(dbg, tid, names)


# ============================================================================
# Call Stack Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_stacktrace() -> list[dict[str, str]]:
    """Get call stack"""
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "addr": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)

            callstack.append(frame_info)

    except Exception:
        pass
    return callstack


# ============================================================================
# Debugger Memory Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            size = region["size"]

            data = idaapi.dbg_read_memory(addr, size)
            if data:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data),
                        "data": data.hex(),
                    }
                )
            else:
                results.append(
                    {
                        "addr": region["addr"],
                        "size": 0,
                        "data": None,
                        "error": "Failed to read memory",
                    }
                )

        except Exception as e:
            results.append(
                {"addr": region.get("addr"), "size": 0, "data": None, "error": str(e)}
            )

    return results


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_write(regions: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Write debug memory"""

    regions = normalize_dict_list(regions)
    dbg_ensure_running()
    results = []

    for region in regions:
        try:
            addr = parse_address(region["addr"])
            data = bytes.fromhex(region["data"])

            success = idaapi.dbg_write_memory(addr, data)
            results.append(
                {
                    "addr": region["addr"],
                    "size": len(data) if success else 0,
                    "ok": success,
                    "error": None if success else "Write failed",
                }
            )

        except Exception as e:
            results.append({"addr": region.get("addr"), "size": 0, "error": str(e)})

    return results
