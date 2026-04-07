"""Composite analysis tools — aggregate multiple data sources in a single call.

Reduces LLM round-trips by returning decompilation, assembly, xrefs, strings,
constants, callers, callees, and CFG summary in one response.
"""

from typing import Annotated

import idaapi
import idautils

from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import (
    parse_address,
    normalize_list_input,
    require_func_t,
    get_prototype,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    extract_function_strings,
    extract_function_constants,
)


# ============================================================================
# Composite Function Analysis
# ============================================================================

_DECOMPILE_LINE_CAP = 200
_STRING_CAP = 10
_CONSTANT_CAP = 10


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include disassembly (default: false)"] = False,
    chunk: Annotated[int, "Chunk index for paginated results (default: 0)"] = 0,
) -> dict:
    """Comprehensive single-function analysis: decompile + asm + xrefs + strings + constants + callers + callees + CFG"""
    ea = parse_address(addr)
    f = require_func_t(ea)
    start = f.start_ea

    result: dict = {
        "addr": hex(start),
        "name": idaapi.get_func_name(start) or "",
        "size": f.end_ea - start,
    }

    # Prototype
    try:
        result["prototype"] = get_prototype(f)
    except Exception:
        result["prototype"] = None

    # Decompilation with line capping
    try:
        code = decompile_function_safe(start)
        if code:
            lines = code.split("\n")
            if len(lines) > _DECOMPILE_LINE_CAP:
                result["decompile"] = "\n".join(lines[:_DECOMPILE_LINE_CAP])
                result["decompile_truncated"] = True
                result["decompile_total_lines"] = len(lines)
            else:
                result["decompile"] = code
        else:
            result["decompile"] = None
    except Exception as e:
        result["decompile_error"] = str(e)

    # Assembly (optional, off by default)
    if include_asm:
        try:
            asm_lines = get_assembly_lines(start)
            lines = asm_lines.split("\n")
            if len(lines) > 300:
                result["asm"] = "\n".join(lines[:300])
                result["asm_truncated"] = True
            else:
                result["asm"] = asm_lines
        except Exception:
            pass

    # Xrefs
    try:
        xref_data = get_all_xrefs(start)
        result["xrefs_to"] = xref_data.get("to", [])[:50]
        result["xrefs_from"] = xref_data.get("from", [])[:50]
    except Exception:
        pass

    # Strings (compact: values only, top N)
    try:
        strs = extract_function_strings(start)
        seen = set()
        unique = []
        for s in strs:
            v = s.get("string", "")
            if v and v not in seen:
                seen.add(v)
                unique.append(v)
        result["strings"] = unique[:_STRING_CAP]
    except Exception:
        pass

    # Constants (filter boring ones: 0, 1, -1, 0xFF, 0xFFFF, etc.)
    try:
        consts = extract_function_constants(start)
        boring = {0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
        interesting = [c for c in consts if c.get("value", 0) not in boring]
        interesting.sort(key=lambda c: abs(c.get("value", 0)), reverse=True)
        result["constants"] = [c.get("value") for c in interesting[:_CONSTANT_CAP]]
    except Exception:
        pass

    # Callers
    try:
        callers = list(idautils.CodeRefsTo(start, 0))
        result["callers"] = [
            {"addr": hex(c), "func": idaapi.get_func_name(c) or hex(c)}
            for c in callers[:30]
        ]
    except Exception:
        pass

    # Callees
    try:
        callees_set = set()
        for item_ea in idautils.FuncItems(start):
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                callee_f = idaapi.get_func(ref)
                if callee_f and callee_f.start_ea != start:
                    callees_set.add(callee_f.start_ea)
        result["callees"] = [
            {"addr": hex(c), "name": idaapi.get_func_name(c) or ""}
            for c in sorted(callees_set)[:30]
        ]
    except Exception:
        pass

    # Basic block summary using FlowChart (accurate CFG, excludes call edges)
    try:
        flowchart = idaapi.FlowChart(f)
        blocks = 0
        edges = 0
        for block in flowchart:
            blocks += 1
            edges += sum(1 for _ in block.succs())
        blocks = max(blocks, 1)
        result["cfg_summary"] = {
            "blocks": blocks,
            "edges": edges,
            "complexity": edges - blocks + 2,
        }
    except Exception:
        pass

    # Comments
    try:
        comments = get_all_comments(start)
        if comments:
            result["comments"] = comments
    except Exception:
        pass

    # AI instruction hint
    result["_ai_instruction"] = (
        f"Function {result['name']} analyzed. "
        "Use rename() to name variables, set_comments() to annotate, "
        "or analyze_function on callers/callees for deeper analysis."
    )

    return result


# ============================================================================
# Component Analysis (multi-function group)
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Root function addresses"],
    max_depth: Annotated[int, "Max callee traversal depth (default: 1)"] = 1,
    max_functions: Annotated[int, "Max functions to analyze (default: 20)"] = 20,
) -> dict:
    """Analyze a group of related functions: internal call graph + shared globals + interface"""
    roots = normalize_list_input(addrs)
    ea_set: set[int] = set()
    queue: list[tuple[int, int]] = []

    # Collect root functions
    for root in roots:
        try:
            ea = parse_address(root)
            f = require_func_t(ea)
            ea_set.add(f.start_ea)
            queue.append((f.start_ea, 0))
        except Exception:
            continue

    # BFS to collect callees up to max_depth
    while queue and len(ea_set) < max_functions:
        current_ea, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        try:
            f = require_func_t(current_ea)
            for item_ea in idautils.FuncItems(f.start_ea):
                for ref in idautils.CodeRefsFrom(item_ea, 0):
                    callee_f = idaapi.get_func(ref)
                    if callee_f and callee_f.start_ea not in ea_set:
                        ea_set.add(callee_f.start_ea)
                        queue.append((callee_f.start_ea, depth + 1))
                        if len(ea_set) >= max_functions:
                            break
                if len(ea_set) >= max_functions:
                    break
        except Exception:
            continue

    # Build compact summaries
    functions = []
    internal_edges = []
    for ea in sorted(ea_set):
        try:
            f = require_func_t(ea)
            summary = {
                "addr": hex(ea),
                "name": idaapi.get_func_name(ea) or "",
                "size": f.end_ea - ea,
            }
            try:
                summary["prototype"] = get_prototype(f)
            except Exception:
                pass

            # Compact strings (top 5 values)
            try:
                strs = extract_function_strings(ea)
                summary["strings"] = list({s.get("string", "") for s in strs})[:5]
            except Exception:
                pass

            functions.append(summary)

            # Internal call edges
            for item_ea in idautils.FuncItems(ea):
                for ref in idautils.CodeRefsFrom(item_ea, 0):
                    callee_f = idaapi.get_func(ref)
                    if callee_f and callee_f.start_ea in ea_set and callee_f.start_ea != ea:
                        internal_edges.append({"from": hex(ea), "to": hex(callee_f.start_ea)})

        except Exception:
            continue

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for e in internal_edges:
        key = (e["from"], e["to"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    # Interface functions (called from outside the component)
    interface_funcs = []
    for ea in sorted(ea_set):
        for ref in idautils.CodeRefsTo(ea, 0):
            caller_f = idaapi.get_func(ref)
            if caller_f and caller_f.start_ea not in ea_set:
                interface_funcs.append(hex(ea))
                break

    return {
        "functions": functions,
        "internal_call_graph": unique_edges,
        "interface_functions": interface_funcs,
        "total_functions": len(functions),
        "truncated": len(ea_set) >= max_functions,
        "_ai_instruction": "Component analyzed. Use analyze_function on individual functions for full detail.",
    }
