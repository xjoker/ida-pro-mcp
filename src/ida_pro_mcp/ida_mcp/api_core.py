"""Core API Functions - IDB metadata and basic queries"""

import logging
import re
import time
from typing import Annotated, Any

import idaapi
import ida_funcs
import ida_lines
import ida_search
import ida_segment
import idautils
import ida_nalt

from .rpc import tool
from .sync import idasync
from .cache import function_cache

logger = logging.getLogger(__name__)

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")


from .utils import (
    Function,
    ConvertedNumber,
    Global,
    Import,
    Page,
    NumberConversion,
    ListQuery,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    paginate,
    parse_address,
    pattern_filter,
)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, } for fn in all_funcs]

    results = []
    for query in queries:
        # Try cache first
        cache_key = f"lookup:{query}"
        cached = function_cache.get(cache_key)
        if cached is not None:
            results.append(cached)
            continue

        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    result = {"query": query, "fn": func, }
                else:
                    result = {"query": query, "fn": None, "error": "Not a function"}
            else:
                result = {"query": query, "fn": None, "error": "Not found"}
        except Exception as e:
            result = {"query": query, "fn": None, "error": str(e)}

        # Cache the result
        function_cache.set(cache_key, result)
        results.append(result)

    return results


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
            }
        )

    return results


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 100, "filter": s}
    )
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 100, "filter": s}
    )
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings with case-insensitive regex patterns"""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {
            "n": 0,
            "matches": [],
            "cursor": {"done": True},
            "error": f"Invalid regex pattern: {e}",
        }
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


# ============================================================================
# Text Search
# ============================================================================


class SearchTextLine(dict):
    """One matching line from the rendered listing: kind ('disasm'|'comment') + text."""


class SearchTextHit(dict):
    """One search hit: addr, optional function/segment, and matching lines."""


class SearchTextResult(dict):
    """Paginated result from search_text."""


_COMMENT_SCOLORS = (
    ida_lines.SCOLOR_REGCMT,
    ida_lines.SCOLOR_RPTCMT,
    ida_lines.SCOLOR_AUTOCMT,
    ida_lines.SCOLOR_COLLAPSED,
)


def _line_is_comment(tagged: str) -> bool:
    """Return True if the rendered listing line carries any comment SCOLOR tag."""
    if not tagged:
        return False
    for sc in _COMMENT_SCOLORS:
        if ida_lines.COLOR_ON + sc in tagged:
            return True
    return False


def _classify_hit_lines(
    ea: int,
    matcher,
    want_disasm: bool,
    want_comments: bool,
    max_lines: int = 32,
) -> list[dict]:
    """Render the listing for `ea` once, classify each line, return matching lines."""
    out: list[dict] = []
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, False)
    except Exception:
        return out
    # Bindings vary: (n, lineno, lines) or (lines, lineno).
    lines = None
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                lines = list(item)
                break
    if lines is None:
        return out

    for tagged in lines:
        text = ida_lines.tag_remove(tagged) or ""
        if not text or not matcher(text):
            continue
        is_cmt = _line_is_comment(tagged)
        kind = "comment" if is_cmt else "disasm"
        if kind == "disasm" and not want_disasm:
            continue
        if kind == "comment" and not want_comments:
            continue
        out.append({"kind": kind, "text": text})
    return out


def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing (literal substring by default)"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Cursor: address to resume from (hex or symbol). Empty = first segment."] = "",
    regex: Annotated[bool, "Treat pattern as a regex (uses IDA's SEARCH_REGEX)"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
) -> dict:
    """Search the rendered listing using IDA's native text search (fast C++ scan).

    Discovers candidate EAs with `ida_search.find_text()`, then renders each hit
    once via `ida_lines.generate_disassembly()` to extract matching lines and
    classify them as disasm or comment. Returns one hit per EA.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    # Build a Python-side matcher for per-line filtering after the C++ find.
    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {e}"}
        matcher = lambda s: bool(rx.search(s))  # noqa: E731
    else:
        if case_sensitive:
            needle = pattern
            matcher = lambda s: needle in s  # noqa: E731
        else:
            needle = pattern.lower()
            matcher = lambda s: needle in s.lower()  # noqa: E731

    # Build IDA search flags.
    sflag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NOSHOW
    if case_sensitive:
        sflag |= ida_search.SEARCH_CASE
    if regex:
        sflag |= ida_search.SEARCH_REGEX

    # Resolve cursor.
    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    if start:
        try:
            cursor_ea = parse_address(start)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {e}"}
    else:
        cursor_ea = segments[0][0]

    hits: list[dict] = []
    next_cursor: int | None = None
    seg_idx = 0
    # Skip ahead to the segment that contains/follows cursor_ea.
    while seg_idx < len(segments) and segments[seg_idx][1] <= cursor_ea:
        seg_idx += 1
    if seg_idx < len(segments) and cursor_ea < segments[seg_idx][0]:
        cursor_ea = segments[seg_idx][0]

    while seg_idx < len(segments) and len(hits) < limit:
        seg_start, seg_end = segments[seg_idx]
        ea = ida_search.find_text(cursor_ea, 0, 0, pattern, sflag)
        if ea == idaapi.BADADDR or ea >= seg_end:
            seg_idx += 1
            if seg_idx < len(segments):
                cursor_ea = segments[seg_idx][0]
            continue
        if ea < seg_start:
            # Match landed in a segment we already passed; skip.
            cursor_ea = ea + 1
            continue

        lines = _classify_hit_lines(ea, matcher, want_disasm, want_comments)
        if lines:
            entry: dict[str, Any] = {"addr": hex(ea), "matches": lines}
            func = idaapi.get_func(ea)
            if func is not None:
                fname = ida_funcs.get_func_name(func.start_ea)
                if fname:
                    entry["function"] = fname
            seg = idaapi.getseg(ea)
            if seg is not None:
                sname = ida_segment.get_segm_name(seg)
                if sname:
                    entry["segment"] = sname
            hits.append(entry)
            if len(hits) >= limit:
                # Compute resume cursor: just past this hit.
                size = max(1, idaapi.get_item_size(ea))
                next_cursor = ea + size
                break

        # Advance past this match. Use item size if known to avoid re-hitting
        # the same head's listing on the next iteration.
        size = idaapi.get_item_size(ea)
        cursor_ea = ea + (size if size > 0 else 1)

    cursor: dict[str, Any]
    if next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    return {"n": len(hits), "hits": hits, "cursor": cursor}
