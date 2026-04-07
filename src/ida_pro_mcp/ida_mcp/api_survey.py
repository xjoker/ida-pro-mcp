"""Binary survey tool — one-call triage providing a comprehensive overview.

Returns metadata, segments, entry points, statistics, interesting strings/functions,
and categorized imports for rapid binary assessment.
"""

import re
from typing import Annotated

import ida_entry
import ida_funcs
import ida_ida
import ida_nalt
import idaapi
import idautils

from .rpc import tool
from .sync import idasync, tool_timeout


# ============================================================================
# Import categorization patterns
# ============================================================================

_IMPORT_CATEGORIES = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|ssl|tls|hmac|pbkdf|chacha|salsa|blowfish", re.I)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|inet|dns|gethost|getaddr|bind|listen|accept", re.I)),
    ("file", re.compile(r"fopen|fclose|fread|fwrite|CreateFile|ReadFile|WriteFile|open|close|read|write|stat|unlink|remove|rename|mkdir", re.I)),
    ("process", re.compile(r"exec|spawn|fork|CreateProcess|ShellExecute|system|popen|WinExec|kill|signal|wait", re.I)),
    ("memory", re.compile(r"alloc|malloc|free|realloc|mmap|VirtualAlloc|HeapAlloc|memcpy|memset|memmove", re.I)),
    ("registry", re.compile(r"Reg(Open|Close|Query|Set|Delete|Create|Enum)Key", re.I)),
    ("thread", re.compile(r"thread|mutex|semaphore|critical_section|pthread|CreateThread|WaitForSingle", re.I)),
    ("debug", re.compile(r"debug|assert|IsDebuggerPresent|CheckRemoteDebugger|OutputDebugString", re.I)),
]

# Performance caps for large binaries
_MAX_FUNC_ITER = 10000
_MAX_STRING_ITER = 5000


# ============================================================================
# Survey Tool
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def survey_binary(
    detail_level: Annotated[str, "Detail: 'minimal', 'standard', or 'full' (default: 'standard')"] = "standard",
) -> dict:
    """Generate a comprehensive binary triage report in a single call"""

    result: dict = {}

    # --- Metadata ---
    result["metadata"] = {
        "path": ida_nalt.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
        "size": hex(ida_ida.inf_get_max_ea() - ida_ida.inf_get_min_ea()),
        "md5": ida_nalt.retrieve_input_file_md5().hex() if ida_nalt.retrieve_input_file_md5() else "",
        "sha256": ida_nalt.retrieve_input_file_sha256().hex() if ida_nalt.retrieve_input_file_sha256() else "",
        "filetype": ida_ida.inf_get_filetype(),
        "is_64bit": ida_ida.inf_is_64bit(),
        "processor": ida_ida.inf_get_procname(),
    }

    # --- Segments ---
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            segments.append({
                "name": idaapi.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "type": "CODE" if seg.type == idaapi.SEG_CODE else "DATA" if seg.type == idaapi.SEG_DATA else "BSS" if seg.type == idaapi.SEG_BSS else str(seg.type),
                "perm": f"{'R' if seg.perm & idaapi.SFL_READ else '-'}{'W' if seg.perm & idaapi.SFL_WRITE else '-'}{'X' if seg.perm & idaapi.SFL_EXEC else '-'}",
            })
    result["segments"] = segments

    # --- Entry points ---
    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        entries.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    result["entrypoints"] = entries[:50]

    # --- Statistics ---
    func_count = 0
    lib_func_count = 0
    total_code_size = 0
    func_eas = []
    for ea in idautils.Functions():
        func_count += 1
        f = idaapi.get_func(ea)
        if f:
            if f.flags & ida_funcs.FUNC_LIB:
                lib_func_count += 1
            else:
                func_eas.append(ea)
            total_code_size += f.end_ea - f.start_ea
        if func_count >= _MAX_FUNC_ITER:
            break

    string_count = 0
    for _ in idautils.Strings():
        string_count += 1
        if string_count >= _MAX_STRING_ITER:
            break

    result["statistics"] = {
        "functions": func_count,
        "library_functions": lib_func_count,
        "user_functions": func_count - lib_func_count,
        "strings": string_count,
        "total_code_size": total_code_size,
        "functions_capped": func_count >= _MAX_FUNC_ITER,
        "strings_capped": string_count >= _MAX_STRING_ITER,
    }

    if detail_level == "minimal":
        result["_ai_instruction"] = "Use analyze_function on specific functions for deeper analysis."
        return result

    # --- Interesting strings (by xref count) ---
    scored_strings = []
    str_count = 0
    for s in idautils.Strings():
        str_count += 1
        if str_count > _MAX_STRING_ITER:
            break
        value = str(s)
        if len(value) < 4:
            continue
        xref_count = sum(1 for _ in idautils.XrefsTo(s.ea, 0))
        if xref_count > 0:
            scored_strings.append({"value": value[:200], "addr": hex(s.ea), "xrefs": xref_count})

    scored_strings.sort(key=lambda x: x["xrefs"], reverse=True)
    result["interesting_strings"] = scored_strings[:15]

    # --- Interesting functions (by xref count, non-library) ---
    scored_funcs = []
    for ea in func_eas[:_MAX_FUNC_ITER]:
        f = idaapi.get_func(ea)
        if not f:
            continue
        name = idaapi.get_func_name(ea) or ""
        xref_count = sum(1 for _ in idautils.CodeRefsTo(ea, 0))
        size = f.end_ea - f.start_ea

        # Classification
        callee_count = 0
        for item_ea in idautils.FuncItems(ea):
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                cf = idaapi.get_func(ref)
                if cf and cf.start_ea != ea:
                    callee_count += 1
                    break  # just need count > 0 detection

        if size <= 8:
            kind = "thunk"
        elif callee_count == 0:
            kind = "leaf"
        elif size > 500:
            kind = "complex"
        else:
            kind = "normal"

        scored_funcs.append({
            "addr": hex(ea),
            "name": name,
            "size": size,
            "xrefs": xref_count,
            "kind": kind,
        })

    scored_funcs.sort(key=lambda x: x["xrefs"], reverse=True)
    result["interesting_functions"] = scored_funcs[:15]

    # --- Categorized imports ---
    categorized: dict[str, list[str]] = {}
    uncategorized = []

    for i in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            continue

        def imp_cb(ea, name, ordinal):
            if not name:
                return True
            matched = False
            for cat_name, pattern in _IMPORT_CATEGORIES:
                if pattern.search(name):
                    if cat_name not in categorized:
                        categorized[cat_name] = []
                    categorized[cat_name].append(f"{module_name}!{name}")
                    matched = True
                    break
            if not matched:
                uncategorized.append(f"{module_name}!{name}")
            return True

        ida_nalt.enum_import_names(i, imp_cb)

    result["imports_by_category"] = {k: v[:20] for k, v in categorized.items()}
    result["imports_uncategorized_count"] = len(uncategorized)

    # --- Analysis tips ---
    tips = []
    if func_count > 10000:
        tips.append("Large binary (>10k functions). Focus on specific segments or entry points.")
    if lib_func_count > func_count * 0.6:
        tips.append("Many library functions detected. Use FLIRT/Lumina to identify remaining ones.")
    if result["metadata"].get("is_64bit"):
        tips.append("64-bit binary. Watch for register-based calling conventions.")
    if any(cat in categorized for cat in ("crypto", "network")):
        tips.append("Crypto/network imports detected. Check for key material and protocol handlers.")
    stripped = all(not idaapi.get_func_name(ea) or idaapi.get_func_name(ea).startswith("sub_") for ea in func_eas[:20])
    if stripped and len(func_eas) > 20:
        tips.append("Binary appears stripped. Consider running FLIRT signatures first.")

    result["analysis_tips"] = tips

    result["_ai_instruction"] = (
        "Binary surveyed. Suggested next steps:\n"
        "1. analyze_function on interesting_functions for detailed analysis\n"
        "2. Use insn_query to search for specific patterns\n"
        "3. Use type_query to browse the type library"
    )

    return result
