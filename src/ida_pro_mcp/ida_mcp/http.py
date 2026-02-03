import html
import json
import re
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar, cast
from http.server import HTTPServer

from .sync import idasync
from .rpc import (
    McpRpcRegistry,
    McpHttpRequestHandler,
    MCP_SERVER,
    MCP_UNSAFE,
    get_cached_output,
)


T = TypeVar("T")


# 工具描述双语翻译 / Tool descriptions bilingual
TOOL_DESCRIPTIONS = {
    # Core functions
    "idb_meta": ("Get IDB metadata", "获取 IDB 元数据"),
    "lookup_funcs": ("Get functions by address or name", "通过地址或名称获取函数"),
    "cursor_addr": ("Get current cursor address", "获取当前光标地址"),
    "cursor_func": ("Get current function at cursor", "获取光标所在函数"),
    "int_convert": ("Convert numbers between formats", "数字格式转换"),
    "list_funcs": ("List functions with filtering", "列出函数（支持过滤）"),
    "list_globals": ("List global variables", "列出全局变量"),
    "imports": ("List imported symbols", "列出导入符号"),
    "strings": ("List strings in binary", "列出二进制中的字符串"),
    "segments": ("List memory segments", "列出内存段"),
    "local_types": ("List local types", "列出本地类型"),
    "entrypoints": ("Get entry points", "获取入口点"),

    # Analysis
    "decompile": ("Decompile function to pseudocode", "反编译函数为伪代码"),
    "disasm": ("Disassemble function", "反汇编函数"),
    "xrefs_to": ("Get cross-references to address", "获取到地址的交叉引用"),
    "xrefs_to_field": ("Get xrefs to struct field", "获取到结构体字段的交叉引用"),
    "callees": ("Get functions called by function", "获取函数调用的其他函数"),
    "callers": ("Get functions calling this function", "获取调用此函数的函数"),
    "analyze_funcs": ("Comprehensive function analysis", "全面的函数分析"),
    "find_bytes": ("Search for byte patterns", "搜索字节模式"),
    "find_insns": ("Search for instruction sequences", "搜索指令序列"),
    "basic_blocks": ("Get control flow basic blocks", "获取控制流基本块"),
    "find_paths": ("Find execution paths", "查找执行路径"),
    "search": ("Search for patterns in binary", "在二进制中搜索模式"),
    "find_insn_operands": ("Find instructions with operands", "查找带特定操作数的指令"),
    "callgraph": ("Build call graph", "构建调用图"),
    "xref_matrix": ("Build cross-reference matrix", "构建交叉引用矩阵"),
    "analyze_strings": ("Analyze and filter strings", "分析和过滤字符串"),
    "export_funcs": ("Export function data", "导出函数数据"),

    # Memory
    "get_bytes": ("Read bytes from memory", "从内存读取字节"),
    "get_u8": ("Read 8-bit unsigned integer", "读取 8 位无符号整数"),
    "get_u16": ("Read 16-bit unsigned integer", "读取 16 位无符号整数"),
    "get_u32": ("Read 32-bit unsigned integer", "读取 32 位无符号整数"),
    "get_u64": ("Read 64-bit unsigned integer", "读取 64 位无符号整数"),
    "get_string": ("Read string from memory", "从内存读取字符串"),
    "get_global_value": ("Read global variable value", "读取全局变量值"),
    "patch": ("Patch bytes at address", "在地址处补丁字节"),

    # Types
    "declare_type": ("Declare C types", "声明 C 类型"),
    "structs": ("List all structures", "列出所有结构体"),
    "struct_info": ("Get structure info", "获取结构体信息"),
    "read_struct": ("Read struct fields at address", "读取地址处的结构体字段"),
    "search_structs": ("Search structures by name", "按名称搜索结构体"),
    "apply_types": ("Apply types to entities", "应用类型到实体"),
    "infer_types": ("Infer types at address", "推断地址处的类型"),

    # Modify
    "set_comments": ("Set comments at address", "在地址处设置注释"),
    "patch_asm": ("Patch assembly instructions", "补丁汇编指令"),
    "rename": ("Rename functions/variables", "重命名函数/变量"),

    # Stack
    "stack_frame": ("Get stack frame variables", "获取栈帧变量"),
    "declare_stack": ("Create stack variable", "创建栈变量"),
    "delete_stack": ("Delete stack variable", "删除栈变量"),

    # Debug (unsafe)
    "dbg_start": ("⚠️ Start debugger", "⚠️ 启动调试器"),
    "dbg_exit": ("⚠️ Exit debugger", "⚠️ 退出调试器"),
    "dbg_continue": ("⚠️ Continue execution", "⚠️ 继续执行"),
    "dbg_run_to": ("⚠️ Run to address", "⚠️ 运行到地址"),
    "dbg_step_into": ("⚠️ Step into instruction", "⚠️ 步入指令"),
    "dbg_step_over": ("⚠️ Step over instruction", "⚠️ 步过指令"),
    "dbg_list_bps": ("⚠️ List breakpoints", "⚠️ 列出断点"),
    "dbg_add_bp": ("⚠️ Add breakpoint", "⚠️ 添加断点"),
    "dbg_delete_bp": ("⚠️ Delete breakpoint", "⚠️ 删除断点"),
    "dbg_enable_bp": ("⚠️ Enable/disable breakpoint", "⚠️ 启用/禁用断点"),
    "dbg_regs": ("⚠️ Get all registers", "⚠️ 获取所有寄存器"),
    "dbg_regs_thread": ("⚠️ Get thread registers", "⚠️ 获取线程寄存器"),
    "dbg_regs_cur": ("⚠️ Get current thread registers", "⚠️ 获取当前线程寄存器"),
    "dbg_gpregs_thread": ("⚠️ Get GP registers for thread", "⚠️ 获取线程通用寄存器"),
    "dbg_current_gpregs": ("⚠️ Get current GP registers", "⚠️ 获取当前通用寄存器"),
    "dbg_regs_for_thread": ("⚠️ Get specific thread registers", "⚠️ 获取特定线程寄存器"),
    "dbg_current_regs": ("⚠️ Get specific current registers", "⚠️ 获取特定当前寄存器"),
    "dbg_callstack": ("⚠️ Get call stack", "⚠️ 获取调用栈"),
    "dbg_read_mem": ("⚠️ Read debug memory", "⚠️ 读取调试内存"),
    "dbg_write_mem": ("⚠️ Write debug memory", "⚠️ 写入调试内存"),

    # Python
    "py_eval": ("⚠️ Execute Python code in IDA", "⚠️ 在 IDA 中执行 Python 代码"),
}

# 国际化文本 / Internationalization texts
I18N = {
    "en": {
        "title": "IDA Pro MCP Config",
        "server_config": "Server Configuration",
        "host": "Host",
        "host_hint": "0.0.0.0 = all interfaces, 127.0.0.1 = localhost only",
        "port": "Port",
        "enabled_tools": "Enabled Tools",
        "select": "Select",
        "all": "All",
        "none": "None",
        "disable_unsafe": "Disable unsafe",
        "save": "Save",
        "save_restart": "Save & Restart Server",
        "language": "Language",
        "server_will_restart": "Server will restart after saving configuration changes.",
        "current_status": "Current Status",
        "running": "Running",
        "stopped": "Stopped",
        "listening_on": "Listening on",
        "config_saved": "Configuration saved. Server restarting...",
        "auth_config": "Authentication",
        "auth_enabled": "Enable API Key Authentication",
        "api_key": "API Key",
        "api_key_tip": "Leave empty to disable. Use ${ENV_VAR} for environment variable.",
        "tools_count": "tools enabled",
        "unsafe_warning": "⚠️ = Unsafe tool (debugger/code execution)",
    },
    "zh": {
        "title": "IDA Pro MCP 配置",
        "server_config": "服务器配置",
        "host": "监听地址",
        "host_hint": "0.0.0.0 = 所有接口，127.0.0.1 = 仅本地",
        "port": "端口",
        "enabled_tools": "已启用工具",
        "select": "选择",
        "all": "全部",
        "none": "无",
        "disable_unsafe": "禁用不安全工具",
        "save": "保存",
        "save_restart": "保存并重启服务器",
        "language": "语言",
        "server_will_restart": "保存配置更改后服务器将重启。",
        "current_status": "当前状态",
        "running": "运行中",
        "stopped": "已停止",
        "listening_on": "监听地址",
        "config_saved": "配置已保存。服务器正在重启...",
        "auth_config": "认证设置",
        "auth_enabled": "启用 API Key 认证",
        "api_key": "API Key",
        "api_key_tip": "留空禁用。使用 ${环境变量} 引用环境变量。",
        "tools_count": "个工具已启用",
        "unsafe_warning": "⚠️ = 不安全工具（调试器/代码执行）",
    },
}


@idasync
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idasync
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337


def get_server_config() -> dict:
    """Get server configuration from IDA database."""
    return config_json_get(
        "server_config",
        {
            "host": DEFAULT_HOST,
            "port": DEFAULT_PORT,
            "auth_enabled": False,
            "api_key": None,
        },
    )


def set_server_config(config: dict):
    """Save server configuration to IDA database."""
    config_json_set("server_config", config)


def get_language() -> str:
    """Get current language setting."""
    return config_json_get("language", "en")


def set_language(lang: str):
    """Set language preference."""
    if lang in I18N:
        config_json_set("language", lang)


def t(key: str, lang: str = None) -> str:
    """Get translated text for the given key."""
    if lang is None:
        lang = get_language()
    return I18N.get(lang, I18N["en"]).get(key, key)


def get_tool_description(name: str, lang: str) -> str:
    """Get tool description in specified language."""
    if name in TOOL_DESCRIPTIONS:
        en_desc, zh_desc = TOOL_DESCRIPTIONS[name]
        return zh_desc if lang == "zh" else en_desc
    return name


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")

# Global reference to trigger server restart
_server_restart_callback = None


def set_server_restart_callback(callback):
    """Set callback function to restart the server."""
    global _server_restart_callback
    _server_restart_callback = callback


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
            return

        # Handle output download requests
        output_match = re.match(r"^/output/([a-f0-9-]+)\.(\w+)$", path)
        if output_match:
            self._handle_output_download(output_match.group(1), output_match.group(2))
            return

        super().do_GET()

    def _handle_output_download(self, output_id: str, extension: str):
        """Handle download of cached output data."""
        data = get_cached_output(output_id)
        if data is None:
            self.send_error(404, "Output not found or expired")
            return

        if extension == "json":
            content = json.dumps(data, indent=2)
        elif isinstance(data, dict) and "code" in data:
            content = str(data["code"])
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            content = "\n\n".join(
                str(item.get("code", item.get("asm", item.get("lines", ""))))
                for item in data
            )
        else:
            content = json.dumps(data, indent=2)

        body = content.encode("utf-8")
        self.send_response(200)
        content_type = "application/json" if extension == "json" else "text/plain"
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{output_id}.{extension}"'
        )
        self.end_headers()
        self.wfile.write(body)

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _check_origin(self) -> bool:
        """
        Prevents CSRF and DNS rebinding attacks by ensuring POST requests
        originate from pages served by this server, not external websites.
        """
        origin = self.headers.get("Origin")
        port = self.server_port
        if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self.send_error(403, "Invalid Origin")
            return False
        return True

    def _check_host(self) -> bool:
        """
        Prevents DNS rebinding attacks where an attacker's domain (e.g., evil.com)
        resolves to 127.0.0.1, allowing their page to read localhost resources.
        """
        host = self.headers.get("Host")
        port = self.server_port
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.send_error(403, "Invalid Host")
            return False
        return True

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        # Get current settings
        server_config = get_server_config()
        lang = get_language()

        # Get query parameter for language switch
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if "lang" in query:
            new_lang = query["lang"][0]
            if new_lang in I18N:
                set_language(new_lang)
                lang = new_lang

        # Count enabled tools
        enabled_count = len(self.mcp_server.tools.methods)
        total_count = len(ORIGINAL_TOOLS)

        # Build HTML
        body = f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{t("title", lang)}</title>
  <style>
:root {{
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
  --success: #28a745;
  --warning: #ffc107;
  --card-bg: #f8f9fa;
}}

@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
    --success: #48bb78;
    --warning: #ecc94b;
    --card-bg: #242424;
  }}
}}

* {{
  box-sizing: border-box;
}}

body {{
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 900px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.5;
}}

h1 {{
  font-size: 1.5rem;
  margin-bottom: 0.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}}

h2 {{
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.75rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid var(--border);
}}

.lang-switch {{
  font-size: 0.9rem;
  font-weight: normal;
}}

.lang-switch a {{
  color: var(--accent);
  text-decoration: none;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}}

.lang-switch a:hover {{
  background: var(--hover);
}}

.lang-switch a.active {{
  background: var(--accent);
  color: white;
}}

.card {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
}}

.status-bar {{
  display: flex;
  gap: 1rem;
  align-items: center;
  flex-wrap: wrap;
  padding: 0.75rem 1rem;
  background: var(--card-bg);
  border-radius: 8px;
  margin-bottom: 1rem;
  border: 1px solid var(--border);
}}

.status-indicator {{
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 0.5rem;
  background: var(--success);
  box-shadow: 0 0 6px var(--success);
}}

.form-group {{
  margin-bottom: 1rem;
}}

.form-row {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}}

@media (max-width: 600px) {{
  .form-row {{
    grid-template-columns: 1fr;
  }}
}}

label {{
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}}

label:hover {{
  background: var(--hover);
}}

label.form-label {{
  font-weight: 500;
  margin-bottom: 0.25rem;
  padding: 0;
}}

label.form-label:hover {{
  background: transparent;
}}

input[type="text"],
input[type="number"] {{
  width: 100%;
  padding: 0.5rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg);
  color: var(--text);
  font-size: 1rem;
}}

input[type="text"]:focus,
input[type="number"]:focus {{
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px rgba(0, 102, 204, 0.2);
}}

input[type="checkbox"] {{
  margin-right: 0.5rem;
  accent-color: var(--accent);
}}

.btn {{
  padding: 0.6rem 1.5rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  margin-right: 0.5rem;
  margin-top: 0.5rem;
}}

.btn-success {{
  background: var(--success);
  color: white;
}}

.btn-success:hover {{
  opacity: 0.9;
}}

.hint {{
  font-size: 0.85rem;
  color: #666;
  margin-top: 0.25rem;
}}

@media (prefers-color-scheme: dark) {{
  .hint {{
    color: #999;
  }}
}}

.tools-container {{
  max-height: 500px;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.5rem;
}}

.tool-item {{
  display: flex;
  align-items: flex-start;
  padding: 0.4rem 0.5rem;
  border-radius: 4px;
}}

.tool-item:hover {{
  background: var(--hover);
}}

.tool-name {{
  font-family: monospace;
  font-weight: 500;
  min-width: 180px;
}}

.tool-desc {{
  color: #666;
  font-size: 0.9rem;
}}

@media (prefers-color-scheme: dark) {{
  .tool-desc {{
    color: #999;
  }}
}}

.quick-select {{
  font-size: 0.9rem;
  margin: 0.5rem 0;
  display: flex;
  gap: 0.5rem;
  align-items: center;
}}

.quick-select a {{
  color: var(--accent);
  text-decoration: none;
}}

.quick-select a:hover {{
  text-decoration: underline;
}}

.notice {{
  padding: 0.75rem 1rem;
  background: rgba(255, 193, 7, 0.1);
  border: 1px solid var(--warning);
  border-radius: 4px;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}}

.tools-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
}}

.tools-count {{
  font-size: 0.9rem;
  color: #666;
}}
  </style>
  <script defer>
  function setTools(mode) {{
    document.querySelectorAll('input[data-tool]').forEach(cb => {{
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    }});
    updateCount();
  }}
  function updateCount() {{
    const checked = document.querySelectorAll('input[data-tool]:checked').length;
    const total = document.querySelectorAll('input[data-tool]').length;
    document.getElementById('tools-count').textContent = checked + '/' + total;
  }}
  </script>
</head>
<body>
<h1>
  {t("title", lang)}
  <span class="lang-switch">
    <a href="?lang=en" class="{'active' if lang == 'en' else ''}">EN</a>
    <a href="?lang=zh" class="{'active' if lang == 'zh' else ''}">中文</a>
  </span>
</h1>

<div class="status-bar">
  <span>
    <span class="status-indicator"></span>
    <strong>{t("current_status", lang)}:</strong> {t("running", lang)}
  </span>
  <span>
    <strong>{t("listening_on", lang)}:</strong> {server_config.get("host", DEFAULT_HOST)}:{server_config.get("port", DEFAULT_PORT)}
  </span>
</div>

<form method="post" action="/config">

<div class="notice">
  ⚠️ {t("server_will_restart", lang)}
</div>

<h2>{t("server_config", lang)}</h2>
<div class="card">
  <div class="form-row">
    <div class="form-group">
      <label class="form-label">{t("host", lang)}</label>
      <input type="text" name="host" value="{html.escape(str(server_config.get('host', DEFAULT_HOST)))}" placeholder="127.0.0.1">
      <div class="hint">{t("host_hint", lang)}</div>
    </div>
    <div class="form-group">
      <label class="form-label">{t("port", lang)}</label>
      <input type="number" name="port" value="{server_config.get('port', DEFAULT_PORT)}" min="1" max="65535">
    </div>
  </div>
</div>

<h2>{t("auth_config", lang)}</h2>
<div class="card">
  <div class="form-group">
    <label>
      <input type="checkbox" name="auth_enabled" value="1" {'checked' if server_config.get('auth_enabled') else ''}>
      {t("auth_enabled", lang)}
    </label>
  </div>
  <div class="form-group">
    <label class="form-label">{t("api_key", lang)}</label>
    <input type="text" name="api_key" value="{html.escape(str(server_config.get('api_key') or ''))}" placeholder="${{IDA_MCP_API_KEY}}">
    <div class="hint">{t("api_key_tip", lang)}</div>
  </div>
</div>

<div class="tools-header">
  <h2>{t("enabled_tools", lang)}</h2>
  <span class="tools-count"><span id="tools-count">{enabled_count}/{total_count}</span> {t("tools_count", lang)}</span>
</div>

<div class="quick-select">
  {t("select", lang)}:
  <a href="#" onclick="setTools('all'); return false;">{t("all", lang)}</a> ·
  <a href="#" onclick="setTools('none'); return false;">{t("none", lang)}</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">{t("disable_unsafe", lang)}</a>
  <span style="margin-left: 1rem; color: #666; font-size: 0.85rem;">{t("unsafe_warning", lang)}</span>
</div>

<div class="tools-container">
"""
        for name, func in ORIGINAL_TOOLS.items():
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            description = get_tool_description(name, lang)

            body += f"""<label class="tool-item">
  <input type="checkbox" name="{html.escape(name)}" value="{html.escape(name)}"{checked}{unsafe_attr} data-tool onchange="updateCount()">
  <span class="tool-name">{html.escape(name)}</span>
  <span class="tool-desc">{html.escape(description)}</span>
</label>
"""
        body += "</div>"

        body += f"""
<div style="margin-top: 1.5rem;">
  <button type="submit" class="btn btn-success">{t("save_restart", lang)}</button>
</div>

</form>
</body>
</html>"""
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        # Parse the form data
        length = int(self.headers.get("content-length", "0"))
        postvars = parse_qs(self.rfile.read(length).decode("utf-8"))

        # Update server configuration
        new_host = postvars.get("host", [DEFAULT_HOST])[0].strip() or DEFAULT_HOST
        try:
            new_port = int(postvars.get("port", [DEFAULT_PORT])[0])
            if not (1 <= new_port <= 65535):
                new_port = DEFAULT_PORT
        except (ValueError, TypeError):
            new_port = DEFAULT_PORT

        auth_enabled = "auth_enabled" in postvars
        api_key = postvars.get("api_key", [None])[0]
        if api_key:
            api_key = api_key.strip() or None

        server_config = {
            "host": new_host,
            "port": new_port,
            "auth_enabled": auth_enabled,
            "api_key": api_key,
        }
        set_server_config(server_config)

        # Update the server's tools
        enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Trigger server restart if callback is set
        if _server_restart_callback:
            try:
                # Schedule restart after response is sent
                import threading

                def delayed_restart():
                    import time

                    time.sleep(0.5)  # Wait for response to be sent
                    _server_restart_callback(new_host, new_port)

                threading.Thread(target=delayed_restart, daemon=True).start()
            except Exception as e:
                print(f"[MCP] Failed to schedule server restart: {e}")

        # Redirect back to the config page (will use new port after restart)
        self.send_response(302)
        self.send_header("Location", f"http://{new_host}:{new_port}/config.html")
        self.end_headers()
