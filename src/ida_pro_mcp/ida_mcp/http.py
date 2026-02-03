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


# 国际化文本 / Internationalization texts
I18N = {
    "en": {
        "title": "IDA Pro MCP Config",
        "server_config": "Server Configuration",
        "host": "Host",
        "port": "Port",
        "api_access": "API Access",
        "unrestricted": "⛔ Unrestricted",
        "unrestricted_tip": "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
        "local": "🏠 Local apps only",
        "local_tip": "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
        "direct": "🔒 Direct connections only",
        "direct_tip": "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
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
        "api_key_tip": "Leave empty to disable authentication. Use environment variable reference like ${IDA_MCP_API_KEY} for security.",
    },
    "zh": {
        "title": "IDA Pro MCP 配置",
        "server_config": "服务器配置",
        "host": "监听地址",
        "port": "端口",
        "api_access": "API 访问策略",
        "unrestricted": "⛔ 无限制",
        "unrestricted_tip": "任何网站都可以向此服务器发送请求。您访问的恶意网站可能会访问或修改您的 IDA 数据库。",
        "local": "🏠 仅本地应用",
        "local_tip": "只有在 localhost 上运行的 Web 应用可以连接。远程网站被阻止，但本地开发工具可以正常工作。",
        "direct": "🔒 仅直接连接",
        "direct_tip": "阻止基于浏览器的请求。只有 curl、MCP 工具或 Claude Desktop 等直接客户端可以连接。",
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
        "api_key_tip": "留空禁用认证。为安全起见，可使用环境变量引用，如 ${IDA_MCP_API_KEY}。",
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


DEFAULT_CORS_POLICY = "local"
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


def get_cors_policy(port: int) -> str:
    """Retrieve the current CORS policy from configuration."""
    match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
        case "unrestricted":
            return "*"
        case "local":
            return "127.0.0.1 localhost"
        case "direct":
            return f"http://127.0.0.1:{port} http://localhost:{port}"
        case _:
            return "*"


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
        self.update_cors_policy()

    def update_cors_policy(self):
        match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
            case "unrestricted":
                self.mcp_server.cors_allowed_origins = "*"
            case "local":
                self.mcp_server.cors_allowed_origins = self.mcp_server.cors_localhost
            case "direct":
                self.mcp_server.cors_allowed_origins = None

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
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)
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
}}

.status-running {{
  background: var(--success);
  box-shadow: 0 0 6px var(--success);
}}

.status-stopped {{
  background: #dc3545;
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

input[type="checkbox"],
input[type="radio"] {{
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

.btn-primary {{
  background: var(--accent);
  color: white;
}}

.btn-primary:hover {{
  opacity: 0.9;
}}

.btn-success {{
  background: var(--success);
  color: white;
}}

.btn-success:hover {{
  opacity: 0.9;
}}

.tooltip {{
  border-bottom: 1px dotted var(--text);
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
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.5rem;
}}

.quick-select {{
  font-size: 0.9rem;
  margin: 0.5rem 0;
}}

.quick-select a {{
  color: var(--accent);
  text-decoration: none;
  margin: 0 0.25rem;
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
  </style>
  <script defer>
  function setTools(mode) {{
    document.querySelectorAll('input[data-tool]').forEach(cb => {{
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    }});
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
    <span class="status-indicator status-running"></span>
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
      <div class="hint">0.0.0.0 = all interfaces, 127.0.0.1 = localhost only</div>
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

<h2>{t("api_access", lang)}</h2>
<div class="card">
"""
        cors_options = [
            ("unrestricted", t("unrestricted", lang), t("unrestricted_tip", lang)),
            ("local", t("local", lang), t("local_tip", lang)),
            ("direct", t("direct", lang), t("direct_tip", lang)),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'

        body += "</div>"

        quick_select = f"""<div class="quick-select">
  {t("select", lang)}:
  <a href="#" onclick="setTools('all'); return false;">{t("all", lang)}</a> ·
  <a href="#" onclick="setTools('none'); return false;">{t("none", lang)}</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">{t("disable_unsafe", lang)}</a>
</div>"""

        body += f"<h2>{t('enabled_tools', lang)}</h2>"
        body += quick_select
        body += '<div class="tools-container">'
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += "</div>"
        body += quick_select

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

        # Update CORS policy
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        config_json_set("cors_policy", cors_policy)
        self.update_cors_policy()

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
