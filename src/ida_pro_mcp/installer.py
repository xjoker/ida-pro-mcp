"""MCP client and IDA plugin installation logic.

Handles auto-configuration of 20+ MCP clients across Windows/macOS/Linux,
and IDA Pro plugin installation via symlink or copy.
"""

import os
import sys
import json
import glob
import shutil
import tempfile
import tomllib
import tomli_w

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# Server name used in MCP client configs
MCP_SERVER_NAME = "ida-pro-mcp"

# Legacy name for migration
_OLD_SERVER_NAME = "github.com/xjoker/ida-pro-mcp"


def _validate_plugin_paths():
    """Verify that plugin source files exist."""
    if not os.path.exists(IDA_PLUGIN_PKG):
        raise RuntimeError(
            f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
        )
    if not os.path.exists(IDA_PLUGIN_LOADER):
        raise RuntimeError(
            f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
        )


def get_python_executable():
    """Get the path to the Python executable."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    """Forward Python-related environment variables for MCP server subprocesses."""
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool, ida_host: str, ida_port: int):
    """Generate MCP client configuration dict."""
    if stdio:
        mcp_config = {
            "command": get_python_executable(),
            "args": [
                os.path.join(SCRIPT_DIR, "server.py"),
                "--ida-rpc",
                f"http://{ida_host}:{ida_port}",
            ],
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{ida_host}:{ida_port}/mcp"}


def print_mcp_config(ida_host: str, ida_port: int):
    """Print MCP configuration for manual setup."""
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        stdio=False, ida_host=ida_host, ida_port=ida_port
                    )
                }
            },
            indent=2,
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        stdio=True, ida_host=ida_host, ida_port=ida_port
                    )
                }
            },
            indent=2,
        )
    )


def _get_client_configs() -> dict[str, tuple[str, str]]:
    """Return platform-specific MCP client config paths."""
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA", "")
        home = os.path.expanduser("~")
        return {
            "Cline": (
                os.path.join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(appdata, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"),
                "mcp_settings.json",
            ),
            "Claude": (os.path.join(appdata, "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(home, ".codex"), "config.toml"),
            "Zed": (os.path.join(appdata, "Zed"), "settings.json"),
            "Gemini CLI": (os.path.join(home, ".gemini"), "settings.json"),
            "Qwen Coder": (os.path.join(home, ".qwen"), "settings.json"),
            "Copilot CLI": (os.path.join(home, ".copilot"), "mcp-config.json"),
            "Crush": (home, "crush.json"),
            "Augment Code": (os.path.join(appdata, "Code", "User"), "settings.json"),
            "Qodo Gen": (os.path.join(appdata, "Code", "User"), "settings.json"),
            "Antigravity IDE": (os.path.join(home, ".gemini", "antigravity"), "mcp_config.json"),
            "Warp": (os.path.join(home, ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(home, ".aws", "amazonq"), "mcp_config.json"),
            "Opencode": (os.path.join(home, ".opencode"), "mcp_config.json"),
            "Kiro": (os.path.join(home, ".kiro"), "mcp_config.json"),
            "Trae": (os.path.join(home, ".trae"), "mcp_config.json"),
            "VS Code": (os.path.join(appdata, "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(appdata, "Code - Insiders", "User"), "settings.json"),
        }
    elif sys.platform == "darwin":
        home = os.path.expanduser("~")
        app_support = os.path.join(home, "Library", "Application Support")
        return {
            "Cline": (
                os.path.join(app_support, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(app_support, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(app_support, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"),
                "mcp_settings.json",
            ),
            "Claude": (os.path.join(app_support, "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(home, ".codex"), "config.toml"),
            "Antigravity IDE": (os.path.join(home, ".gemini", "antigravity"), "mcp_config.json"),
            "Zed": (os.path.join(app_support, "Zed"), "settings.json"),
            "Gemini CLI": (os.path.join(home, ".gemini"), "settings.json"),
            "Qwen Coder": (os.path.join(home, ".qwen"), "settings.json"),
            "Copilot CLI": (os.path.join(home, ".copilot"), "mcp-config.json"),
            "Crush": (home, "crush.json"),
            "Augment Code": (os.path.join(app_support, "Code", "User"), "settings.json"),
            "Qodo Gen": (os.path.join(app_support, "Code", "User"), "settings.json"),
            "BoltAI": (os.path.join(app_support, "BoltAI"), "config.json"),
            "Perplexity": (os.path.join(app_support, "Perplexity"), "mcp_config.json"),
            "Warp": (os.path.join(home, ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(home, ".aws", "amazonq"), "mcp_config.json"),
            "Opencode": (os.path.join(home, ".opencode"), "mcp_config.json"),
            "Kiro": (os.path.join(home, ".kiro"), "mcp_config.json"),
            "Trae": (os.path.join(home, ".trae"), "mcp_config.json"),
            "VS Code": (os.path.join(app_support, "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(app_support, "Code - Insiders", "User"), "settings.json"),
        }
    elif sys.platform == "linux":
        home = os.path.expanduser("~")
        config = os.path.join(home, ".config")
        return {
            "Cline": (
                os.path.join(config, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(config, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(config, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"),
                "mcp_settings.json",
            ),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(home, ".codex"), "config.toml"),
            "Antigravity IDE": (os.path.join(home, ".gemini", "antigravity"), "mcp_config.json"),
            "Zed": (os.path.join(config, "zed"), "settings.json"),
            "Gemini CLI": (os.path.join(home, ".gemini"), "settings.json"),
            "Qwen Coder": (os.path.join(home, ".qwen"), "settings.json"),
            "Copilot CLI": (os.path.join(home, ".copilot"), "mcp-config.json"),
            "Crush": (home, "crush.json"),
            "Augment Code": (os.path.join(config, "Code", "User"), "settings.json"),
            "Qodo Gen": (os.path.join(config, "Code", "User"), "settings.json"),
            "Warp": (os.path.join(home, ".warp"), "mcp_config.json"),
            "Amazon Q": (os.path.join(home, ".aws", "amazonq"), "mcp_config.json"),
            "Opencode": (os.path.join(home, ".opencode"), "mcp_config.json"),
            "Kiro": (os.path.join(home, ".kiro"), "mcp_config.json"),
            "Trae": (os.path.join(home, ".trae"), "mcp_config.json"),
            "VS Code": (os.path.join(config, "Code", "User"), "settings.json"),
            "VS Code Insiders": (os.path.join(config, "Code - Insiders", "User"), "settings.json"),
        }
    else:
        return {}


# Clients with non-standard JSON key structures
_SPECIAL_JSON_STRUCTURES = {
    "VS Code": ("mcp", "servers"),
    "VS Code Insiders": ("mcp", "servers"),
    "Visual Studio 2022": (None, "servers"),
}


def _read_config_file(config_path: str, is_toml: bool, name: str, quiet: bool):
    """Read and parse a config file. Returns None on error."""
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "rb" if is_toml else "r", encoding=None if is_toml else "utf-8") as f:
        if is_toml:
            data = f.read()
            if len(data) == 0:
                return {}
            try:
                return tomllib.loads(data.decode("utf-8"))
            except tomllib.TOMLDecodeError:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)")
                return None
        else:
            data = f.read().strip()
            if len(data) == 0:
                return {}
            try:
                return json.loads(data)
            except json.decoder.JSONDecodeError:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                return None


def _get_mcp_servers_dict(config: dict, name: str, is_toml: bool) -> dict:
    """Navigate to the mcp_servers dict in the config, creating if needed."""
    if is_toml:
        if "mcp_servers" not in config:
            config["mcp_servers"] = {}
        return config["mcp_servers"]

    if name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[name]
        if top_key is None:
            if nested_key not in config:
                config[nested_key] = {}
            return config[nested_key]
        else:
            if top_key not in config:
                config[top_key] = {}
            if nested_key not in config[top_key]:
                config[top_key][nested_key] = {}
            return config[top_key][nested_key]

    if "mcpServers" not in config:
        config["mcpServers"] = {}
    return config["mcpServers"]


def _write_config_file(config: dict, config_path: str, config_dir: str, is_toml: bool):
    """Atomically write config file."""
    suffix = ".toml" if is_toml else ".json"
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
    try:
        with os.fdopen(fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8") as f:
            if is_toml:
                f.write(tomli_w.dumps(config).encode("utf-8"))
            else:
                json.dump(config, f, indent=2)
        os.replace(temp_path, config_path)
    except Exception:
        os.unlink(temp_path)
        raise


def install_mcp_servers(
    *,
    stdio: bool = False,
    uninstall: bool = False,
    quiet: bool = False,
    ida_host: str = "127.0.0.1",
    ida_port: int = 13337,
):
    """Install or uninstall MCP server configuration for all detected clients."""
    configs = _get_client_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        config = _read_config_file(config_path, is_toml, name, quiet)
        if config is None:
            continue

        mcp_servers = _get_mcp_servers_dict(config, name, is_toml)

        # Migrate old name
        if _OLD_SERVER_NAME in mcp_servers:
            mcp_servers[MCP_SERVER_NAME] = mcp_servers[_OLD_SERVER_NAME]
            del mcp_servers[_OLD_SERVER_NAME]

        if uninstall:
            if MCP_SERVER_NAME not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[MCP_SERVER_NAME]
        else:
            mcp_servers[MCP_SERVER_NAME] = generate_mcp_config(
                stdio=stdio, ida_host=ida_host, ida_port=ida_port
            )

        _write_config_file(config, config_path, config_dir, is_toml)

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1

    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config(ida_host, ida_port)


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    """Install or uninstall the IDA Pro plugin."""
    _validate_plugin_paths()

    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")

    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print("IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
            sys.exit(1)

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = os.path.realpath(loader_destination) if os.path.lexists(loader_destination) else None
        if loader_realpath != IDA_PLUGIN_LOADER:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)
            try:
                os.symlink(IDA_PLUGIN_LOADER, loader_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_LOADER, loader_destination)
            installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = os.path.realpath(pkg_destination) if os.path.lexists(pkg_destination) else None
        if pkg_realpath != IDA_PLUGIN_PKG:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)
            try:
                os.symlink(IDA_PLUGIN_PKG, pkg_destination)
            except OSError:
                shutil.copytree(IDA_PLUGIN_PKG, pkg_destination)
            installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")
