"""IDA MCP Configuration UI

Provides native IDA Pro dialogs for configuring MCP server instances.
Uses idaapi.Form for cross-platform compatibility.
"""

import idaapi
import logging
from typing import Optional, TYPE_CHECKING

from .config import (
    ServerInstanceConfig,
    McpConfig,
    get_config,
    save_config,
    reload_config,
)
from .server_manager import get_server_manager, ServerManager

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ServerConfigForm(idaapi.Form):
    """Form for adding/editing a server instance configuration."""

    def __init__(self, config: Optional[ServerInstanceConfig] = None):
        self.config = config
        is_new = config is None

        # Default values
        instance_id = "" if is_new else config.instance_id
        host = "127.0.0.1" if is_new else config.host
        port = 13337 if is_new else config.port
        auth_enabled = False if is_new else config.auth_enabled
        api_key = "" if is_new else (config.api_key or "")
        auto_start = False if is_new else config.auto_start

        form_template = r"""STARTITEM 0
BUTTON YES* Save
BUTTON CANCEL Cancel
{title}

<Instance ID:{iInstanceId}>
<Host:{iHost}>
<Port:{iPort}>

<Enable Authentication:{cAuthEnabled}>{cAuthGroup}>
<API Key:{iApiKey}>

<Auto-start on plugin load:{cAutoStart}>{cAutoGroup}>
"""
        title = "Add Server" if is_new else f"Edit Server: {instance_id}"

        idaapi.Form.__init__(
            self,
            form_template.format(title=title),
            {
                "iInstanceId": idaapi.Form.StringInput(value=instance_id),
                "iHost": idaapi.Form.StringInput(value=host),
                "iPort": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "cAuthGroup": idaapi.Form.ChkGroupControl(("cAuthEnabled",)),
                "iApiKey": idaapi.Form.StringInput(value=api_key),
                "cAutoGroup": idaapi.Form.ChkGroupControl(("cAutoStart",)),
            },
        )

        self._is_new = is_new

    def get_config(self) -> Optional[ServerInstanceConfig]:
        """Get the configured ServerInstanceConfig after form execution."""
        instance_id = self.iInstanceId.value.strip()
        if not instance_id:
            return None

        return ServerInstanceConfig(
            instance_id=instance_id,
            host=self.iHost.value.strip() or "127.0.0.1",
            port=self.iPort.value or 13337,
            enabled=True,
            auth_enabled=bool(self.cAuthGroup.value & 1),
            api_key=self.iApiKey.value.strip() or None,
            auto_start=bool(self.cAutoGroup.value & 1),
        )


class ServerListChooser(idaapi.Choose):
    """Chooser widget for displaying and selecting server instances."""

    def __init__(self, manager: ServerManager, title: str = "MCP Servers"):
        columns = [
            ["ID", 15],
            ["Address", 25],
            ["Status", 12],
            ["Auth", 8],
        ]
        idaapi.Choose.__init__(
            self,
            title,
            columns,
            flags=idaapi.Choose.CH_MODAL | idaapi.Choose.CH_CAN_DEL,
        )
        self.manager = manager
        self._items: list[tuple[str, str, str, str]] = []
        self._refresh()

    def _refresh(self) -> None:
        """Refresh the list of servers."""
        self._items = []
        for instance_id, status in self.manager.get_status().items():
            self._items.append((
                instance_id,
                status["address"],
                status["status"],
                "Yes" if status["auth_enabled"] else "No",
            ))

    def OnGetSize(self) -> int:
        return len(self._items)

    def OnGetLine(self, n: int) -> list[str]:
        if 0 <= n < len(self._items):
            return list(self._items[n])
        return ["", "", "", ""]

    def OnDeleteLine(self, n: int) -> int:
        """Handle delete action."""
        if 0 <= n < len(self._items):
            instance_id = self._items[n][0]
            if self.manager.remove_server(instance_id):
                self._refresh()
                return n
        return -1

    def OnRefresh(self, n: int) -> int:
        self._refresh()
        return n

    def get_selected_id(self, n: int) -> Optional[str]:
        """Get the instance ID at the given index."""
        if 0 <= n < len(self._items):
            return self._items[n][0]
        return None


class McpConfigDialog(idaapi.Form):
    """Main configuration dialog for MCP servers."""

    def __init__(self):
        form_template = r"""STARTITEM 0
BUTTON YES* Close
MCP Server Configuration

{FormChangeCb}
<Server List:{cServerList}>

<Add Server:{iAddBtn}> <Start:{iStartBtn}> <Stop:{iStopBtn}> <Edit:{iEditBtn}>

<Tool Timeout (sec):{iTimeout}>
<Debug Mode:{cDebug}>{cDebugGroup}>

<Save Config:{iSaveBtn}> <Reload Config:{iReloadBtn}>
"""

        self.manager = get_server_manager()
        self.config = get_config()

        # Create embedded chooser
        self.server_chooser = ServerListChooser(self.manager)

        idaapi.Form.__init__(
            self,
            form_template,
            {
                "FormChangeCb": idaapi.Form.FormChangeCb(self._on_form_change),
                "cServerList": idaapi.Form.EmbeddedChooserControl(self.server_chooser),
                "iAddBtn": idaapi.Form.ButtonInput(self._on_add_click),
                "iStartBtn": idaapi.Form.ButtonInput(self._on_start_click),
                "iStopBtn": idaapi.Form.ButtonInput(self._on_stop_click),
                "iEditBtn": idaapi.Form.ButtonInput(self._on_edit_click),
                "iTimeout": idaapi.Form.NumericInput(
                    value=int(self.config.tool_timeout_sec),
                    tp=idaapi.Form.FT_DEC,
                ),
                "cDebugGroup": idaapi.Form.ChkGroupControl(("cDebug",)),
                "iSaveBtn": idaapi.Form.ButtonInput(self._on_save_click),
                "iReloadBtn": idaapi.Form.ButtonInput(self._on_reload_click),
            },
        )

    def _on_form_change(self, fid: int) -> int:
        return 1

    def _get_selected_instance_id(self) -> Optional[str]:
        """Get the currently selected server instance ID."""
        sel = self.GetControlValue(self.cServerList)
        if sel is None or sel < 0:
            return None
        return self.server_chooser.get_selected_id(sel)

    def _on_add_click(self, code: int) -> int:
        """Handle Add Server button click."""
        form = ServerConfigForm()
        form.Compile()
        if form.Execute() == 1:
            new_config = form.get_config()
            if new_config:
                try:
                    self.manager.add_server(new_config)
                    self.config.add_server(new_config)
                    self.RefreshField(self.cServerList)
                    print(f"[MCP] Added server: {new_config.instance_id}")
                except ValueError as e:
                    print(f"[MCP] Error: {e}")
        form.Free()
        return 1

    def _on_start_click(self, code: int) -> int:
        """Handle Start button click."""
        instance_id = self._get_selected_instance_id()
        if instance_id:
            if self.manager.start_server(instance_id):
                self.RefreshField(self.cServerList)
        else:
            print("[MCP] No server selected")
        return 1

    def _on_stop_click(self, code: int) -> int:
        """Handle Stop button click."""
        instance_id = self._get_selected_instance_id()
        if instance_id:
            if self.manager.stop_server(instance_id):
                self.RefreshField(self.cServerList)
        else:
            print("[MCP] No server selected")
        return 1

    def _on_edit_click(self, code: int) -> int:
        """Handle Edit button click."""
        instance_id = self._get_selected_instance_id()
        if not instance_id:
            print("[MCP] No server selected")
            return 1

        instance = self.manager.get_instance(instance_id)
        if not instance:
            return 1

        form = ServerConfigForm(instance.config)
        form.Compile()
        if form.Execute() == 1:
            new_config = form.get_config()
            if new_config:
                # Update config
                was_running = instance.is_running
                if was_running:
                    self.manager.stop_server(instance_id)

                # Update instance config
                instance.config = new_config

                # Restart if was running
                if was_running:
                    self.manager.start_server(new_config.instance_id)

                self.RefreshField(self.cServerList)
                print(f"[MCP] Updated server: {new_config.instance_id}")
        form.Free()
        return 1

    def _on_save_click(self, code: int) -> int:
        """Handle Save Config button click."""
        # Update config from form values
        self.config.tool_timeout_sec = float(self.iTimeout.value or 15)
        self.config.debug = bool(self.cDebugGroup.value & 1)

        # Sync server list
        self.config.servers = [
            inst.config for inst in self.manager._instances.values()
        ]

        if save_config(self.config):
            print("[MCP] Configuration saved")
        else:
            print("[MCP] Failed to save configuration")
        return 1

    def _on_reload_click(self, code: int) -> int:
        """Handle Reload Config button click."""
        self.config = reload_config()
        self.manager.load_from_config(self.config)
        self.RefreshField(self.cServerList)
        self.SetControlValue(self.iTimeout, int(self.config.tool_timeout_sec))
        print("[MCP] Configuration reloaded")
        return 1


def show_config_dialog() -> None:
    """Show the MCP configuration dialog."""
    dialog = McpConfigDialog()
    dialog.Compile()
    dialog.Execute()
    dialog.Free()


class McpConfigAction(idaapi.action_handler_t):
    """Action handler for showing the config dialog."""

    ACTION_ID = "ida_mcp:config"
    ACTION_NAME = "MCP Configuration"
    ACTION_HOTKEY = "Ctrl+Shift+M"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx) -> int:
        show_config_dialog()
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


def register_actions() -> bool:
    """Register UI actions with IDA."""
    action_desc = idaapi.action_desc_t(
        McpConfigAction.ACTION_ID,
        McpConfigAction.ACTION_NAME,
        McpConfigAction(),
        McpConfigAction.ACTION_HOTKEY,
        "Configure MCP server instances",
        -1,
    )

    if not idaapi.register_action(action_desc):
        logger.warning("Failed to register MCP config action")
        return False

    return True


def unregister_actions() -> None:
    """Unregister UI actions from IDA."""
    idaapi.unregister_action(McpConfigAction.ACTION_ID)


__all__ = [
    "ServerConfigForm",
    "ServerListChooser",
    "McpConfigDialog",
    "show_config_dialog",
    "McpConfigAction",
    "register_actions",
    "unregister_actions",
]
