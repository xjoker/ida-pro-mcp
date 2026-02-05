"""端口冲突自动递增工具

多个 IDA Pro 实例同时加载 MCP 插件时，提供端口自动递增重试功能。
"""

import errno
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .zeromcp.mcp import McpServer

logger = logging.getLogger(__name__)

# 端口已占用的 errno 值（跨平台）
# macOS: 48, Linux: 98, Windows: 10048
_ADDR_IN_USE_ERRNOS = {errno.EADDRINUSE, 48, 98, 10048}

DEFAULT_MAX_RETRIES = 10


def try_serve_with_port_retry(
    mcp_server: "McpServer",
    host: str,
    base_port: int,
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    request_handler=None,
) -> tuple[int, list[int]]:
    """尝试启动 MCP 服务器，端口冲突时自动递增重试。

    Args:
        mcp_server: McpServer 实例
        host: 绑定地址
        base_port: 起始端口
        max_retries: 最大重试次数（包含首次尝试共 max_retries 次）
        request_handler: HTTP 请求处理器类

    Returns:
        (actual_port, failed_ports) 元组：
        - actual_port: 实际绑定成功的端口
        - failed_ports: 绑定失败的端口列表（为空表示首次即成功）

    Raises:
        OSError: 所有端口尝试均失败，或遇到非端口冲突的错误
    """
    kwargs = {}
    if request_handler is not None:
        kwargs["request_handler"] = request_handler

    failed_ports: list[int] = []
    last_error: OSError | None = None

    for i in range(max_retries):
        port = base_port + i
        if port > 65535:
            break
        try:
            mcp_server.serve(host, port, **kwargs)
            return port, failed_ports
        except OSError as e:
            if e.errno in _ADDR_IN_USE_ERRNOS:
                logger.debug(f"Port {port} in use, trying next")
                failed_ports.append(port)
                last_error = e
            else:
                # 非端口冲突错误，立即抛出
                raise

    # 所有端口都失败了
    assert last_error is not None
    raise last_error


def format_port_exhausted_message(
    host: str, base_port: int, failed_ports: list[int]
) -> str:
    """生成端口耗尽时的用户友好提示信息。

    Args:
        host: 绑定地址
        base_port: 起始端口
        failed_ports: 尝试失败的端口列表

    Returns:
        格式化的错误提示字符串
    """
    if not failed_ports:
        return f"[MCP] Error: Could not bind to port on {host}"

    first = failed_ports[0]
    last = failed_ports[-1]
    ports_str = ", ".join(str(p) for p in failed_ports)

    return (
        f"[MCP] Error: Could not find an available port.\n"
        f"  Tried ports: {ports_str}\n"
        f"  All ports in range {first}-{last} are in use.\n"
        f"\n"
        f"  To manually set a different port, run in IDA Python console:\n"
        f"    from ida_mcp.http import set_server_config\n"
        f"    set_server_config({{'host': '{host}', 'port': 15000}})\n"
        f"  Then toggle: Edit -> Plugins -> MCP Server"
    )
