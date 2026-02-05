# IDA Pro MCP（增强 Fork 版）

English | [中文文档](https://github.com/xjoker/ida-pro-mcp/blob/main/README_zh.md)

[![PyPI](https://img.shields.io/pypi/v/ida-pro-mcp-xjoker)](https://pypi.org/project/ida-pro-mcp-xjoker/)
[![Python](https://img.shields.io/pypi/pyversions/ida-pro-mcp-xjoker)](https://pypi.org/project/ida-pro-mcp-xjoker/)

[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的增强 fork 版本 - 用于 IDA Pro 中 LLM 辅助逆向工程的 MCP 服务器。

## 与原版的区别

| 功能 | 原版 | 本 Fork |
|------|------|---------|
| **多实例支持** | ❌ 端口冲突崩溃 | ✅ 自动端口递增 (13337→13346) |
| **Web 配置界面** | ❌ 无 | ✅ 双语 UI `/config.html` |
| **API Key 认证** | ❌ 无 | ✅ Bearer token + 环境变量支持 |
| **服务器启动** | 手动快捷键 | ✅ IDA 启动自动加载 |
| **快捷键冲突** | 占用 Ctrl+Alt+M | ✅ 无快捷键，仅菜单 |
| **配置持久化** | 无 | ✅ 每个 IDB 数据库独立保存 |

### 核心增强

- **端口冲突自动重试**：多个 IDA 实例自动使用不同端口
- **Web 配置界面**：`http://localhost:13337/config.html` 支持中英文切换
- **API Key 认证**：Bearer token 支持安全远程访问
- **Bug 修复**：线程安全、正则处理、类型解析错误已修复

## 安装

```bash
pip install ida-pro-mcp-xjoker
ida-pro-mcp --install
```

安装后请完全重启 IDA Pro。

## 快速开始

1. 在 IDA Pro 中打开二进制文件
2. MCP 服务器自动启动在 `http://127.0.0.1:13337`
3. 配置你的 MCP 客户端：

```bash
# Claude Code
claude mcp add ida-pro-mcp http://127.0.0.1:13337/mcp

# 带 API Key 认证
claude mcp add --transport http ida-pro-mcp http://127.0.0.1:13337/mcp \
  --header "Authorization: Bearer your-api-key"
```

4. 打开 `http://127.0.0.1:13337/config.html` 自定义设置

## 环境要求

- Python 3.11+
- IDA Pro 8.3+（推荐 9.0），**不支持 IDA Free**
- 任意 [MCP 兼容客户端](https://modelcontextprotocol.io/clients)

## API 概览

**71 个 MCP 工具**：

| 分类 | 工具 |
|------|------|
| 分析 | `decompile`, `disasm`, `xrefs_to`, `callees`, `callers`, `basic_blocks` |
| 内存 | `get_bytes`, `get_string`, `get_int`, `patch` |
| 类型 | `declare_type`, `set_type`, `infer_types`, `read_struct` |
| 修改 | `set_comments`, `rename`, `patch_asm` |
| 搜索 | `find_bytes`, `find_insns`, `find_regex` |
| 调试 | `dbg_*`（20+ 调试器工具，使用 `?ext=dbg` 启用） |
| Python | `py_eval` - 在 IDA 上下文中执行 Python |

**24 个 MCP 资源**（只读访问）：
- `ida://idb/metadata`, `ida://cursor`, `ida://structs`, `ida://xrefs/from/{addr}` 等

## 无头模式

```bash
# SSE 传输
ida-pro-mcp --transport http://127.0.0.1:8744/sse

# 使用 idalib（无 GUI）
idalib-mcp --host 127.0.0.1 --port 8745 /path/to/binary
```

## 链接

- [原项目](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- [更新日志](https://github.com/xjoker/ida-pro-mcp/blob/main/CHANGELOG.md)
- [问题反馈](https://github.com/xjoker/ida-pro-mcp/issues)

## 许可证

MIT - 与原项目相同
