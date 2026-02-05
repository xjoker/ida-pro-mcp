# IDA Pro MCP (Enhanced Fork)

[中文文档](https://github.com/xjoker/ida-pro-mcp/blob/main/README_zh.md) | English

[![PyPI](https://img.shields.io/pypi/v/ida-pro-mcp-xjoker)](https://pypi.org/project/ida-pro-mcp-xjoker/)
[![Python](https://img.shields.io/pypi/pyversions/ida-pro-mcp-xjoker)](https://pypi.org/project/ida-pro-mcp-xjoker/)

An enhanced fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) - MCP Server for LLM-assisted reverse engineering in IDA Pro.

## What's Different from Original

| Feature | Original | This Fork |
|---------|----------|-----------|
| **Multi-instance Support** | ❌ Port conflict crashes | ✅ Auto port increment (13337→13346) |
| **Web Configuration** | ❌ None | ✅ Bilingual UI at `/config.html` |
| **API Key Auth** | ❌ None | ✅ Bearer token + env var support |
| **Server Startup** | Manual hotkey | ✅ Auto-start on IDA launch |
| **Hotkey Conflicts** | Occupies Ctrl+Alt+M | ✅ No hotkey, menu-only |
| **Config Persistence** | None | ✅ Saved per IDB database |

### Key Enhancements

- **Port Conflict Auto-Retry**: Multiple IDA instances automatically use different ports
- **Web Config UI**: `http://localhost:13337/config.html` with English/中文 interface
- **API Key Authentication**: Secure remote access with Bearer token
- **Bug Fixes**: Thread safety, regex handling, type parsing errors fixed

## Installation

```bash
pip install ida-pro-mcp-xjoker
ida-pro-mcp --install
```

Restart IDA Pro completely after installation.

## Quick Start

1. Open a binary in IDA Pro
2. MCP server starts automatically on `http://127.0.0.1:13337`
3. Configure your MCP client:

```bash
# Claude Code
claude mcp add ida-pro-mcp http://127.0.0.1:13337/mcp

# With API Key authentication
claude mcp add --transport http ida-pro-mcp http://127.0.0.1:13337/mcp \
  --header "Authorization: Bearer your-api-key"
```

4. Open web config at `http://127.0.0.1:13337/config.html` to customize settings

## Requirements

- Python 3.11+
- IDA Pro 8.3+ (9.0 recommended), **IDA Free not supported**
- Any [MCP-compatible client](https://modelcontextprotocol.io/clients)

## API Overview

**71 MCP Tools** including:

| Category | Tools |
|----------|-------|
| Analysis | `decompile`, `disasm`, `xrefs_to`, `callees`, `callers`, `basic_blocks` |
| Memory | `get_bytes`, `get_string`, `get_int`, `patch` |
| Types | `declare_type`, `set_type`, `infer_types`, `read_struct` |
| Modify | `set_comments`, `rename`, `patch_asm` |
| Search | `find_bytes`, `find_insns`, `find_regex` |
| Debug | `dbg_*` (20+ debugger tools, enable with `?ext=dbg`) |
| Python | `py_eval` - execute Python in IDA context |

**24 MCP Resources** for read-only access:
- `ida://idb/metadata`, `ida://cursor`, `ida://structs`, `ida://xrefs/from/{addr}`, etc.

## Headless Mode

```bash
# SSE transport
ida-pro-mcp --transport http://127.0.0.1:8744/sse

# With idalib (no GUI)
idalib-mcp --host 127.0.0.1 --port 8745 /path/to/binary
```

## Links

- [Original Project](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- [Changelog](https://github.com/xjoker/ida-pro-mcp/blob/main/CHANGELOG.md)
- [Issues](https://github.com/xjoker/ida-pro-mcp/issues)

## License

MIT - Same as original project
