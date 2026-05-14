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
| **Multi-Host Deployment** | ❌ Single machine only | ✅ Coordinator + Worker Pool + Redis (v1.4 preview) |

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

**80+ MCP Tools** including:

| Category | Tools |
|----------|-------|
| Analysis | `decompile` (含 `include_addresses` 标志), `disasm` (含 labels/comments/refs), `xrefs_to`, `callees`, `basic_blocks`, `insn_query`, `xref_query`, `func_profile` |
| Composite | `analyze_function`, `analyze_batch`, `analyze_component`, `survey_binary` |
| Memory | `get_bytes`, `get_string`, `get_int`, `patch` |
| Types | `declare_type`, `set_type`, `infer_types`, `enum_upsert`, `type_query`, `type_inspect` |
| Modify | `set_comments`, `append_comments`, `rename`, `patch_asm`, `define_func`, `define_code`, `undefine` |
| Search | `find_bytes`, `find_insns`, `find_regex`, `search_text` |
| Signature | `make_signature`, `find_signature` (sigmaker) |
| Debug | `dbg_*` (20+ debugger tools, enable with `?ext=dbg`) |
| Python | `py_eval`, `py_exec_file` |
| Multi-Instance | `list_instances`, `select_instance` |
| Trace | `ida-mcp-trace-dump` CLI (导出 JSONL，环境变量 `IDA_MCP_TRACE=0` 关闭) |

**11 MCP Resources** for read-only access:
- `ida://idb/metadata`, `ida://cursor`, `ida://structs`, `ida://xrefs/from/{addr}`, etc.

## Headless Mode

```bash
# SSE transport
ida-pro-mcp --transport http://127.0.0.1:8744/sse

# With idalib (no GUI)
idalib-mcp --host 127.0.0.1 --port 8745 /path/to/binary
```

## Multi-Host Deployment (v1.4 preview)

Coordinator + Worker Pool + Redis architecture for horizontal scaling.

```bash
# 1. Start Redis on a shared host
docker run -d -p 6379:6379 redis:7-alpine

# 2. Start workers on each IDA host (auto register to Redis)
idalib-mcp --host 0.0.0.0 --port 13337 \
  --registry-url redis://redis-host:6379/0 \
  /path/to/binary.idb

# 3. Start Coordinator (single entry point for MCP clients)
ida-mcp-coordinator --host 0.0.0.0 --port 9000 \
  --registry-url redis://redis-host:6379/0

# 4. Point MCP clients at the Coordinator
# Coordinator routes by IDB affinity + load balancing.
```

Optional: enable cross-host shared task queue:
```bash
export IDA_MCP_TASKS_BACKEND=redis
export IDA_MCP_REGISTRY_REDIS_URL=redis://redis-host:6379/0
```

Backward compatible: omit `--registry-url` to run single-host as before.

## Links

- [Original Project](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- [Changelog](https://github.com/xjoker/ida-pro-mcp/blob/main/CHANGELOG.md)
- [Issues](https://github.com/xjoker/ida-pro-mcp/issues)

## License

MIT - Same as original project
