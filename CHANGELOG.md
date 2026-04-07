# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## 1.1.0 (2026-04-07)

### Features

- 传输层加固：支持 chunked transfer encoding、gzip/deflate 请求解压、SSE 断连检测
- 跨实例代理：`list_instances`/`select_instance` 工具，一个 MCP server 管理多个 IDA 实例
- idalib 隔离上下文：per-transport-session 自动切换数据库
- 新增 15 个分析工具：
  - 复合分析：`analyze_function`, `analyze_component`, `analyze_batch`
  - 二进制摘要：`survey_binary`
  - 高级查询：`insn_query`, `xref_query`, `func_profile`
  - 类型操作：`enum_upsert`, `type_query`, `type_inspect`
  - 代码定义：`define_func`, `define_code`, `undefine`, `append_comments`
  - Python：`py_exec_file`
- Token 优化：移除冗余字段，paginate 加 truncated 标记
- 76 个 MCP 工具 + 11 个资源（11 个 API 模块）

### Refactoring

- 安装逻辑提取到独立 `installer.py` 模块（server.py 1061→402 行）
- 默认工具超时从 15s 提升到 60s
- Windows 平台启用 SO_EXCLUSIVEADDRUSE 防止端口劫持

### Bug Fixes

- 修复 dispatch_proxy 未拦截本地工具（tools/list 合并、tools/call 分流）
- 修复 xref/string/constant 字段名不匹配
- 修复 pattern_filter 参数顺序错误
- 修复 chunked 413 后连接状态污染
- 修复 idalib session manager 多处状态一致性问题
- 修复 _output_cache 线程安全问题

## 1.0.1 (2026-02-05)

### Features

- 端口冲突自动递增：多 IDA 实例同时运行时自动选择可用端口
- API Key 认证支持
- Web 配置界面（双语 EN/中文）
- 服务器管理器支持多实例
- 71 个 MCP 工具 + 24 个资源

### Fork Enhancements

- 从 mrexodia/ida-pro-mcp fork 并增强
- 性能优化提升响应速度
- 完善的错误处理和用户提示
