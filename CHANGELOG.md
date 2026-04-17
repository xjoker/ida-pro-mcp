# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## 1.2.0 (2026-04-17)

### Features

- 异步任务队列：`task_submit` / `task_poll` / `task_list`，重度工具（反编译、`analyze_funcs`、`find_paths`、`callgraph` 等）可提交后台执行，客户端 2-3 秒轮询，彻底避免传输层超时
  - worker 线程走 `registry.dispatch("tools/call")` 完整管线 — unsafe 门、extension 门、输出截断/缓存一致
  - 请求作用域的 thread-local（`_enabled_extensions` / `_transport_session_id`）捕获后在 worker 线程重放
  - 完成任务 TTL 5 分钟，ID 使用完整 UUID + 锁内重试防碰撞

### Bug Fixes

- **MCP 连接稳定性**（IDA 主线程被分析/重度反编译占用时连接假死的根因修复）
  - 代理 HTTP 超时 30s → 180s（server.py）
  - `_sync_wrapper` 的 `res_container.get()` 增加 150s 上界，防止 IDA 主线程卡住导致 HTTP handler 线程无限阻塞（sync.py）
  - 超时次序：proxy 180s > IDA 内层 150s > 工具执行 60s，保证 IDASyncError 能透传到客户端
  - 连接池存活检测改用 `conn.sock.fileno()` 真正验证 socket 状态（原 `conn.sock` 属性访问永不抛异常）
- **吸收上游稳定性修复**（5 处，经 Codex 逐条核对确认存在）
  - 注册 `notifications/initialized` 通知处理器，消除标准 MCP 客户端握手时的 "method not found" 报错日志
  - 模块加载时设置 `SIGPIPE=SIG_IGN`，防止客户端断线时 IDA 主进程被信号杀掉
  - `read_bytes_bss_safe` / `read_int_bss_safe`：按字节 `is_loaded()` 门控，修复读 `.bss` 全局变量时返回 0xFF 哨兵的 bug（`get_bytes`/`get_int`/`get_global_value` 受影响）
  - `decompile_function_safe` 调用 `get_line_item` 时为 head/tail 输出参数分配 `ctree_item_t`，防止空指针崩溃
  - `parse_address` 在 hex/decimal 解析失败时回退到 `idaapi.get_name_ea` 解析符号名，统一"地址或名称"语义（`xrefs_to`/`callees`/`basic_blocks` 等工具现在真正支持传函数名）

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
