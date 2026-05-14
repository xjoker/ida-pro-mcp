# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## 1.3.0 (2026-05-14)

本次发布从 upstream `mrexodia/ida-pro-mcp` 选择性吸收 211 个新提交（不做整体 merge），通过 Agent Team 并行执行 6 个 wave 完成。零新增 lint 错误，全部 50 个 .py 文件语法校验通过，新增 58+ 个回归测试。

### Features

- **签名生成（sigmaker）** — 移植 upstream vendored sigmaker 引擎，新增 `make_signature` / `find_signature` 工具，用于生成可跨 IDB 复用的字节签名（无需 pip 依赖，MIT 许可）
- **`search_text` 工具** — 在反汇编与注释中混合搜索文本（#67 from upstream），底层 hybrid `find_text + generate_disassembly`，兼容 IDA 8.x/9.x
- **`decompile` 新增 `include_addresses` 标志** — 默认 `True`（向后兼容）；设 `False` 时剥离每行地址标记，大幅降低 token 消耗（#169 from upstream）
- **disasm/decompile 输出增强** — 新增 `refs` 字段（labels/comments/cross-refs），`disasm` 顶层附加 `segment` 字段，便于 LLM 理解上下文（#367 from upstream）
- **Trace 持久化系统** — 每次 `tools/call` 写入 IDB netnode（分段批处理 + 启动时 flush），可通过 `ida-mcp-trace-dump` CLI 脚本导出为 JSONL；环境变量 `IDA_MCP_TRACE=0` 关闭
- **IDA 8.3/8.4/8.5/9.0 兼容层** — 新增 `compat.py`，统一处理跨版本 API 差异（`tinfo_get_udm`、`parse_decl` 返回值、`make_bytes_searcher`/`raw_bin_search`、entry-point API 等），IDA 9.0 SP0 缺失 API 时启动期主动报错而非运行期崩

### Bug Fixes

- **`call_stack` 死锁修复（#406 from upstream）** — 重入 `@idasync` 时检测当前线程，已在 IDA main thread 则直接调用，避免 `res_container.get()` 自死锁。我们的异步任务队列受益匪浅
- **`dbg_start` 系列修复（#400/#401/#402 from upstream）**
  - 修复成功启动时被误报失败（DBG_Hooks 状态机）
  - 恢复调用方调用前的 batch 状态，不再硬编码归零
  - IP grace 处理精细化（异步启动 + 批处理状态保存/恢复）
- **`find_bytes` / `find` IDA 9.0 兼容（#345 from upstream）** — 用 `compat.make_bytes_searcher` / `raw_bin_search` 替换被移除的 API
- **`parse_decl` IDA 9.0+ 返回值检查（#317 from upstream）** — 改为 `is not None`，避免 `signed __int64` / `unsigned __int64` 类型表项被误判为失败
- **HTTP `Host` / `Origin` 校验（#352 from upstream）** — 浏览器场景下抵御 DNS rebinding；非浏览器 transport 不受影响
- **MCP 输出 schema 修复**
  - union-shaped 工具结果的 root type（#357/#369 from upstream）—— 用 `anyOf` 而非裸 union
  - 截断元数据不再污染 list/dict 结构（#361 from upstream）—— `truncated` 字段从内嵌改为外层包装
  - schema-invalid 截断在大输出时不再破坏协议（#365 from upstream）
- **HTTP session 重注册** — reconnect 场景下旧 session 状态正确清理（#b46c146 from upstream）
- **`idalib_session_manager` 加固（吸收 upstream supervisor 修复思路，但保留我们的单进程切换 IDB 架构）**
  - TOCTOU 竞态：`ensure_context_for_transport` 引入 `_switch_lock`，check-and-switch 原子化
  - `_transport_bindings` 改为 `OrderedDict` LRU，上限 256 防无限增长
  - `idapro.open/close_database` 失败时用 `try/finally` 强制回滚 `_current_session_id`
  - `auto_wait` 加 300s 主线程超时，避免大型二进制阻塞所有 transport

### Breaking Changes

- **`disasm.lines` 输出格式** — 由原来的单一字符串（`"funcname (seg @ 0xN):\\n<asm>"`）改为结构化 dict 列表，每项含 `addr` / `text` / `label` / `comments` / `refs`。`asm.name` / `asm.start_ea` 字段保持不变。下游 MCP 客户端如直接解析旧字符串需适配

### Testing

- 新增 58+ 个回归测试，分布在：
  - `tests/test_output_schema.py`（19 个） — MCP outputSchema wrapping + union root type
  - `tests/test_browser_transport_guards.py`（6 个） — Host/Origin 校验
  - `tests/test_session_manager_concurrent.py`（15 个） — TOCTOU + LRU + try/finally + auto_wait timeout
  - `tests/test_trace.py`（18 个） — round-trip + 多分段 + 批处理阈值 + shutdown flush
- 测试无需 IDA 安装（通过 `idapro` / `ida_auto` stub 注入）

### Decision Records

- **不**采用 upstream `idalib_supervisor` 架构（advisor 评审 2026-05-14）—— MCP 单用户场景串行切换 IDB 够用，supervisor 的 N×IDA 内存代价不划算，且我们 `transport_bindings + context hooks` 设计的可控性更高

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
