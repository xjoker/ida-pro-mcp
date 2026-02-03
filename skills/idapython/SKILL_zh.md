---
name: idapython
description: IDA Pro Python 逆向工程脚本。用于编写 IDAPython 脚本、分析二进制文件、使用 IDA 的反汇编、反编译（Hex-Rays）、类型系统、交叉引用、函数、段或任何 IDA 数据库操作的 API。涵盖 ida_* 模块（50+）、idautils 迭代器和常用模式。
---

# IDAPython

使用现代 `ida_*` 模块。避免使用旧版 `idc` 模块。

## 模块路由表

| 任务 | 模块 | 关键项 |
|------|------|--------|
| 字节/内存 | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| 函数 | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| 名称 | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| 类型 | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| 反编译器 | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| 段 | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| 交叉引用 | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| 指令 | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| 栈帧 | `ida_frame` | `get_frame`, `define_stkvar` |
| 迭代 | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| UI/对话框 | `ida_kernwin` | `msg`, `ask_*`, `jumpto`, `Choose` |
| 数据库信息 | `ida_ida` | `inf_get_*`, `inf_is_64bit()` |
| 分析 | `ida_auto` | `auto_wait`, `plan_and_wait` |
| 流程图 | `ida_gdl` | `FlowChart`, `BasicBlock` |
| 寄存器跟踪 | `ida_regfinder` | `find_reg_value`, `reg_value_info_t` |

## 核心代码模式

### 遍历函数
```python
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
```

### 遍历函数中的指令
```python
for head in idautils.FuncItems(func_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, head):
        print(f"{head:#x}: {insn.itype}")
```

### 交叉引用
```python
for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### 读写字节
```python
data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### 名称操作
```python
name = ida_name.get_name(ea)
ida_name.set_name(ea, "new_name", ida_name.SN_NOCHECK)
```

### 反编译函数
```python
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # 伪代码
    for lvar in cfunc.lvars:
        print(f"{lvar.name}: {lvar.type()}")
```

### 遍历 ctree（反编译 AST）
```python
class MyVisitor(ida_hexrays.ctree_visitor_t):
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            print(f"Call at {e.ea:#x}")
        return 0

cfunc = ida_hexrays.decompile(ea)
MyVisitor().apply_to(cfunc.body, None)
```

### 应用类型
```python
tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

### 创建结构体
```python
udt = ida_typeinf.udt_type_data_t()
m = ida_typeinf.udm_t()
m.name = "field1"
m.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
m.offset = 0
m.size = 4
udt.push_back(m)
tif = ida_typeinf.tinfo_t()
tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
tif.set_named_type(ida_typeinf.get_idati(), "MyStruct")
```

### 字符串列表
```python
for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")
```

### 等待分析完成
```python
ida_auto.auto_wait()  # 阻塞直到自动分析完成
```

## 关键常量

| 常量 | 值/用途 |
|------|---------|
| `BADADDR` | 无效地址哨兵值 |
| `ida_name.SN_NOCHECK` | 跳过名称验证 |
| `ida_typeinf.TINFO_DEFINITE` | 强制应用类型 |
| `o_reg`, `o_mem`, `o_imm`, `o_displ`, `o_near` | 操作数类型 |
| `dt_byte`, `dt_word`, `dt_dword`, `dt_qword` | 数据类型 |
| `fl_CF`, `fl_CN`, `fl_JF`, `fl_JN`, `fl_F` | 代码交叉引用类型 |
| `dr_R`, `dr_W`, `dr_O` | 数据交叉引用类型 |

## 重要规则

1. **绝对不要手动进行十六进制/十进制转换** — 使用 `int_convert` MCP 工具
2. **等待分析**：在读取结果前调用 `ida_auto.auto_wait()`
3. **线程安全**：IDA SDK 调用必须在主线程运行（使用 `@idasync`）
4. **64 位地址**：始终假设 `ea_t` 可能是 64 位

## 反模式

| 避免 | 应该这样做 |
|------|------------|
| `idc.*` 函数 | 使用 `ida_*` 模块 |
| 硬编码地址 | 使用名称、模式或交叉引用 |
| 手动十六进制转换 | 使用 `int_convert` 工具 |
| 阻塞主线程 | 对长时间操作使用 `execute_sync()` |
| 猜测类型 | 从反汇编/反编译推导 |

## 详细 API 参考

有关任何模块的详细文档，请阅读 `docs/<module>.md`：
- **高频使用**：`ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_name`, `idautils`
- **中频使用**：`ida_segment`, `ida_xref`, `ida_ua`, `ida_frame`, `ida_kernwin`
- **专用**：`ida_dbg`（调试器）、`ida_nalt`（netnode 存储）、`ida_regfinder`（寄存器跟踪）

来自 hex-rays.com 的完整 RST 源文件可在 `docs/<module>.rst` 获取。
