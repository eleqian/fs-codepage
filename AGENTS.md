# AGENTS.md

独立 Atmosphère 系统模块：开机一次，把 fs 进程里的 CP932(Shift-JIS) 代码页转换例程替换为
UTF-8 <-> UTF-16，让 FAT/exFAT 卷支持中文等 3 字节 UTF-8 文件名。C++23 on devkitPro/libnx，aarch64。

与 `impeeza/sys-patch` **无源码依赖**：本工程是它的姊妹模块，补丁站点与 upstream 的 fs 条目
（noacidsigchk/noncasigchk/nocntchk）函数级不相交，可并存安装。

## Layout

- `sysmod/` — 系统模块（title `42000000000000E0`）。
  - `src/main.cpp` —— 本工程骨架：配置、调度（fs 调试器互斥 ⇒ 退避重试）、日志。
  - `src/fs_codepage.cpp` —— 补丁本体（表 + 7 个替换体），API `src/fs_codepage.h`，
    共享 pattern/patch 基元 `src/patch_types.h`。
  - `tools/check_patch_sizes.py` —— 构建期守卫。
  - `fs-codepage.json`（NPDM）/ `toolbox.json` / `Makefile`（`TARGET=fs-codepage`、`TITLE_ID`）。
- `common/minIni/` — INI 库（与 sys-patch 同源）。
- `fs_encode_fix/` — 逆向笔记 / 设计文档 / 离线工具（**文档，不参与构建**），索引见其 `README.md`。
  根目录另有 `补丁点合并优化分析.md`（设计现状 + 决策台账）、`M6_Ghidra反编译报告.md`、`plan.md`。
- `.workbuddy/memory/` — 逐日工作日志 + `MEMORY.md`（长期备忘，先读它）。
- 运行时配置 `/config/fs-codepage/config.ini`，日志 `/config/fs-codepage/log.ini`。

## Build

- 从**仓库根** `make`（只管 sysmod，产物收进 `out/`）；`make dist` 额外出 `fs-codepage-sysmodule.zip`。
- 本机构建进 devkitPro 自带的 msys2 登录 shell：
  `C:\devkitPro\msys2\usr\bin\bash.exe -lc 'cd /d/Design/NS/fs-codepage && make' > _build.log 2>&1`
  （它的 PATH 带 `/opt/devkitpro/tools/bin`；直连 IDE shell 取不到 stdout）。
- 每次构建自动跑 `sysmod/tools/check_patch_sizes.py`（也 `make check-patch-sizes`）：校验 7 个 fs 替换体
  （label delta == ELF 符号尺寸 且 ≤ 该点洞）、**从源码文本**解析 fs 补丁表、位置无关性。
  **任一失败即构建失败**；正则解析不到的条目会被**静默跳过**，所以表条目必须保持原格式。
- sysmod 需要 **`-fno-toplevel-reorder`**（在 `sysmod/Makefile`）：否则 GCC 把顶层 asm 排到延迟函数体之前，
  算出的补丁尺寸为 0。

## Hard invariants

- **ASLR discipline.** 替换体被原样拷进 fs 地址空间、基址随机 ⇒ 必须位置无关且自包含：
  不得出现绝对地址物化、外部调用、字面量池、`&function`。
- **Never hardcode an fs offset or global.** 一切靠字节模式定位；随版本变化的值（代码页 ctx 槽、
  一个外部 callee）由哨兵 `0xDEAD0001/2`、`0xDEAD0003/4` 在打补丁时从原函数体收割，
  **收割失败该点整组放弃**（不写任何字节）。
- **Pattern notation.** 表与 `patch_types.h` 用 `.` = 一个通配字节；离线脚本/JSON 用 `..` = 一个通配字节。
  两种写法**不要混**，混了会整表 0 命中。
- **No per-entry gating.** 整份生效或整份跳过（`[options] fs_codepage=0`），没有中间态 ——
  半成品的 fs 会挂（换了转换器却没打配对的宽度钳制 ⇒ `FAT_MakeShortName` 死循环）。
- **Never hand-edit machine code** in the replacement bodies —— 只做语义等价改写，
  并复验 7 个替换体尺寸逐位不变。
- **四文件与 sys-patch fork 逐字节同步**（`fs_codepage.cpp/.h`、`patch_types.h`、`check_patch_sizes.py`）：
  fork 侧表有更新就重新复制；复制后本工程的 `main.cpp` 不动。

## Docs

文档与历史 **在本仓库**（2026-09-29 从 `D:/Design/NS/sys-patch` 的 `dev/fs-codepage` 分支迁来，
原工程不再同步）。入口：

| 要什么 | 读哪 |
|---|---|
| 功能/配置/构建/共存 | `README.md` |
| 方案与实现的唯一权威 | `fs_encode_fix/re_utf8_patch_final.md` |
| 文档层级 L0–L5 | `fs_encode_fix/README.md` |
| 设计现状 + 决策台账 | `补丁点合并优化分析.md` |
| 演进史（裸写 `§N` 指它） | `fs_encode_fix/补丁点合并优化分析·演进史.md` |
| 硬约束速查 + 坑 | `.workbuddy/memory/MEMORY.md` |
