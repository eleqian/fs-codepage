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
- `doc/` — 设计文档 / 逆向结论（**不参与构建**），索引 `doc/README.md`。
- `scripts/` — 离线工具（固件审计、反汇编、重名检查），**不参与构建**，需时手动跑。
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
| 文档索引（先读它定方向） | `doc/README.md` |
| 方案与实现的唯一权威 | `doc/patch-design.md` |
| 设计现状 + 决策台账 | `doc/design-decisions.md` |
| 版本兼容选型 + 固件审计工具用法 | `doc/fw-compat.md` |
| 离线工具 | `scripts/`（见 `doc/README.md` 末节） |
| 硬约束速查 + 环境坑 | `.workbuddy/memory/MEMORY.md` |

过程性历史（演进史全文、逐轮 Ghidra 笔记、事故复盘、退役脚本归档）已于 2026-09-29 删除，
只保留最终设计思路与原理；原始过程见 git 历史提交 `eff8a96`，或 `D:/Design/NS/sys-patch`
的 `dev/fs-codepage` 分支。
