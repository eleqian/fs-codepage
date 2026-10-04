# AGENTS.md

fs-codepage：开机一次，把 fs 进程的 CP932 代码页转换换成 UTF-8 ⇄ UTF-16，让 FAT/exFAT 支持中文名。
C++23 / devkitPro + libnx，aarch64。基于 sys-patch 框架，与 upstream sys-patch 可并存（站点函数级不相交）。

## Layout

- `sysmod/src/main.cpp` —— 骨架：配置、调度（fs 调试器互斥 ⇒ 退避重试）、日志
- `sysmod/src/fs_codepage.cpp` —— 补丁本体（表 + 整函数替换体）；API `fs_codepage.h`；基元 `patch_types.h`
- `sysmod/{fs-codepage.json,toolbox.json,Makefile}` —— NPDM / Toolbox / `TARGET` 与 `TITLE_ID`
- `common/minIni/` —— INI 库
- `doc/` —— 对外文档与逆向结论（**不参与构建**），索引 `doc/README.md`；
  `doc/inner/` 是内部工作文档，**已 gitignore**
- `scripts/` —— 构建期守卫 `check_patch_sizes.py`（`make` 自动跑）+ 离线工具（手动跑）
- `.workbuddy/memory/` —— 逐日日志 + `MEMORY.md`（长期备忘，先读它）
- 运行期：配置 `/config/fs-codepage/config.ini`，日志 `/config/fs-codepage/log.ini`

## Build

- 从**仓库根** `make`（只管 sysmod，产物收进 `out/`）；`make dist` 额外出 zip。
  只跑守卫用 `make -C sysmod check-patch-sizes`（目标在 `sysmod/Makefile`，根 Makefile 没有）。
- 本机：进 devkitPro 的 msys2 登录 shell 执行（它的 PATH 才带 `/opt/devkitpro/tools/bin`）：
  `C:\devkitPro\msys2\usr\bin\bash.exe -lc 'cd /d/Design/NS/fs-codepage && make' > _build.log 2>&1`
- 守卫（每次构建自动跑，**任一失败即构建失败**）：替换体尺寸 ≤ 该补丁点的洞、位置无关、
  并从**源码文本**解析补丁表。正则解析不到的条目会被**静默跳过** ⇒ 表条目必须保持原格式。
- sysmod 需要 **`-fno-toplevel-reorder`**（在 `sysmod/Makefile`）：否则顶层 asm 被排到函数体之前，尺寸算成 0。

## Rules

改动前逐条对照：

- **ASLR discipline.** 替换体被原样拷进 fs、基址随机 ⇒ 位置无关且自包含：无绝对地址物化、
  无外部调用、无字面量池、不取函数地址。
- **不写死任何 fs 偏移 / 全局.** 定位只靠字节模板；随版本变化的值在打补丁时从被覆盖的原函数体
  **收割**（哨兵占位），**收割失败该点整组放弃**，一个字节都不写。ctx 槽判据是「候选集去重后
  恰好 1 个」，歧义仍然拒绝 —— 不要退回「见到第 2 条 adrp 就放弃」，那会被无关的 adrp 误杀。
- **收割成功 ≠ 指针可信.** 解错指针 ⇒ 替换体解引用野指针 ⇒ **fs 崩溃、只能 JIT 重新编译救砖**。
  写内存前必须过 `fs_verify_ctx_chain()`：非 0、对齐、落在 fs 基址附近的**双向**窗口内
  （单向会误杀），且该 impl 真正用到的槽同样成立；不通过 ⇒ `FAILED_HARVEST`。
  ⚠️ 这一步**无法离线求值**（kip 文件里的 GOT 槽是压缩且未重定位的），上机后必须以 `log.ini`
  里那 3 个收割点是 `Patched (sys-patch)` 而非 `Failed (fs ctx harvest)` 为准。
- **整份生效或整份跳过**（`[options] fs_codepage=0`），**没有条目级开关** —— 半成品的 fs 会挂
  （换了转换器却没打配对的宽度钳制 ⇒ `FAT_MakeShortName` 死循环）。
- **不手改替换体机器码** —— 只做语义等价改写，并复验尺寸逐位不变。
- **Pattern 只有一种写法：`..` = 一个通配字节**（单个 `.` 非法，依据 `patch_types.h::str2hex`）。
  表 / C++ / 离线脚本 / JSON **同一口径**；按「一个 `.` 一槽」写会让槽数翻倍，
  通配之后还有实字节的条目会全部 0 命中。
- **模板末尾不留 `..`**：通配槽占位但不比值，只有后面还有实字节时才构成约束
  （把后继实字节锚在正确的偏移上）；末尾通配恒真，唯一生效处是块尾越界判定
  `i + plen >= data_size`，而那是负作用（只会漏命中）。
  要消歧就补**实字节** —— 见 `fat_getnextpathcomp_10.0.0-14.1.2` 与
  `widechar_compare_12.0.0-14.1.2` 的锚注释（只放宽不补锚会有 7~8 个命中点）。
- **条目名 `fs_cp_<功能>_<版本范围>`**，版本范围 = **逐小版本实测端点**，**不按 major 写**
  （同一大版本内 fs 也会换驱动，补丁点恰好落在不变区只是运气）。族 = 版本范围之前的功能前缀。
- **改表 / 改名后必跑**（两个参数都不能省，默认值会给出**假的**改名建议 / 只验一个变体）：
  `python scripts/fs_version_matrix.py --min 10.0.0 --variant both`
  期望：**0 问题 + 每份固件全部族覆盖**。
- **`RULE_PATCHES` 只留被条目引用的规则**：对应补丁点已被整函数替换的规则**别加回来**
  （会改坏重写后的函数），守卫会报「未被任何条目引用的规则」。
- **改表的连带清单**（漏一处即静默失效）：C++ 表 + `scripts/check_patch_sizes.py` +
  `scripts/fs_fw_audit.py` —— 三处 pattern 解析口径必须同步。

## Code comments

**注释解释代码，不记录改动。** 来历是 `git log` / `blame` 的职责，写进注释只会腐烂。

- 不写：日期、「（新增）」、「原来是 X 现已改成 Y」、「别把 X 加回来（已删过一次）」。
  最后一条改写成**约束**（例：加改写规则前先确认该补丁点未被整函数替换覆盖）。
- 要写：**为什么**（依据、坑位、原版怪癖、失败形态）、**不变量与前置条件**（歧义仍拒绝、
  必须 8 字节对齐、callee 按去重目标数判）、**跨文件耦合**（改这里要同步哪个脚本）。
- 自检：这条注释在描述「现在的代码」还是「代码的来历」？后者删掉。（`doc/` 是例外。）
- **易变数字不进注释、不进文档**（条目数 / 族数 / 语料份数 / 函数组数）：由工具当场报出，
  用 `static_assert` 守**不变式**而非当前值。**同一份数据只留一处**；需要人工比对的稳定值
  （洞尺寸、偏移、返回值约定）只放 `doc/patch-design.md` §8。

## Docs

| 要什么 | 读哪 |
|---|---|
| 功能/安装/配置/排障 | `README.md` |
| 文档索引（先读它定方向） | `doc/README.md` |
| 方案与实现的唯一权威 | `doc/patch-design.md` |
| 设计现状 + 决策台账 | `doc/design-decisions.md` |
| 内部工作文档（不进仓库） | `doc/inner/` |
| 离线工具 + 构建期守卫 | `scripts/`（见 `doc/README.md` 末节） |
| 硬约束速查 + 环境坑 | `.workbuddy/memory/MEMORY.md` |

过程性历史（演进史全文、逐轮 Ghidra 笔记、事故复盘、退役脚本归档）已删除或移入 `doc/inner/`；
原始过程见 git 历史。
