# 文档索引（`doc/` · `scripts/`）

> **2026-09-29 整理**：只保留**最终设计思路与原理**。过程性论证（原「演进史」全文）、逐轮
> Ghidra 笔记、已实施的改进清单、事故 post-mortem、退役脚本归档已全部删除 —— 它们的结论
> 已并入 `patch-design.md` / `design-decisions.md`；原始过程仍可从 git 历史（提交 `eff8a96`）
> 或 `D:/Design/NS/sys-patch` 的 `dev/fs-codepage` 分支查到。

## 怎么读

| 你的目的 | 读这个 |
|---|---|
| 改补丁代码之前 | `../AGENTS.md`（硬不变量）+ `patch-design.md` |
| 想知道「补丁是什么、怎么实现的、怎么验的、坏了怎么办」 | **`patch-design.md`** ★ 权威 |
| 想知道「为什么这么设计、哪些做了哪些没做」 | `design-decisions.md` |
| 加新固件版本 / 表命中不上 | `fw-compat.md` + `scripts/fs_fw_audit.py` + `scripts/fs_pat_hits.py` |
| 改条目名 / 版本范围 | `scripts/fs_version_matrix.py`（锁死范围 == 实测） |
| 老固件（10.x–13.x）能不能支持、要改哪些 | **`old-fw-compat.md`** ★ 含逐族命中矩阵、已验证的候选 pattern |
| 查 fs 内部结构 / 函数指针表 | `fs-object-model.md` · `callback-tables.md` · `fs_structs.h` |

## `doc/`

| 文件 | 定位 |
|---|---|
| `patch-design.md` | ★ **权威**：原理、补丁清单（32 条 / 大版本 12–22 / 7 个替换体）、实现要点与 ASLR 纪律、构建期守卫、排障、已知限制 |
| `design-decisions.md` | 设计现状 + 决策台账（M1–M8 / O1–O7：做了什么、没做什么、为什么） |
| `fw-compat.md` | 版本兼容**选型**：指令级补丁 vs 整函数替换的取舍规则、跨版本洞的取法、`fs_fw_audit.py` 用法 |
| `old-fw-compat.md` | 老固件（10.0.0–13.2.1）**兼容性分析**：逐族命中矩阵、根因分类、洞/收割/布局三项硬指标、已过唯一性验证的候选 pattern、遗留风险 |
| `replace-fn-eval.md` | 7 个整函数替换的**功能合理性**（Ghidra 复核、P0/P1 问题、差分口径建议、整改项） |
| `fs-object-model.md` | fs **对象模型**逆向终版（19.exfat，image base `0x7100000000`）：卷内存池、`FsDrvObject`、目录迭代器、FAT 介质驱动层、exFAT 全环节 |
| `interface-map.md` | CP932 ↔ UTF-8 **接口级对照**：每个 `PFCODE_*` 的语义、调用点、适配方式 |
| `encoding-choice.md` | 方案**选型**：GBK/CP936 vs UTF-8（结论：UTF-8） |
| `test-plan.md` | 上机测试计划（部署、功能、边界、性能、回归）—— 现行 SOP |
| `callback-tables.md` | 代码页回调表 / FS vtable / `IDirectory_Func_Table` 等**函数指针表的逐槽清单**（参考数据，不建议通读） |
| `fs_structs.h` | 结构体偏移定义（packed + `_Static_assert` 校验） |

## `scripts/`

离线工具，**不参与构建**，需要时手动跑。

| 工具 | 用途 | 依赖 |
|---|---|---|
| `fs_fw_audit.py` | 固件解包 + fs 补丁适配审计（`all` / `check` / `audit` / `unpack` / `holes` / `batch`）；改表后必跑 | hactool / nstool |
| `fs_pat_hits.py` | **pattern 命中矩阵**：逐份 fs 数全部模板的命中数；`--try` 验候选 pattern 在全语料上的唯一性（族间互斥）。评估新固件时先跑它 | capstone（可选） |
| `fs_version_matrix.py` | **精确版本矩阵**：fs 二进制哈希分组 + 逐条目 × 逐小版本命中 + 建议改名 + 族内互斥 + 14/14 覆盖。**改名后必跑**（32 条 / 14 族 / 0 问题，语料 12.0.0–22.5.0 全小版本） | — |
| `_fs_dis.py` | fs 二进制反汇编小工具（`sites` / `range` / `word` / `adrp`） | capstone |
| `_dump_blobs.py` | 从 `sysmod/fs-codepage.elf` 反汇编 7 个替换体，打印 size vs 洞（守卫报 `ZERO SLACK` / `HOLE OVERFLOW` 时用） | capstone |
| `_name_collision_check.py` | 「fs 视角同名」冲突检查（`--explain` / `--mode wide`） | — |

> 需要 capstone 的两个用托管 venv 的 python 跑：`~/.workbuddy/binaries/python/envs/default/Scripts/python.exe`。
> 离线验证脚本（`_verify_cpp_table.py` / `_p1_sim_scan.py` / `_opt_equiv.py` / `_m6_*.py` …）
> 与 26 份固件语料同在 `D:/Game/NS/firmware/_audit/`，**不在本仓库**（上百 MB）。
