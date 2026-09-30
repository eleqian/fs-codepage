# fs-codepage 长期备忘（2026-09-29 从 sys-patch 迁出，独立维护）

## 工程定位
- 独立系统模块，**只做 fs codepage 补丁**：把 fs 的 CP932(Shift-JIS) 转换例程换成 UTF-8 <-> UTF-16，
  让 FAT/exFAT 支持中文等 3 字节 UTF-8 文件名。可与 **upstream sys-patch 并存**（不改动 sys-patch）。
- TID `42000000000000E0`（sys-patch 是 ...0B），config/log 在 `/config/fs-codepage/`。
- **源码来源**：`sysmod/src/{fs_codepage.cpp,fs_codepage.h,patch_types.h}` +
  `sysmod/tools/check_patch_sizes.py` 四文件**原样复制**自 sys-patch fork
  （`D:/Design/NS/sys-patch`，全量分支 `dev/fs-codepage` / master 单点提交 `6db363f`）；
  `sysmod/src/main.cpp` 是本工程新写的骨架（退避重试 + 独立 config/log）。
- ★ 2026-09-30 起**本工程是这四文件的权威侧**（改名 + 12/13 覆盖已改 `fs_codepage.cpp` /
  `check_patch_sizes.py`），fork 侧停在旧版、不再反向同步；需要时回拷给 fork。
- **文档与历史已迁来并整理（2026-09-29，原工程保持不变、今后不再同步）**：文档入 `doc/`、
  工具入 `scripts/`；**只保留最终设计思路与原理**，过程性历史（演进史全文、逐轮 Ghidra 笔记、
  已实施的改进清单、事故 post-mortem、退役脚本归档）已删 —— 原始过程仍在本仓库 git 历史
  （`eff8a96`）或 sys-patch 的 `dev/fs-codepage` 分支。两个离线工具默认路径已改成本工程。
- ★ 共存关键：fs 调试器（`svcDebugActiveProcess`）互斥 ⇒ main 里退避重试（25×200ms），
  判据 = `fs_codepage_patch_result=="start"`（可安全重跑，入口重置全部状态）；
  站点与 upstream fs 条目函数级不相交。**fork sys-patch + 本模块并存须二选一**（sys-patch 侧 `fs_codepage=0`）。

## 形态（P1+M6+M8+14/15+12/13 → P3 扫描 → 停用 stage 并修 4 处 → 合并结构体 + 去编号改名）
- 全部在 `sysmod/src/fs_codepage.cpp`（API `fs_codepage.h`；共享类型 `patch_types.h`）。
- 全 pattern 驱动、无硬编码偏移：`fs_fn_groups[12]` + `fs_inst_patches[18]` + `fs_blob_patches[22]`；
  **40 条 / 14 族**（2026-09-30 深夜：下限降到 10.0.0，+8 条 10/11 变体）；
  每份固件写内存 **14**；**7** 个整函数替换。
  旧拼接管线（PATTERNS.json/_gen_cpp/_splice_main）不在仓库 ⇒ 直接改源码，格式须让 `PAT_RE`/`BLOB_RE`/
  `GROUP_RE`/`PRED_LIST_RE` 可解析，改完跑 `make`（守卫 `check_patch_sizes.py`，`--main src/fs_codepage.cpp`）。
- 条目命名 `fs_cp_<功能名>_<版本范围>`，**族号 = 版本范围之前的功能前缀**；31 条 / **14 族**。
  三个同布局 fs 对象视图统一为单一 **`StringDesc`**（24 B，不用 union）；`FsNameDesc16`（16 B）独立。
  换型后 7 个替换函数字节尺寸逐位不变（776/488/148…）。
- **没有条目级门控**：只有「整份生效 / 整份跳过 (`[options] fs_codepage=0`)」两态 —— 半成品危险
  （转换器已换、p27 宽度钳制未打 ⇒ FAT32 建 CJK 名在 `subs w23,w23,#2` 死循环）。
- P3 扫描结构（估 3.61×）：S1 族内互斥兄弟退役；S2 全族落定空转退出；S3 blob 车道快筛
  （偏移 0/4 → `fs_blob_lane[2][256]`）。车道取样须留 `FS_BLOB_LOOP_MARGIN=8`。

## 铁律
- **ASLR**：进 fs 的代码必须位置无关（禁 MOVZ/MOVK 宽常量、BL、字面量池、`&函数名`）。
- ★ **支持范围 = 10.0.0–22.5.0**（2026-09-30 深夜下扩：+8 条 `10.0.0-11.0.1` 变体；
  main.cpp 有 `MAKEHOSVERSION(10,0,0)` 门控，取不到版本放行）；**≤9.x 不做**（更早代
  代码生成，ctx/布局/洞不保证，代价高 1-2 个数量级）；**23.0.0 缺新代 master key 解不了**，待重 Dump keys。
  ★★ **「同一大版本内 fs 不变」是错的**（12.0.x→12.1.0、13.0.0→13.1.0、16.0.2→16.0.3、
  18.0.x→18.1.0、21.1.0→21.2.0、22.1.0→22.5.0 都换 fs；补丁点恰在不变区才没翻车）⇒
  条目版本范围 = **逐小版本实测端点**：`10.0.0-14.1.2` / `16.0.0+` / `10.0.0-14.1.2,21.0.0+`
  （major 写法在 `NAME_RE` 兼容但不用）。
- ★★ **pattern 只有一种写法：`..` = 一个通配字节**（单个 `.` 非法）—— 依据是
  `patch_types.h::str2hex`：看到 '.' 就 `s += 2` 吃掉两个点。JSON/离线脚本与 C++ **同一口径**。
  三个实现必须同步：`patch_types.h` / `sysmod/tools/check_patch_sizes.py::parse_pattern`
  / `scripts/fs_fw_audit.py::parse_fs_pattern`。
  （坑：旧备忘曾写成「C++ 一个 `.` 一槽」，照它写会让槽数翻倍 ⇒ 通配符不在模板末尾的
  条目**全部 0 命中**；`fs_fw_audit.py` 就是这么漂掉的，2026-09-30 审计 10.x~13.x 才发现，已修。）
- ★ **fs 全局槽地址绝不可写死**（槽 **18** 个取值）⇒ 哨兵 `0xDEAD0001/2` + 读原函数体唯一 adrp+配对 ldr 收割，
  失败整点跳过。callee 按**去重目标数**判（非 bl 条数）；delta 同形状内也变。
- 绝不手抄字节改机器码，只做等价改写；哨兵按**内容**校验（序言在 asm 之前）。
- ★ 去魔鬼数字 = 纯源码整理：`fs_codepage.cpp` 顶有 **§0 具名常量块**，展开逐位相同；
  坑：`.inst` 汇编串里不能写 C++ 宏名 ⇒ 用 `FS_ASM_STR(x)`（`#x` 字符串化）。改完必证 7 个尺寸不变。
- ★ `FS_OVERLAP` 必须 4 的倍数(`0x50`)，否则 M3 位面**静默不命中**。
- ★ 差分目标 = 与原版**逐位一致**。短分支的 NUL 落点也算差分（Unicode2OEM 1 字节路径
  `strb wT,[x1]`+`strb wzr,[x1,#1]`）。
- ★ ASCII 折叠 `+0xffe0` 是旧 15 点补丁的 bug：原版比较是 16 位（`uxth`）丢进位 ⇒ 等价 `c-0x20`；
  M6 统一 `fold_ascii_upper(c)=c-0x20`（`0x31C`→`0x308`）。
- ★ 改表的连带清单（漏一个就静默失效）：`check_patch_sizes.py` + `scripts/fs_fw_audit.py`
  （`FS_PAT_RE`/`FS_BLOB_RE`）。
- ★ 改条目名/版本范围后必跑 **`scripts/fs_version_matrix.py`**（取代已删的 fs_name_ranges.py）：
  fs 哈希分组 + 逐条目×逐小版本命中 + 建议改名 + 族内不相交 + 每份固件 14/14。
  当前期望 **40 条 / 14 族 / 0 问题 / ≥10 固件全 14/14**（0819/081b 一致）。
  （仓库外那两个 `_map_variants.py` / `_check_name_ranges.py` 已过时：带着「一个 `.` 一槽」
  的错误口径 + 指向 sys-patch 的旧路径，别再用。）
- ★★ 名字正则的字符类必须放宽：条目名含 `. + - ,` ⇒ 用 `([A-Za-z0-9_.,+-]+)`，用 `\w+` 会解析成 0 条。
- 调试：`svcDebugActiveProcess()` 后 fs 挂起、禁写 log.ini；逃生只有 `[options] fs_codepage=0`。
  日志：`[fs_codepage]` 只列已定位条目，未命中数进 `[debug] fs_codepage_unmatched`。

## 关键结论
- 当前 7 个替换体尺寸/洞：0xEC/0x170、0x8C/0x1D0、0x48/0x50、0xEC/**0x110**、0x94/0xB0、0x308/0x360、0x1E8/0x240。
  （str_unicode2oem 洞 0x120→0x110：10/11 实测最小，仍 > 0xEC。）守卫会报 `ZERO SLACK`/`HOLE OVERFLOW`。
- 整函数替换可行性 = **外部依赖一票否决 + 洞够不够**；bl=0 只有 `FAT_GetNextChar`。
  14/15 属另一代代码生成，用**追加式变体族**覆盖，族间必须严格不相交。
- ctx 表（`PFCODE_CODE_PAGE_CONTEXT @0x7100FCFC38`）：`+0x18` OEM2Unicode / `+0x20` Unicode2OEM /
  `+0x28` OEMCharWidth / `+0x30` isOEMMBchar / `+0x38`·`+0x40` 常量回调 / `+0x48` 特殊映射标志。
  `ConvertWidth(oem,uni)=oem<<16|uni`；非 BMP 名字折叠同名，**决定不做**。
- 语料：`D:/Game/NS/firmware/_audit/` 下 92 份 `FS_unc.kip1`（10.0.0–22.5.0 全小版本 × 2 变体；
  **不在本仓库**）。评估新固件 / 验候选 pattern 用 `scripts/fs_pat_hits.py`，
  命名/覆盖校验用 `scripts/fs_version_matrix.py`（都读这个目录，默认路径已内置）。
  23.0.0 的 package2 需 keygen 0x17（`package2_key_17`），手写解密器 `_pkg2_decrypt.py` 备用。

## 环境坑
- 构建（实测最优解）：`C:\devkitPro\msys2\usr\bin\bash.exe -lc 'cd /d/Design/NS/fs-codepage && make'`
  （msys2 的 PATH 带 `/opt/devkitpro/tools/bin`）。⚠️ 在 PowerShell 里补 `C:\devkitPro\tools\bin`
  仍报 `elf2nso: No such file`。msys2 无 zip ⇒ dist 用 `python -m zipfile -c`。
- ★ 带 capstone 的 python = `~/.workbuddy/binaries/python/envs/default/Scripts/python.exe`。
- `_dump_blobs.py` 读本工程 `sysmod/fs-codepage.elf`（已从 sys-patch.elf 改过）。

## 文档地图（本工程内）
- 入口 `README.md`（用户向）/ `AGENTS.md`（规则约束/硬不变量/布局/文档地图）/ `doc/README.md`（文档索引）。
- **权威实现** `doc/patch-design.md`（§3.5=M6/§3.6=M8）。
- **设计现状＋决策台账** `doc/design-decisions.md`（无编号）；**版本兼容选型** `doc/fw-compat.md`；
  **替换体评估** `doc/replace-fn-eval.md`（§7=整改）；**对象模型** `doc/fs-object-model.md`；
  **接口对照** `doc/interface-map.md`；**测试 SOP** `doc/test-plan.md`；参考数据 `doc/callback-tables.md`
  + `doc/fs_structs.h`。工具：`scripts/{fs_fw_audit,_fs_dis,_dump_blobs,_name_collision_check}.py`。
- ★ 过程性历史已删 ⇒ 现在文档里的 `§N` 一律指**该文档自身**的章节（旧约定「裸 §N 指演进史」作废）。

## 迁来的日志索引（`.workbuddy/memory/`）
| 文件 | 内容 |
|---|---|
| 2026-09-13 / 14 | fs 对象模型、FAT 驱动层、SD 卡取证（目录 ARCHIVE 位） |
| 2026-09-15 | 开机卡 logo、中文名「能枚举打不开」（`isOEMMBchar` 忽略 `byte_idx`） |
| 2026-09-16 | PPSSPP/RetroArch 闪退诊断（**与本补丁无关**，工具在 fs_encode_fix/ 里一并迁来） |
| 2026-09-17 / 18 | 版本兼容选型、跨版本固件审计（prod.keys 坑、argparse 全局参数坑） |
| 2026-09-19 / 20 | `+0xffe0` 折叠陷阱、整函数替换评估、守卫整改 |
| 2026-09-27 / 28 | sys-patch 仓库重排、fs 表适配上游 `..` 通配写法（两份 str2hex 合并） |
| 2026-09-29 | 拆出本工程 + 文档/历史迁移 + 整理（doc/ + scripts/，删过程性历史）与初始提交 |

> 日志里的 `fs_encode_fix/...` 旧路径按下表换算：`fs_encode_fix/*.md` → `doc/`（文件名已改英文名，
> 见 `doc/README.md`）、`fs_encode_fix/*.py` → `scripts/`；`sys-patch.elf` → `fs-codepage.elf`。
