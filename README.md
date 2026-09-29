# fs-codepage（独立 fs UTF-8 补丁模块）

从 sys-patch fork 拆出的**独立**系统模块，只做一件事：把 fs 的 CP932 (Shift-JIS)
代码页转换例程替换为 UTF-8 <-> UTF-16，让 FAT/exFAT 卷支持中文等 3 字节 UTF-8 文件名。

设计动机：该功能目前寄生在 sys-patch fork 里，改动较大、不确定能否合并上游。
本工程把它拆成单独的补丁插件，作为**备选方案**——可与**原版（upstream）sys-patch
并存安装**，sys-patch 项目本体不做任何改动。

## 与 sys-patch 的共存（兼容性）

| 组合 | 行为 |
| --- | --- |
| 原版 upstream sys-patch + 本模块 | **推荐**。补丁站点函数级不相交（upstream 的 fs 条目 noacidsigchk/noncasigchk/nocntchk 碰的是别的函数），互不干扰 |
| fork sys-patch（自带 fs codepage）+ 本模块 | 不要同时开。在 sys-patch 的 `/config/sys-patch/config.ini` 里设 `fs_codepage=0`，把编码补丁完全交给本模块；或者反过来禁用本模块 |
| 只有本模块 | 只修 fs 代码页，其余签名补丁等由 sys-patch 负责（或都不打） |

竞争处理：fs 的调试器（`svcDebugActiveProcess`）是互斥的，两个模块开机同时跑时
输家会拿不到 fs。本模块 main 里做了退避重试（25 次 × 200ms，最长 5s）——
`fs_codepage_patch()` 找不到 fs 时结果停在 `"start"` 且每次进入都会重置全部状态，
因此重跑是安全的。补丁写入本身是 fail-safe 的：pattern 未命中绝不写。

## 安装

把 `out/atmosphere/` 整个拷到 SD 卡根目录（或 `dist` 出的 zip 解压）：

```
atmosphere/contents/42000000000000E0/
├── exefs.nsp
├── toolbox.json
└── flags/boot2.flag
```

- Title ID `42000000000000E0`，与 sys-patch（`420000000000000B`）不同，可并存。
  若与其他自制系统模块撞号，改 `sysmod/fs-codepage.json`、`sysmod/toolbox.json`
  和 `sysmod/Makefile` 里的 `TITLE_ID` 三处即可。
- 开机（boot2）自动运行一次，打完补丁即退出。

## 配置与日志

`/config/fs-codepage/config.ini`（首次运行自动生成）：

```ini
[options]
patch_sysmmc=1
patch_emummc=1
enable_logging=1
fs_codepage=1   ; 唯一开关：置 0 整份跳过（排障/救砖用）
```

日志在 `/config/fs-codepage/log.ini`：`[fs_codepage]` 逐条结果、
`[fs_codepage_sites]` 命中站点偏移、`[debug]` 诊断（含挂死时最后进入的函数组）。
与 sys-patch 的 `/config/sys-patch/` 完全分开。

## 构建

```
C:\devkitPro\msys2\usr\bin\bash.exe -lc 'cd /d/Design/NS/fs-codepage && make'
```

- 需要 devkitPro/libnx，C++23。
- 每次构建自动跑 `sysmod/tools/check_patch_sizes.py` 守卫（7 个替换体尺寸 ==
  ELF 符号尺寸且 ≤ 洞、pattern 表结构合法、参考固件上恰好命中 1 次、位置无关），
  任一失败构建即失败。
- `make dist` 额外产出 `fs-codepage-sysmodule.zip`。

## 布局

```
Makefile                 根：只管 sysmod，收集 out/
common/minIni/           INI 库（与 sys-patch 同源）
sysmod/
  Makefile               TARGET=fs-codepage, TITLE_ID=42000000000000E0
  fs-codepage.json       NPDM（name/title_id 与 sys-patch 不同）
  toolbox.json           Toolbox 列表项
  src/main.cpp           模块骨架：配置、调度（重试）、日志
  src/fs_codepage.cpp    补丁本体（自 sys-patch fork 原样复制，未改）
  src/fs_codepage.h      API
  src/patch_types.h      pattern/patch 基元（自 sys-patch fork 原样复制）
  tools/check_patch_sizes.py  构建期守卫（原样复制）
```

`fs_codepage.*` / `patch_types.h` / `check_patch_sizes.py` 与 sys-patch fork
保持逐字节同步；若 fork 侧表有更新，直接重新复制这四个文件即可。

## 文档与历史（2026-09-29 从 sys-patch 迁来，本工程单独维护）

设计文档、逆向笔记、离线工具和逐日工作日志已随代码一起迁到本工程，
`D:/Design/NS/sys-patch` 保持原样、**今后不再同步**：

```
AGENTS.md                       智能体入口：硬不变量 / 构建 / 布局 / 文档地图
补丁点合并优化分析.md            设计现状 + 决策台账
M6_Ghidra反编译报告.md           M6 三个形状的 Ghidra 反编译全文
plan.md                          CP932 ↔ UTF-8 接口级对照
fs_encode_fix/                   RE 文档 + 离线工具（索引见 fs_encode_fix/README.md，L0–L5）
.workbuddy/memory/               逐日工作日志（13~29 日）+ MEMORY.md 长期备忘
```

- 文档里的路径已按本工程校正（离线工具读 `sysmod/fs-codepage.elf`、
  `sysmod/src/fs_codepage.cpp`）。
- 26 份固件语料与离线验证脚本（`D:/Game/NS/firmware/_audit/`）体积过大，**仍在仓库外**。
