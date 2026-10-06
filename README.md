# fs-codepage

Switch 大气层系统模块：把文件系统驱动 `fs` 的 CP932（日文）字符集转换替换为 UTF-8 ⇄ UTF-16，
使 FAT / exFAT 卷支持中文等 3 字节 UTF-8 文件名。

[![Horizon OS](https://img.shields.io/badge/Horizon%20OS-10.0.0%2B-3c7abf?style=flat-square)](doc/patch-design.md)
[![Corpus](https://img.shields.io/badge/verified-full%20corpus-3c7abf?style=flat-square)](scripts/fs_version_matrix.py)
[![Build](https://img.shields.io/badge/build-guard%20enforced-3c7abf?style=flat-square)](scripts/check_patch_sizes.py)

基于 sys-patch 框架实现，与 sys-patch **可并存安装**（打补丁的函数不相关）。

---

## 概述

官方系统的 `fs` 驱动按 CP932 处理文件名，FAT / exFAT 卷上的中文名因此无法创建，或可枚举但无法打开。
本模块在 boot2 阶段对 `fs` 进程做一次内存补丁，替换其代码页转换链，并修正配套的字符宽度处理与通配符匹配；
补丁完成后模块退出，不常驻、不修改卷上的数据，重启即恢复原状。

补丁点为**全表 pattern 驱动**，运行期不含写死的 fs 偏移或全局地址：定位靠字节模板，改写靠语义等价规则，
随版本变化的值（代码页上下文槽、外部 callee）在打补丁时从被覆盖的原函数体现场收割。
收割失败则该点整组跳过，不写入任何字节。

## 特性

- **中文文件名可用** —— 创建、枚举、打开、读取、重命名、删除（3 字节 UTF-8）。
- **零硬编码偏移** —— 定位与收割全部在运行期完成，跨版本自适应。
- **可与 sys-patch 并存** —— Title ID 不同，补丁站点函数级不相交。
- **构建期强制守卫** —— 每次 `make` 校验替换体尺寸与洞容量、位置无关性、pattern 语法、
  条目命名、族内互斥、规则引用，任一失败即构建失败。
- **失败安全** —— pattern 未命中绝不写入；生效粒度是整份，不存在半成品状态。
- **可停用** —— `[options] fs_codepage=0` 完全跳过，排障路径唯一。

## 支持范围

| 项目 | 说明 |
| --- | --- |
| 已验证 | Horizon OS 10.0.0 – 23.0.0，逐小版本实测，全部补丁点在每份固件上命中 |
| 不支持 | < 10.0.0：过于古老的版本，支持意义不大，模块整份跳过（日志 `unsupported_fw_version`） |

## 安装

解压 `fs-codepage-sysmodule.zip`，拷至 SD 卡根目录：

```
SD:/atmosphere/contents/42000000000000E0/
├── exefs.nsp
├── toolbox.json
└── flags/boot2.flag
```

- `flags/boot2.flag` 使模块在 boot2 阶段自动运行一次。
- 模块需访问 `fs` 进程内存，NPDM 已申请 `debug_flags.force_debug` 与相应 syscall。

**验证**：开机一次，在 FAT32 / exFAT 分区创建中文名文件（如 `测试.txt`）并确认可打开；
再检查 `/config/fs-codepage/log.ini` 的 `[debug] fs_codepage_patch_result` 为成功状态。

## 配置

`/config/fs-codepage/config.ini`（首次运行自动生成，缺键补默认值）：

```ini
[options]
fs_codepage=1      ; 唯一开关：置 0 整份跳过补丁（排障 / 救砖）
enable_logging=1   ; 写 log.ini
patch_sysmmc=1     ; 允许在 sysMMC 上打补丁
patch_emummc=1     ; 允许在 emuMMC 上打补丁
```

`patch_sysmmc` / `patch_emummc` 按当前启动介质二选一生效；两者都关则补丁整体不执行
（结果不写入日志，表现为补丁未生效）。

## 日志与排障

日志位于 `/config/fs-codepage/log.ini`：

| 段 | 内容 |
| --- | --- |
| `[stats]` | 模块版本、构建时间、固件版本、是否 emuMMC、打补丁耗时 |
| `[debug]` | `fs_codepage_patch_result`（总体结论）、`fs_codepage_phase`、`fs_codepage_missing_families` |
| `[fs_codepage]` | 逐条结果：`Patched (sys-patch)` / `Unpatched` / `Failed (fs ctx harvest)` / `Failed (svcWriteDebugProcessMemory)` |
| `[fs_codepage_missing]` | 整族缺席的补丁点数（**期望 0**），键 = 族名 |
| `[fs_codepage_sites]` | 命中站点在 fs 内的偏移 |

排障顺序：

1. `[debug] fs_codepage_patch_result` —— `disabled_by_config` = 开关置 0；
   `unsupported_fw_version` = 固件低于支持下限；停在 `attaching` 且无结论 = 卡在补丁流程内。
2. `[fs_codepage_missing_families]` 应为 0；非 0 时由 `[fs_codepage_missing]` 指出缺席的族。
3. 异常时唯一逃生路径：`[options] fs_codepage=0`。

## 从源码构建

环境：[devkitPro](https://devkitpro.org/) + libnx（C++23）、`python`（守卫需要）。

在 devkitPro 的 msys2 登录 shell 中从**仓库根**执行：

```bash
make                     # 构建 + 自动跑守卫，产物收进 out/
make dist                # 额外出 fs-codepage-sysmodule.zip
make check-patch-sizes   # 只跑守卫
make clean
```

产物：`out/atmosphere/contents/42000000000000E0/{exefs.nsp, toolbox.json, flags/boot2.flag}`。

> 与其它自制模块 Title ID 冲突时，修改 `sysmod/fs-codepage.json`、`sysmod/toolbox.json`
  与 `sysmod/Makefile` 的 `TITLE_ID` 三处后重新构建。

**构建期守卫**（`scripts/check_patch_sizes.py`，每次构建自动运行，任一失败即构建失败）：

- 替换体 `label delta == ELF 符号尺寸` 且 ≤ 该补丁点的洞（余量不足报 `ZERO SLACK` / `HOLE OVERFLOW`）；
- 替换体位置无关（禁 MOVZ/MOVK 宽常量、字面量池、外部 `BL`、非 `adrp+add` 的 PC 相对引用）；
- 从源码文本解析补丁表：条目名合规、pattern 语法、cond/patch 配套、族内互斥、规则被引用；
- 收割判据与 ctx 链校验在 C++ 与 Python 两侧一致；参考固件上每个 pattern 恰好命中 1 次。

修改补丁表或条目名后，需再跑离线版本矩阵（依赖仓库外的固件语料）：

```bash
python scripts/fs_version_matrix.py --min 10.0.0 --variant both
# 期望：0 问题，且每份固件上每个族都覆盖
```

## 项目结构

```
Makefile                      根：只管 sysmod，产物收集到 out/
common/minIni/                INI 库
sysmod/
  Makefile                    TARGET=fs-codepage, TITLE_ID=42000000000000E0
  fs-codepage.json            权限声明（NPDM）
  toolbox.json                Toolbox 列表项
  src/main.cpp                骨架：配置、调度、日志
  src/fs_codepage.cpp         补丁本体（表 + 整函数替换体）
  src/fs_codepage.h           接口
  src/patch_types.h           pattern / patch 基元
doc/                          设计文档与逆向结论（不参与构建）
scripts/                      构建期守卫 + 离线工具
AGENTS.md                     硬约束与改动纪律
```

## 已知限制

- **4 字节字符（emoji 等）**：比较值只取前 3 字节，前 3 字节相同的不同字符会判为同名。
  3 字节汉字（U+0800–FFFF）零碰撞。
- **FAT32 8.3 短名**：宽度钳制为 2 以避免死循环，短名空间仍按 CP932 行为估算，PC 侧可能识别不出短名。
- **半角片假名**：CP932 ⇄ UTF-8 往返丢失，属已知取舍。
- **< 10.0.0 版本不支持**。

## 许可

本项目使用 `MIT` 开源许可。
