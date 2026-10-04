// ============================================================================
// fs-codepage —— 独立系统模块，只应用 fs codepage 补丁
// （CP932 -> UTF-8，让 FAT/exFAT 支持中文/UTF-8 文件名）。
// 基于 sys-patch 框架实现，可与 sys-patch 并存安装。
//
// 补丁相关实现全部在 fs_codepage.cpp；本文件只是模块骨架：配置、调度、日志。
//
// 与 sys-patch 并存的三个前提：
//   * 补丁位点不相交：sys-patch 的 fs 条目改的是别的函数，
//     本模块只动 codepage 转换例程。
//   * 唯一共享资源是 fs 调试器（svcDebugActiveProcess 互斥）。
//     两个模块都在开机时跑一次，竞争输家必须退避重试。
//     fs_codepage_patch() 每次进入都会重置全部状态，
//     找不到 fs 时 fs_codepage_patch_result 停在 "start" —— 这就是下面的重试判据。
//
// 配置/日志在 /config/fs-codepage/ 下。
// ============================================================================

#include <cstring>
#include <switch.h>
#include "minIni/minIni.h"
#include "fs_codepage.h"

namespace {

constexpr u64 INNER_HEAP_SIZE = 0x1000;

constexpr auto MODULE_VERSION = "v1.0.0";

u32 FW_VERSION{}; // 启动时设置（仅日志诊断用）

// 退避重试： sys-patch 开机也会附加 fs 调试（互斥），输家等它脱附。
// 25 次 x 200ms = 最长等 5s，足够覆盖 sys-patch 的整个补丁流程（实测亚秒级）。
constexpr u32 ATTACH_ATTEMPTS = 25;
constexpr u64 ATTACH_RETRY_MS = 200;

struct EmummcPaths {
    char unk[0x80];
    char nintendo[0x80];
};

void smcAmsGetEmunandConfig(EmummcPaths* out_paths) {
    SecmonArgs args{};
    args.X[0] = 0xF0000404; /* smcAmsGetEmunandConfig */
    args.X[1] = 0; /* EXO_EMUMMC_MMC_NAND*/
    args.X[2] = (u64)out_paths; /* 输出路径 */
    svcCallSecureMonitor(&args);
}

auto is_emummc() -> bool {
    EmummcPaths paths{};
    smcAmsGetEmunandConfig(&paths);
    return (paths.unk[0] != '\0') || (paths.nintendo[0] != '\0');
}

// 建目录，非递归！
auto create_dir(const char* path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};

    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

// 同 ini_get，但键不存在时把默认值写回文件
auto ini_load_or_write_default(const char* section, const char* key, long _default, const char* path) -> long {
    if (!ini_haskey(section, key, path)) {
        ini_putl(section, key, _default, path);
        return _default;
    } else {
        return ini_getbool(section, key, _default, path);
    }
}

// 例：852481 -> 13.2.1
void version_to_str(char* s, u32 ver) {
    const auto num_2_str = [&s](u16 num) {
        u16 mv = 100;
        if (num > 9) {
            while (mv >= 10) {
                if (num >= mv) {
                    while (mv != 1) {
                        *s++ = '0' + (num / mv);
                        num -= (num / mv) * mv;
                        mv /= 10;
                    }
                } else {
                    mv /= 10;
                }
            }
        }
        *s++ = '0' + (num);
    };

    for (int i = 0; i < 3; i++) {
        num_2_str((ver >> 16) & 0xFF);
        if (i != 2) {
            *s++ = '.';
        }
        ver <<= 8;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    constexpr auto ini_path = "/config/fs-codepage/config.ini";
    constexpr auto log_path = "/config/fs-codepage/log.ini";

    create_dir("/config/");
    create_dir("/config/fs-codepage/");
    ini_remove(log_path);

    // 读配置
    const auto patch_sysmmc = ini_load_or_write_default("options", "patch_sysmmc", 1, ini_path);
    const auto patch_emummc = ini_load_or_write_default("options", "patch_emummc", 1, ini_path);
    const auto enable_logging = ini_load_or_write_default("options", "enable_logging", 1, ini_path);
    // 整份开关（唯一开关，没有逐点分级）：置 0 完全跳过，用于排障/救砖。
    const auto fs_codepage_enabled = ini_load_or_write_default("options", "fs_codepage", 1, ini_path);

    const auto emummc = is_emummc();
    bool enable_patching = true;

    if (!patch_sysmmc && !emummc) {
        enable_patching = false;
    }
    if (!patch_emummc && emummc) {
        enable_patching = false;
    }

    const auto ticks_start = armGetSystemTick();

    if (enable_patching) {
        if (fs_codepage_enabled) {
            // 版本下限门控：补丁表按实测只覆盖 ≥ 10.0.0；更老的 fs 是更早的代码生成，
            // 会出现「部分条目命中、部分不命中」的半成品
            // （FAT_MakeShortName 宽度钳制与转换器不成对 ⇒ 建 CJK 名时死循环）。
            // FW_VERSION 取不到时为 0 —— 必须放行
            // （setsys 失败不应让补丁静默失效），命中判定交给 pattern 扫描兜底。
            if (FW_VERSION != 0 && FW_VERSION < MAKEHOSVERSION(10, 0, 0)) {
                fs_codepage_patch_result = "unsupported_fw_version";
            } else {
            // 挂死定位标记：附加调试进程后 fs 会被挂起、写不了日志，所以进入补丁流程前
            // 先落 "attaching"。补丁收尾落盘时（fs_codepage_write_log）会把它覆写成
            // "done" —— 日志里它停在 "attaching" 且没有 fs_codepage_patch_result 行，
            // 才说明挂死/崩溃在补丁流程内；成功时两行都在，不会误读成「卡在启动」。
            if (enable_logging) {
                ini_puts("debug", "fs_codepage_phase", "attaching", log_path);
            }
            // 竞争退避：fs_codepage_patch() 找不到 fs（调试器被其它补丁模块占用，
            // 或进程表读取失败）时 patch_result 停在 "start"，此时重跑是安全的
            // —— 它每次进入都会重置族表/车道/站点 sink。
            for (u32 attempt = 0; attempt < ATTACH_ATTEMPTS; attempt++) {
                fs_codepage_patch();
                if (std::strcmp(fs_codepage_patch_result, "start") != 0) {
                    break;
                }
                svcSleepThread(ATTACH_RETRY_MS * 1000000ULL);
            }
            }
        } else {
            fs_codepage_patch_result = "disabled_by_config";
        }
    }

    const auto ticks_end = armGetSystemTick();
    const auto diff_ms = (armTicksToNs(ticks_end) - armTicksToNs(ticks_start)) / 1000ULL / 1000ULL;

    if (enable_logging) {
        char fw_version[12]{};
        version_to_str(fw_version, FW_VERSION);

        ini_puts("stats", "version", MODULE_VERSION, log_path);
        ini_puts("stats", "build_date", __DATE__ " " __TIME__, log_path);
        ini_puts("stats", "fw_version", fw_version, log_path);
        ini_putl("stats", "is_emummc", emummc, log_path);
        ini_putl("stats", "patch_time_ms", (long)diff_ms, log_path);

        // fs 编码补丁：逐条结果、命中站点偏移与诊断信息（fs 已脱附，可安全落盘）
        fs_codepage_write_log(log_path);
    }

    // 注：系统模块返回即退出。
    return 0;
}

// 以下是 libnx 固定样板
extern "C" {

// 系统模块不得使用 applet*。
u32 __nx_applet_type = AppletType_None;

// 系统模块通常只需要一个 FS 会话。
u32 __nx_fs_num_sessions = 1;

// newlib 堆配置函数（让 malloc/free 可用）。
void __libnx_initheap(void) {
    static char inner_heap[INNER_HEAP_SIZE];
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    // 配置 newlib 堆。
    fake_heap_start = inner_heap;
    fake_heap_end   = inner_heap + sizeof(inner_heap);
}

// 服务初始化。
void __appInit(void) {
    Result rc{};

    // 打开服务管理器会话。
    if (R_FAILED(rc = smInitialize()))
        fatalThrow(rc);

    // 获取当前系统版本（仅日志诊断用）。
    if (R_SUCCEEDED(rc = setsysInitialize())) {
        SetSysFirmwareVersion fw{};
        if (R_SUCCEEDED(rc = setsysGetFirmwareVersion(&fw))) {
            FW_VERSION = MAKEHOSVERSION(fw.major, fw.minor, fw.micro);
            hosversionSet(FW_VERSION);
        }
        setsysExit();
    }

    if (R_FAILED(rc = fsInitialize()))
        fatalThrow(rc);

    // 关闭服务管理器会话。
    smExit();
}

// 服务反初始化。
void __appExit(void) {
    fsExit();
}

} // extern "C"
