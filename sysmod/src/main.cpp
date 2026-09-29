// ============================================================================
// fs-codepage -- standalone system module applying ONLY the fs codepage patch
// (CP932 -> UTF-8, Chinese/UTF-8 filenames on FAT/exFAT), extracted from the
// sys-patch fork so it can run next to the ORIGINAL (upstream) sys-patch.
//
// Everything patch-related lives in fs_codepage.cpp (copied verbatim from the
// sys-patch fork); this file is just the module skeleton: config, scheduling,
// logging.
//
// Coexistence with sys-patch:
//   * Patch sites are disjoint: upstream sys-patch's fs entries
//     (noacidsigchk / noncasigchk / nocntchk) touch other functions, this
//     module only touches the codepage conversion routines.
//   * The one shared resource is the fs DEBUGGER (svcDebugActiveProcess is
//     exclusive). Both modules run once at boot, so whoever loses the race
//     must back off and retry. fs_codepage_patch() resets all of its state on
//     entry and leaves fs_codepage_patch_result at "start" when fs was not
//     found, which is the retry criterion used below.
//   * Do NOT also enable the codepage patch inside a sys-patch build that has
//     it (fork builds): pick one, via [options] fs_codepage=0 in the
//     sys-patch config. Running both is fail-safe (the second scan finds the
//     sites already rewritten and matches nothing) but pointless noise.
//
// Config / log live under /config/fs-codepage/ -- deliberately NOT
// /config/sys-patch/ so the two modules never touch each other's files.
// ============================================================================

#include <cstring>
#include <switch.h>
#include "minIni/minIni.h"
#include "fs_codepage.h"

namespace {

constexpr u64 INNER_HEAP_SIZE = 0x1000; // same budget as sys-patch

constexpr auto MODULE_VERSION = "v1.0.0";

u32 FW_VERSION{}; // set on startup (log diagnostics only)

// 退避重试：原版 sys-patch 开机也会附加 fs 调试（互斥），输家等它脱附。
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
    args.X[2] = (u64)out_paths; /* out path */
    svcCallSecureMonitor(&args);
}

auto is_emummc() -> bool {
    EmummcPaths paths{};
    smcAmsGetEmunandConfig(&paths);
    return (paths.unk[0] != '\0') || (paths.nintendo[0] != '\0');
}

// creates a directory, non-recursive!
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

// same as ini_get but writes out the default value instead
auto ini_load_or_write_default(const char* section, const char* key, long _default, const char* path) -> long {
    if (!ini_haskey(section, key, path)) {
        ini_putl(section, key, _default, path);
        return _default;
    } else {
        return ini_getbool(section, key, _default, path);
    }
}

// eg, 852481 -> 13.2.1
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

    // load options
    const auto patch_sysmmc = ini_load_or_write_default("options", "patch_sysmmc", 1, ini_path);
    const auto patch_emummc = ini_load_or_write_default("options", "patch_emummc", 1, ini_path);
    const auto enable_logging = ini_load_or_write_default("options", "enable_logging", 1, ini_path);
    // 整份开关（唯一开关，没有逐点分级）：置 0 完全跳过，用于排障/救砖。
    // 与 fork sys-patch 的 [options] fs_codepage 同名同义。
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
            // 附加调试进程后 fs 会被挂起，此后不能再写日志，所以先落一条标记
            if (enable_logging) {
                ini_puts("debug", "fs_codepage", "start", log_path);
            }
            // 竞争退避：fs_codepage_patch() 找不到 fs（调试器被 sys-patch 占用，
            // 或进程表读取失败）时 patch_result 停在 "start"，此时重跑是安全的
            // —— 它每次进入都会重置族表/车道/站点 sink。
            for (u32 attempt = 0; attempt < ATTACH_ATTEMPTS; attempt++) {
                fs_codepage_patch();
                if (std::strcmp(fs_codepage_patch_result, "start") != 0) {
                    break;
                }
                svcSleepThread(ATTACH_RETRY_MS * 1000000ULL);
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

    // note: sysmod exits here.
    return 0;
}

// libnx stuff goes below
extern "C" {

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Sysmodules will normally only want to use one FS session.
u32 __nx_fs_num_sessions = 1;

// Newlib heap configuration function (makes malloc/free work).
void __libnx_initheap(void) {
    static char inner_heap[INNER_HEAP_SIZE];
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    // Configure the newlib heap.
    fake_heap_start = inner_heap;
    fake_heap_end   = inner_heap + sizeof(inner_heap);
}

// Service initialization.
void __appInit(void) {
    Result rc{};

    // Open a service manager session.
    if (R_FAILED(rc = smInitialize()))
        fatalThrow(rc);

    // Retrieve the current version of Horizon OS (log diagnostics only).
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

    // Close the service manager session.
    smExit();
}

// Service deinitialization.
void __appExit(void) {
    fsExit();
}

} // extern "C"
