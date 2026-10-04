#ifndef PATCH_TYPES_H
#define PATCH_TYPES_H

// Pattern / patch 基元，
// 供系统模块补丁器（main.cpp）与 fs codepage 补丁（fs_codepage.cpp）共用。

#include <cstring>
#include <utility> // std::unreachable
#include <switch.h>

constexpr u16 REGEX_SKIP = 0x100;        // 字节模板里的通配槽
constexpr u64 READ_BUFFER_SIZE = 0x1000; // 读内存用的静态缓冲大小

// "0xAB..CD" -> {0xAB, REGEX_SKIP, 0xCD}：
// ".." 是一个通配字节，两个 hex 字符是一个字面字节。非法字符串在编译期报错。
template<typename T>
constexpr void str2hex(const char* s, T* data, u8& size) {
    // 跳过前导 0x（若有）
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    // 非法字符串会因无返回值而编译期报错
    constexpr auto hexstr_2_nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= '0' && c <= '9') { return c - '0'; }
    };

    // 解析并转换字符串
    while (*s != '\0') {
        if (sizeof(T) == sizeof(u16) && *s == '.') {
            data[size] = REGEX_SKIP;
            s += 2; // 吃掉 ".." 的两个点
        } else {
            data[size] |= hexstr_2_nibble(*s++) << 4;
            data[size] |= hexstr_2_nibble(*s++) << 0;
        }
        size++;
    }
}

struct PatternData {
    constexpr PatternData(const char* s) {
        str2hex(s, data, size);
    }

    u16 data[60]{}; // 模板长度上限（足够大，按需调整）
    u8 size{};
};

struct PatchData {
    constexpr PatchData(const char* s) {
        str2hex(s, data, size);
    }

    template<typename T>
    constexpr PatchData(T v) {
        for (u32 i = 0; i < sizeof(T); i++) {
            data[size++] = v & 0xFF;
            v >>= 8;
        }
    }

    constexpr auto cmp(const void* _data) -> bool {
        return !std::memcmp(data, _data, size);
    }

    u8 data[20]{}; // 补丁长度上限（足够大，按需调整）
    u8 size{};
};

enum class PatchResult {
    NOT_FOUND,
    SKIPPED,
    DISABLED,
    PATCHED_FILE,
    PATCHED_SYSPATCH,
    FAILED_WRITE,
    FAILED_HARVEST, // 仅 fs：现场收割失败，该点保持原样不动
};

inline auto patch_result_to_str(PatchResult result) -> const char* {
    switch (result) {
        case PatchResult::NOT_FOUND: return "Unpatched";
        case PatchResult::SKIPPED: return "Skipped";
        case PatchResult::DISABLED: return "Disabled";
        case PatchResult::PATCHED_FILE: return "Patched (file)";
        case PatchResult::PATCHED_SYSPATCH: return "Patched (sys-patch)";
        case PatchResult::FAILED_WRITE: return "Failed (svcWriteDebugProcessMemory)";
        case PatchResult::FAILED_HARVEST: return "Failed (fs ctx harvest)";
    }

    std::unreachable();
}

#endif // PATCH_TYPES_H
