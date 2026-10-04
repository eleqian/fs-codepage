#ifndef FS_CODEPAGE_H
#define FS_CODEPAGE_H

// fs codepage 补丁（CP932 -> UTF-8）。实现在 fs_codepage.cpp。
//
// 没有「部分生效」：补丁表要么整份应用、要么经 [options] fs_codepage=0 整份跳过
// （半份会让 FAT_MakeShortName 挂死）。

// 附加 fs，按 pattern 定位全部补丁点并应用。
// 只扫描第一个 >= 1MiB 的 Rx/CodeStatic 段（fs 主 .text，同时就是模块基址）。
// 运行期间 fs 被挂起，调用方不得碰任何经过 fs 服务的操作（例如写 SD 卡日志）。
void fs_codepage_patch(void);

// 把结果写进 log.ini（[fs_codepage] / [fs_codepage_sites] / [debug]）。
// 只能在 fs_codepage_patch() 返回之后调用，即 fs 已脱附。
void fs_codepage_write_log(const char* log_path);

// 最后进入的函数组的进度名（"start" / <组名> / "success"）。
// 若补丁把 fs 打挂，这就是元凶所在的那一组。
extern const char* fs_codepage_patch_result;

#endif // FS_CODEPAGE_H
