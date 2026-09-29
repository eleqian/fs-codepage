#ifndef SYS_PATCH_FS_CODEPAGE_H
#define SYS_PATCH_FS_CODEPAGE_H

// fs codepage patch (CP932 -> UTF-8). Implementation: fs_codepage.cpp.
//
// No partial switch: the table is applied as a whole or skipped as a whole via
// [options] fs_codepage=0 (a half applied table hangs FAT_MakeShortName).

// Attach to fs, locate every patch point by pattern and apply it. Only the first
// Rx/CodeStatic segment >= 1MiB is scanned (fs .text, which is also the module
// base). fs is suspended while this runs, so the caller must not touch anything
// that goes through the fs service (writing the SD log, for instance).
void fs_codepage_patch(void);

// Write the results to log.ini ([fs_codepage] / [fs_codepage_sites] / [debug]).
// Only call this after fs_codepage_patch() has returned, i.e. fs is detached.
void fs_codepage_write_log(const char* log_path);

// Progress name of the last function group entered ("start" / <group> / "success").
// If the patch ever hangs fs, this is the group that did it.
extern const char* fs_codepage_patch_result;

#endif // SYS_PATCH_FS_CODEPAGE_H
