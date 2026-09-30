# -*- coding: utf-8 -*-
"""
fs_pat_hits.py —— 给定一份 fs 二进制，逐条报告补丁表里 31 个 pattern 的命中情况。

与 fs_fw_audit.py 的分工：
  * fs_fw_audit.py 的 sites 由**基线**（19.0.1）反推，再重定位到目标固件 —— 它回答
    "已知点在目标固件里漂到哪了"，只能覆盖在基线上有唯一命中的那部分条目。
  * 本工具反过来：**拿目标固件自己当基线**，逐条数命中数。回答"这份固件能用现表的
    哪几条、哪几条要新增变体族"，这才是评估"能不能兼容"的第一步。

用法：
  python scripts/fs_pat_hits.py <FS_unc.kip1> [<FS_unc.kip1> ...]
  python scripts/fs_pat_hits.py --dir D:/Game/NS/firmware/_audit     # 扫所有 FS_unc.kip1

输出：每份 fs 一张表：条目 / 命中数 / 落点偏移 / 落点指令（capstone 反汇编）。
命中数 1 = 可定位（还需 cond 谓词通过，见各 rules_is_*）；0 = 该族不覆盖这份固件；
>=2 = 危险（多落点），必须加长 pattern。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_fw_audit as A  # noqa: E402

try:
    import capstone
    HAS_CS = True
except ImportError:
    HAS_CS = False

IMAGE_BASE = A.IMAGE_BASE
MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN) if HAS_CS else None
if MD:
    MD.detail = False


def fam(name):
    """族号 = 剥掉版本范围后的功能前缀（与 _check_name_ranges.py 同口径）。"""
    return re.sub(r"_\d[\d.,+-]*$", "", name)


def dis_at(code, off, n=4):
    """反汇编 off 处的 n 条指令，返回可读串。"""
    if not HAS_CS or off is None or off < 0 or off + 4 * n > len(code):
        return ""
    out = []
    for ins in MD.disasm(bytes(code[off:off + 4 * n]), IMAGE_BASE + off):
        out.append("%s %s" % (ins.mnemonic, ins.op_str))
        if len(out) >= n:
            break
    return " ; ".join(out)


def collect(main_cpp):
    """解析两张表，返回 [(kind, name, pattern_bytes, off, extra)]。"""
    src = A.strip_comments(open(main_cpp, encoding="utf-8").read())
    ents = []
    for m in A.FS_PAT_RE.finditer(src):
        ents.append(("inst", m.group(1), A.parse_fs_pattern(m.group(2)),
                     int(m.group(3)), m.group(4)))
    for m in A.FS_BLOB_RE.finditer(src):
        ents.append(("blob", m.group(1), A.parse_fs_pattern(m.group(2)),
                     int(m.group(3)), m.group(4)))
    return ents


def one(fs_path, ents, show_dis=True):
    img = A.FsImage(fs_path)
    code = img.code
    rows = []
    for kind, name, pat, off, extra in ents:
        if pat is None:
            rows.append((name, kind, -1, None, "pattern 语法非法", extra))
            continue
        hits = A.find_pattern(code, pat)
        if not hits:
            rows.append((name, kind, 0, None, "", extra))
        elif len(hits) > 1:
            rows.append((name, kind, len(hits), None,
                         "多命中 %s" % ", ".join("0x%X" % h for h in hits[:6]), extra))
        else:
            site = hits[0] + off
            rows.append((name, kind, 1, site,
                         dis_at(code, site) if show_dis else "", extra))
    return rows, len(code)


def all_fs(root):
    out = []
    for dp, _dn, fn in os.walk(root):
        if "FS_unc.kip1" in fn:
            out.append(os.path.join(dp, "FS_unc.kip1"))
    return sorted(out)


def try_pattern(pat_s, files):
    """试一条候选 pattern：在每份 fs 上数命中数。

    「族间互斥」是硬不变量：新变体必须在**每一份**语料上「恰好 0 或 1 次命中」，
    且不能与本族兄弟在同一份上同时命中。所以这里要扫全部语料，不能只看目标版本。
    """
    pat = A.parse_fs_pattern(pat_s)
    if pat is None:
        sys.exit("pattern 语法非法（记住：`..` = 一个通配字节，单个 `.` 非法）")
    bad = 0
    for f in files:
        code = A.FsImage(f).code
        hits = A.find_pattern(code, pat)
        tag = "%s/%s" % (os.path.basename(os.path.dirname(os.path.dirname(f))),
                         os.path.basename(os.path.dirname(f)))
        mark = "OK  " if len(hits) <= 1 else "!!  "
        if len(hits) > 1:
            bad += 1
        print("%s%-34s %d 次  %s" % (mark, tag, len(hits),
                                     ", ".join("0x%X" % h for h in hits[:4])))
    print("\n多命中 %d 份 / 共 %d 份 ⇒ %s"
          % (bad, len(files), "可用" if bad == 0 else "不可用（族间不互斥）"))


def main():
    av = sys.argv[1:]
    if not av:
        sys.exit(__doc__)
    corpus = os.environ.get("FS_CORPUS", "D:/Game/NS/firmware/_audit")
    if av[0] == "--try":
        rest = av[2:]
        files = rest if rest else all_fs(corpus)
        try_pattern(av[1], files)
        return
    if av[0] == "--dir":
        root = av[1]
        files = all_fs(root)
    else:
        files = av
    if not files:
        sys.exit("没找到 FS_unc.kip1")

    main_cpp = A.MAIN_CPP
    ents = collect(main_cpp)
    print("补丁表 %s：%d 条（%d 指令 + %d 替换），%d 族"
          % (main_cpp, len(ents),
             sum(1 for e in ents if e[0] == "inst"),
             sum(1 for e in ents if e[0] == "blob"),
             len({fam(e[1]) for e in ents})))
    print("capstone: %s\n" % ("可用" if HAS_CS else "不可用（只报命中数）"))

    # 表头：所有 fs 并排，便于看"哪一族覆盖哪些版本"
    for fs_path in files:
        rows, codelen = one(fs_path, ents)
        tag = os.path.basename(os.path.dirname(fs_path))
        ver = os.path.basename(os.path.dirname(os.path.dirname(fs_path)))
        print("=" * 100)
        print("%s / %s   代码段 0x%X (%d bytes)" % (ver, tag, codelen, codelen))
        print("-" * 100)
        nhit1 = sum(1 for r in rows if r[2] == 1)
        nhit0 = sum(1 for r in rows if r[2] == 0)
        nhitn = sum(1 for r in rows if r[2] > 1)
        for name, kind, n, site, note, extra in rows:
            mark = "OK " if n == 1 else ("-- " if n == 0 else "!! ")
            loc = "0x%06X" % site if site is not None else " " * 8
            print("%s%-46s %-4s %1d  %s  %s" % (mark, name, kind, max(n, 0), loc, note))
        print("-" * 100)
        print("唯一命中 %d ｜ 0 命中 %d ｜ 多命中 %d  （共 %d 条 / 族覆盖 %d）"
              % (nhit1, nhit0, nhitn, len(rows),
                 len({fam(r[0]) for r in rows if r[2] == 1})))
        print()


if __name__ == "__main__":
    main()
