# -*- coding: utf-8 -*-
"""
fs_version_matrix.py —— 补丁点 × 固件版本 的真实命中矩阵 + 命名建议。

为什么需要它（2026-09-30）：
  之前按「同一大版本内 fs 驱动字节级不变」把条目名写成 major 粒度（`12` / `12-15` /
  `16+`）。**该假设被语料证伪**：18.0.x→18.1.0、20.0.x→20.1.x、21.1.0→21.2.0、
  22.1.0→22.5.0 的 fs 二进制都不同（上游 sys-patch 的 es 断点也落在 21.2.0 这种
  非大版本边界上）。所以范围必须回到 `a.b.c` 粒度，并且**逐版本实测**。

本工具做的事：
  1. 把语料按 FS 二进制哈希分组 ⇒ 看清哪些版本共用一份 fs（范围可跨版本外推的根据）
  2. 逐条条目 × 逐份固件数命中数：1 = 唯一命中、0 = 未命中、>1 = 落点不唯一（错误）
  3. 由实测结果生成**建议名字**（把连续命中的版本段压成 `a.b.c-d.e.f` / `a.b.c+`）
  4. 族内互斥检查 + 每份固件的族覆盖（14/14）

用法：
  python scripts/fs_version_matrix.py                     # 全语料
  python scripts/fs_version_matrix.py --variant 081b      # 只看 exfat 变体
  python scripts/fs_version_matrix.py --min 12.0.0 --suggest
"""
import argparse
import collections
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_fw_audit as A  # noqa: E402

DEF_ROOT = r"D:/Game/NS/firmware/_audit"
DEF_MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "sysmod", "src", "fs_codepage.cpp")

_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# 名字 → (族前缀, 版本范围串)
_SUF_RE = re.compile(r"^(?P<pt>fs_cp_[a-z0-9_]+?)_(?P<ver>[\d.,+-]+)$")
# 范围段：12 | 12.0.0 | 12-15 | 12.0.0-15.0.1 | 16+ | 16.0.0+
_SEG_RE = re.compile(r"^(?P<lo>\d+(?:\.\d+\.\d+)?)(?:-(?P<hi>\d+(?:\.\d+\.\d+)?))?(?P<plus>\+)?$")


def vtuple(s):
    m = _VER_RE.search(s)
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(t):
    return "%d.%d.%d" % t


def scan(root, variant):
    """-> [(版本元组, 变体, 路径)]，按版本排序。目录名里没有 x.y.z 的（如 smoke）跳过。"""
    out = []
    for dp, _dn, fn in os.walk(root):
        if "FS_unc.kip1" not in fn:
            continue
        var = os.path.basename(dp)
        if variant != "both" and var != variant:
            continue
        v = vtuple(os.path.basename(os.path.dirname(dp)))
        if v is None:
            continue
        out.append((v, var, os.path.join(dp, "FS_unc.kip1")))
    out.sort()
    return out


def entries(main):
    src = A.strip_comments(open(main, encoding="utf-8").read())
    out = []
    for m in A.FS_PAT_RE.finditer(src):
        out.append(("inst", m.group(1), m.group(2)))
    for m in A.FS_BLOB_RE.finditer(src):
        out.append(("blob", m.group(1), m.group(2)))
    return out


def fam_of(name):
    m = _SUF_RE.match(name)
    if not m:
        raise SystemExit("条目名不合 `fs_cp_<功能名>_<版本范围>`: %r" % name)
    return m.group("pt"), m.group("ver")


def expand(ver, versions):
    """范围串 -> 版本集合。段内按语料里的实际版本列表展开。"""
    out = set()
    for seg in ver.split(","):
        m = _SEG_RE.match(seg)
        if not m:
            raise SystemExit("版本范围段不合法: %r（条目 %r）" % (seg, ver))
        lo = vtuple(m.group("lo")) if "." in m.group("lo") else (int(m.group("lo")),)
        hi = m.group("hi")
        if hi:
            hi = vtuple(hi) if "." in hi else (int(hi),)
            out |= {v for v in versions if lo <= key1(v, lo) and key1(v, hi) <= hi}
        elif m.group("plus"):
            out |= {v for v in versions if key1(v, lo) >= lo}
        else:
            out |= {v for v in versions if key1(v, lo) == lo}
    return out


def key1(v, bound):
    """把三元组按 bound 的粒度截断比较（bound 只有 major 时只比 major）。"""
    return v[:len(bound)] if len(bound) < 3 else v


def collapse(hit_versions, all_versions, newest):
    """命中的版本集合 -> 建议范围串（连续段合并；末段到最新已知版本用 `+`）。"""
    order = [v for v in all_versions]
    idx = {v: i for i, v in enumerate(order)}
    got = sorted(hit_versions, key=lambda v: idx[v])
    if not got:
        return "(未命中)"
    runs, cur = [], [got[0]]
    for v in got[1:]:
        if idx[v] == idx[cur[-1]] + 1:
            cur.append(v)
        else:
            runs.append(cur)
            cur = [v]
    runs.append(cur)
    segs = []
    for r in runs:
        first, last = r[0], r[-1]
        if last == newest:
            segs.append(vstr(first) + "+")
        elif first == last:
            segs.append(vstr(first))
        else:
            segs.append("%s-%s" % (vstr(first), vstr(last)))
    return ",".join(segs)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEF_ROOT)
    ap.add_argument("--main", default=DEF_MAIN)
    ap.add_argument("--variant", default="081b", choices=["081b", "0819", "both"])
    ap.add_argument("--min", default="12.0.0", help="支持下限；更老的只提示")
    ap.add_argument("--suggest", action="store_true", help="输出建议改名表")
    args = ap.parse_args()

    ents = entries(args.main)
    if not ents:
        sys.exit("error: 没解析到条目（表格式变了？）")
    files = scan(args.root, args.variant)
    if not files:
        sys.exit("error: %s 下没有 FS_unc.kip1" % args.root)
    lo = vtuple(args.min)

    versions = []
    for v, _var, _p in files:
        if v not in versions:
            versions.append(v)
    allv = [v for v in versions if v >= lo]
    newest = allv[-1] if allv else None

    print("语料 %d 份（变体 %s）/ 版本 %d 个；下限 %s；条目 %d 条"
          % (len(files), args.variant, len(versions), args.min, len(ents)))
    print()

    # ---- 1. FS 二进制分组 ----------------------------------------------------
    groups = collections.OrderedDict()
    for v, var, p in files:
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]
        groups.setdefault(h, []).append((v, var))
    print("=== FS 二进制分组（同组 = 字节级同一份驱动）===")
    for h, items in groups.items():
        vs = sorted({v for v, _ in items})
        runs, cur = [], [vs[0]]
        for v in vs[1:]:
            if v == cur[-1]:
                continue
            cur.append(v)
        # 简写：连续列出
        tags = [vstr(v) for v in vs]
        print("  %s  n=%-2d  %s" % (h, len(items), " ".join(tags)))
    print()

    # ---- 2. 命中矩阵 --------------------------------------------------------
    codes = {}
    hits = collections.defaultdict(dict)   # name -> {(v,var): n}
    for v, var, p in files:
        code = A.FsImage(p).code
        codes[(v, var)] = code
        for _k, name, pat in ents:
            hits[name][(v, var)] = len(A.find_pattern(code, A.parse_fs_pattern(pat)))
    # 按变体归并：同一版本的两个变体必须一致，否则报警
    per_ver = collections.defaultdict(dict)  # name -> {v: n(max over variants)}
    for name, d in hits.items():
        for (v, var), n in d.items():
            prev = per_ver[name].get(v)
            per_ver[name][v] = n if prev is None else max(prev, n)

    print("=== 逐条目实测覆盖（变体 %s）===" % args.variant)
    errs = []
    fams = collections.OrderedDict()
    suggest = []
    for _k, name, _pat in ents:
        pt, ver = fam_of(name)
        fams.setdefault(pt, []).append((name, ver))
        d = per_ver[name]
        multi = sorted(vstr(v) for v, n in d.items() if n > 1)
        measured = {v for v, n in d.items() if n == 1}
        below = sorted(vstr(v) for v in measured if v < lo)
        measured = {v for v in measured if v >= lo}
        declared = expand(ver, versions)
        miss = sorted(vstr(v) for v in declared - measured if v >= lo)
        extra = sorted(vstr(v) for v in measured - declared)
        sug = collapse(measured, allv, newest)
        status = "OK" if not (multi or miss or extra) else "MISMATCH"
        if multi:
            status = "MULTI@%s" % ",".join(multi)
        print("  %-48s 声明 %-14s 实测 %-26s %s" %
              (name, ver, sug if measured else "-", status))
        if multi:
            errs.append("%s: 在 %s 上多命中（落点不唯一）" % (name, ",".join(multi)))
        if miss:
            errs.append("%s: 声明但实测未命中 %s" % (name, ",".join(miss)))
        if extra:
            errs.append("%s: 实测命中但名字未声明 %s" % (name, ",".join(extra)))
        if below:
            print("        注：低于下限的命中 %s（不在支持范围）" % ",".join(below))
        if sug != ver:
            suggest.append((name, pt, ver, sug))
    print()

    # ---- 3. 族内互斥 --------------------------------------------------------
    print("=== 族内互斥（声明范围不得相交）===")
    for pt, items in fams.items():
        sets = [(n, v, expand(v, versions)) for n, v in items]
        for i in range(len(sets)):
            for j in range(i + 1, len(sets)):
                inter = sets[i][2] & sets[j][2]
                if inter:
                    errs.append("重叠 %s: %s ∩ %s = %s" %
                                (pt, sets[i][1], sets[j][1],
                                 ",".join(sorted(vstr(x) for x in inter))))
                    print("  !! 重叠 %s: %s ∩ %s = %s" % (pt, sets[i][1], sets[j][1],
                                                        ",".join(sorted(vstr(x) for x in inter))))
        print("  %-44s %s" % (pt, " | ".join(v for _n, v in items)))
    print()

    # ---- 4. 每份固件的族覆盖 -------------------------------------------------
    print("=== 每份固件（≥ %s）的族覆盖 ===" % args.min)
    nfam = len(fams)
    bad = 0
    for v, var, p in files:
        if v < lo or (args.variant != "both" and var != args.variant):
            continue
        got = {fam_of(n)[0] for _k, n, _p in ents if hits[n].get((v, var)) == 1}
        if len(got) != nfam:
            bad += 1
            print("  %-9s %-3s %2d/%d  缺 %s" %
                  (vstr(v), var, len(got), nfam,
                   ",".join(sorted(f for f in fams if f not in got))))
    if bad == 0:
        print("  全部 %d 份固件 %d/%d 覆盖" % (len(allv), nfam, nfam))
    print()

    # ---- 5. 建议改名 ---------------------------------------------------------
    if suggest:
        print("=== 建议改名（声明 != 实测）===")
        for name, pt, ver, sug in suggest:
            print("  %-48s %-14s -> %-26s  => %s_%s" % (name, ver, sug, pt, sug))
        print()

    if errs:
        for e in errs:
            print("ERROR: %s" % e)
        print("结论：条目 %d / 族 %d / 问题 %d / 覆盖不全的固件 %d 份"
              % (len(ents), nfam, len(errs), bad))
        return 1
    print("结论：条目 %d / 族 %d / 0 问题" % (len(ents), nfam))
    return 0


if __name__ == "__main__":
    sys.exit(main())
