"""Classify every sub-100 function as STRUCT / OPS / PERM / NOISE.

Three normalized streams per function:
  1. mnemonic-only
  2. operands, with branch targets rewritten as instruction DELTAS and
     pool/reloc symbol names collapsed
  3. stream 2 again with all GPR/FPR/CR canonicalized by first appearance

Alignment is done on the MNEMONIC stream first; operands are only ever
compared inside equal-mnemonic runs.  Comparing operands positionally is
meaningless once a block shifts.

Negative control: every fuzzy-100 function inside a sub-100 unit must
classify NOISE.  Run with --control to check.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(\S+)(?:\s+(.*))?$")
RELOC_RE = re.compile(r"^\s+([0-9a-f]+):\s+(R_PPC_\S+)\s+(\S+)")
SYMHDR_RE = re.compile(r"^([0-9a-f]{8}) <([^>]+)>:$")

# `a0 <modelRenderFn_80006744+0x3c>` or `24 <getLActions+0x24>`
BRANCH_TGT_RE = re.compile(r"^([0-9a-f]+)\s+<[^>]*>$")

POOL_SYM_RE = re.compile(r"^(?:@\d+|lbl_[0-9A-Fa-f]{6,8}|\.\w+)$")

BRANCH_MNEM = re.compile(r"^b(?:c|dnz|dz)?(?:l?)(?:a?)(?:[+-]?)$|^b(?:lt|gt|eq|ne|ge|le|so|ns|un|nu)(?:l?)(?:[+-]?)$")

REG_RE = re.compile(r"\b([rf])(\d{1,2})\b|\b(cr)(\d)\b")


def objdump(obj: Path) -> str:
    tool = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
    if not tool.is_file():
        tool = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"
    return subprocess.run(
        [str(tool), "-M", "gekko", "-drz", str(obj)],
        check=True, capture_output=True, text=True,
    ).stdout


def parse_functions(text: str) -> dict[str, list[tuple[int, str, str, str | None]]]:
    """-> {symbol: [(addr, mnemonic, operands, reloc_symbol_or_None), ...]}"""
    funcs: dict[str, list] = {}
    cur: list | None = None
    for line in text.splitlines():
        m = SYMHDR_RE.match(line)
        if m:
            cur = []
            funcs[m.group(2)] = cur
            continue
        if cur is None:
            continue
        m = INSN_RE.match(line)
        if m:
            cur.append([int(m.group(1), 16), m.group(3), (m.group(4) or "").strip(), None])
            continue
        m = RELOC_RE.match(line)
        if m and cur:
            cur[-1][3] = m.group(3)
    return {k: [tuple(i) for i in v] for k, v in funcs.items()}


def norm_operands(addr: int, mnem: str, ops: str, reloc: str | None,
                  lo: int = 0, hi: int = 1 << 30) -> str:
    if mnem.startswith("b") and ops:
        parts = [p.strip() for p in ops.split(",")]
        tgt = BRANCH_TGT_RE.match(parts[-1])
        if tgt:
            if reloc is not None:
                parts[-1] = "<REL:%s>" % collapse_sym(reloc)
            else:
                dst = int(tgt.group(1), 16)
                if lo <= dst < hi:
                    parts[-1] = "<%+d>" % ((dst - addr) // 4)
                else:
                    # retail objects are carved from the LINKED image, so an
                    # external call already has a resolved displacement where
                    # ours still carries an R_PPC_REL24.  Wildcard it.
                    parts[-1] = "<EXTCALL>"
            return ",".join(parts)
    if reloc is not None:
        # pool / SDA / HA-LO reference: displacement is a link-time artifact
        ops = re.sub(r"-?\d+\(", "<D>(", ops, count=1)
        ops = re.sub(r"^(-?\d+|0x[0-9a-f]+)$", "<D>", ops)
        return ops + " <DATA>"
    return ops


def collapse_sym(sym: str) -> str:
    # Data-symbol NAMES are not comparable across objects: retail carries real
    # local names (jumptable_802C4EC8, lbl_8XXXXXXX) where our object interns
    # anonymous consts (@243).  Byte-identical code reads as a diff otherwise.
    # Pool CONTENT correctness is pool_content_check.py / sda_reloc_check.py's
    # job, not this tool's.
    return "<POOL>" if POOL_SYM_RE.match(sym) else sym


def canon_regs(stream: list[str]) -> list[str]:
    mapping: dict[str, str] = {}

    def sub(m: re.Match) -> str:
        key = m.group(0)
        if key not in mapping:
            cls = "R" if key.startswith("r") else ("F" if key.startswith("f") else "C")
            mapping[key] = "%s%d" % (cls, sum(1 for v in mapping.values() if v[0] == cls))
        return mapping[key]

    return [REG_RE.sub(sub, s) for s in stream]


def streams(insns):
    lo = insns[0][0]
    hi = insns[-1][0] + 4
    mnem = [i[1] for i in insns]
    ops = [norm_operands(i[0], i[1], i[2], i[3], lo, hi) for i in insns]
    return mnem, ops


def ops_equal(a: str, b: str) -> bool:
    if a == b:
        return True
    # an <EXTCALL> (resolved in the retail image) is compatible with any
    # relocated call at the same position.
    return ("<EXTCALL>" in a and "<REL:" in b) or ("<EXTCALL>" in b and "<REL:" in a)


def classify(tgt, cur) -> tuple[str, int, int]:
    """-> (class, mnemonic_delta, operand_delta)"""
    tm, to = streams(tgt)
    cm, co = streams(cur)

    sm = difflib.SequenceMatcher(None, tm, cm, autojunk=False)
    blocks = sm.get_matching_blocks()
    matched = sum(b.size for b in blocks)
    mdelta = (len(tm) - matched) + (len(cm) - matched)

    # operands compared ONLY inside equal-mnemonic runs
    to_eq, co_eq = [], []
    for b in blocks:
        for k in range(b.size):
            to_eq.append(to[b.a + k])
            co_eq.append(co[b.b + k])
    odelta = sum(1 for a, b in zip(to_eq, co_eq) if not ops_equal(a, b))

    if mdelta:
        return "STRUCT", mdelta, odelta
    if odelta == 0:
        return "NOISE", 0, 0
    ct, cc = canon_regs(to_eq), canon_regs(co_eq)
    if all(ops_equal(a, b) for a, b in zip(ct, cc)):
        return "PERM", 0, odelta
    return "OPS", 0, odelta


def poolswap(tgt, cur):
    """Count adjacent transposed FP-const/field load pairs.

    Retail loading a NAMED cross-TU pool const keeps source operand order;
    our anonymous literal gets canonicalized into the A-slot.  The two `lfs`
    are therefore transposed.  Compare only the MEMORY operand -- the
    destination FPR differs by construction.
    """
    tm, to = streams(tgt)
    cm, co = streams(cur)
    sm = difflib.SequenceMatcher(None, tm, cm, autojunk=False)
    if any(t != "equal" for t, *_ in sm.get_opcodes()):
        return None

    def mem(x):
        return x.split(",", 1)[1] if "," in x else x

    bad = [i for i in range(len(to)) if not ops_equal(to[i], co[i])]
    if not bad:
        return None
    pairs, leftover, i = 0, 0, 0
    while i < len(bad):
        a = bad[i]
        if (i + 1 < len(bad) and bad[i + 1] == a + 1
                and tm[a].startswith("lf") and tm[a + 1].startswith("lf")
                and mem(to[a]) == mem(co[a + 1]) and mem(to[a + 1]) == mem(co[a])
                and "<DATA>" in to[a + 1] and "<DATA>" in co[a]):
            pairs += 1
            i += 2
        else:
            leftover += 1
            i += 1
    return pairs if pairs else None


def surplus(tgt, cur, mnem: str) -> int:
    """Count instructions with this mnemonic present in CUR but not TGT,
    aligned on the mnemonic stream."""
    tm, _ = streams(tgt)
    cm, _ = streams(cur)
    sm = difflib.SequenceMatcher(None, tm, cm, autojunk=False)
    n = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "insert"):
            n += sum(1 for k in range(j1, j2) if cm[k].startswith(mnem))
            n -= sum(1 for k in range(i1, i2) if tm[k].startswith(mnem))
    return max(n, 0)


def show(tgt, cur) -> None:
    """Aligned target-vs-current dump, aligned on the MNEMONIC stream."""
    tm, to = streams(tgt)
    cm, co = streams(cur)
    sm = difflib.SequenceMatcher(None, tm, cm, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                a, b = to[i1 + k], co[j1 + k]
                if ops_equal(a, b):
                    continue
                print("  ~ %-4d %-9s %-38s | %s" % (i1 + k, tm[i1 + k], a, b))
        else:
            for k in range(i1, i2):
                print("  - %-4d %-9s %s" % (k, tm[k], to[k]))
            for k in range(j1, j2):
                print("  + %-4d %-9s %s" % (k, cm[k], co[k]))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--control", action="store_true",
                    help="classify fuzzy-100 fns in sub-100 units (must all be NOISE)")
    ap.add_argument("--unit", help="restrict to one unit (report.json name substring)")
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--cls", help="only show this class")
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--show", help="aligned dump for this function symbol")
    ap.add_argument("--poolswap", action="store_true",
                    help="report fns whose ONLY divergence is an FP-constant "
                         "A-slot/B-slot swap -- the signature of retail importing "
                         "a NAMED cross-TU pool const where we intern an anonymous "
                         "literal.  Unfixable in source (the fix is the banned "
                         "pool-reconstruction shape); these are TU-split leads.")
    ap.add_argument("--extra", metavar="MNEM",
                    help="report fns where OURS emits this mnemonic and the "
                         "target does not (surplus-instruction screen)")
    args = ap.parse_args()

    build = REPO / "build" / args.version
    report = json.load(open(build / "report.json"))

    rows = []
    control_bad = []
    for unit in report["units"]:
        if unit["measures"]["fuzzy_match_percent"] >= 100.0:
            continue
        if args.unit and args.unit not in unit["name"]:
            continue
        src = unit["metadata"].get("source_path")
        if not src:
            continue
        rel = src[len("src/"):] if src.startswith("src/") else src
        tgt_obj = build / "obj" / (rel[:-2] + ".o")
        cur_obj = build / "src" / (rel[:-2] + ".o")
        if not tgt_obj.is_file() or not cur_obj.is_file():
            continue
        try:
            tf = parse_functions(objdump(tgt_obj))
            cf = parse_functions(objdump(cur_obj))
        except subprocess.CalledProcessError:
            continue
        for fn in unit.get("functions", []):
            pct = fn.get("fuzzy_match_percent", 0.0)
            name, size = fn["name"], int(fn["size"])
            if name not in tf or name not in cf:
                continue
            want100 = args.control
            if args.show:
                pass
            elif want100 != (pct >= 100.0):
                continue
            if size < args.min_size:
                continue
            if args.show:
                if name != args.show:
                    continue
                print("%s :: %s  size=%d fuzzy=%.6f" % (unit["name"], name, size, pct))
                show(tf[name], cf[name])
                return
            if args.poolswap:
                n = poolswap(tf[name], cf[name])
                if n is not None and n > 0:
                    rows.append((unit["name"], name, size, pct, "SWAP:%d" % n, 0, 0))
                continue
            if args.extra:
                n = surplus(tf[name], cf[name], args.extra)
                if n:
                    rows.append((unit["name"], name, size, pct, "EXTRA:%d" % n, 0, 0))
                continue
            cls, md, od = classify(tf[name], cf[name])
            if args.control:
                if cls != "NOISE":
                    control_bad.append((unit["name"], name, cls, md, od))
                continue
            rows.append((unit["name"], name, size, pct, cls, md, od))

    if args.control:
        total = sum(1 for u in report["units"]
                    if u["measures"]["fuzzy_match_percent"] < 100.0
                    for f in u.get("functions", []) if f.get("fuzzy_match_percent", 0) >= 100.0)
        print("CONTROL: %d fuzzy-100 fns in sub-100 units, %d misclassified" % (total, len(control_bad)))
        for r in control_bad[:40]:
            print("  ", r)
        return

    if args.cls:
        rows = [r for r in rows if r[4] == args.cls]
    # weight = fuzzy shortfall in bytes
    rows.sort(key=lambda r: -((100.0 - r[3]) / 100.0 * r[2]))
    counts: dict[str, list[int]] = {}
    for r in rows:
        c = counts.setdefault(r[4], [0, 0])
        c[0] += 1
        c[1] += int((100.0 - r[3]) / 100.0 * r[2])
    print("total sub-100 fns: %d" % len(rows))
    for k, (n, w) in sorted(counts.items(), key=lambda kv: -kv[1][1]):
        print("  %-7s %4d fns  %7d wB" % (k, n, w))
    print()
    print("%-34s %-38s %6s %10s %-7s %4s %4s %7s" %
          ("unit", "function", "size", "fuzzy", "class", "mΔ", "oΔ", "wB"))
    for u, f, s, p, c, md, od in rows[:args.limit]:
        print("%-34s %-38s %6d %10.4f %-7s %4d %4d %7d" %
              (u, f, s, p, c, md, od, (100.0 - p) / 100.0 * s))


if __name__ == "__main__":
    main()
