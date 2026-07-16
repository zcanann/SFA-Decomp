#!/usr/bin/env python3
"""Classify every sub-100 game function's target-vs-current diff by known-lever
asm signatures, producing a ranked worklist.

Signatures (levers, see agent memory / git history for the mechanism):
  LI-PLACEMENT    same `li rX,K` on both sides but in different regions
                  (statement-position fill-var lever)
  RMW-CHAIN       target same-dest lwz/add/addi read-modify-write chain where
                  current uses a fresh dest (RMW pointer-chain lever)
  MR-COPY         target `mr` where current re-materializes via `li`
                  (sub-tag SKIP-ZERO when the const is 0: shared-zero weld)
  UNROLL-MISMATCH ctr-loop trip constants differ (li feeding mtctr)
                  (ppc_unroll_instructions_limit ladder)
  PREEVAL-HOIST   a compare+branch(+li) block moved between regions
                  (array-elem accumulator de-hoist)
  WRONG-SYMBOL    named reloc differs on both sides (lbl_X vs lbl_Y)
  SPLIT-SYMBOL    reloc names differ but resolve to the SAME address (target
                  base+addend vs current per-element symbol; arrayifying the
                  source REGRESSES codegen — proven on newshadows — leave it)
  POOL-NEUTRAL    @NNN pool vs named lbl at same site (#70, score-neutral)
  EXT-DELTA       extsb/extsh/clrlwi present on one side only (narrowing)
  CALL-RESULT     current-only `li r3,K`/`mr r3` between two bl's
                  (pass-call-result-through)
  REG-PERM        register permutation only (usually welded, low priority)
  SCHED-ORDER     same opcodes reordered
  OTHER           unclassified region

Read-only: parses existing .o files, never writes build artifacts.

Usage:
  python3 tools/lever_scan.py [--min-fuzzy 90] [--max-fuzzy 100] [--top 30]
                              [--unit SUBSTR] [--detail UNIT SYM]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit, objdump_symbol, strip_preamble
from ndiff import normalize, regions, regs_only_diff

REPO = Path(__file__).resolve().parent.parent
VER = "GSAE01"

LI_RE = re.compile(r"^li (r\d+),(-?\w+)$")
RELOC_RE = re.compile(r"^RELOC (\S+)$")
RMW_RE = re.compile(r"^(?:add|addi|subi|subf|or|rlwinm) (r\d+),(r\d+)\b")
CMP_RE = re.compile(r"^cmp[lw]*w?i? ")
BRANCH_RE = re.compile(r"^b(?:eq|ne|lt|gt|le|ge)[+-]? ")


def mnem(i: str) -> str:
    return i.split()[0] if i and not i.startswith("RELOC") else ""


ADDR_RELOC_RE = re.compile(r"_([0-9A-Fa-f]{8})(?:\+0x([0-9a-f]+))?$")


def reloc_address(r: str):
    m = ADDR_RELOC_RE.search(r)
    if not m:
        return None
    return int(m.group(1), 16) + (int(m.group(2), 16) if m.group(2) else 0)


def same_address_reloc(a: str, b: str) -> bool:
    ra, rb = reloc_address(a), reloc_address(b)
    return ra is not None and ra == rb


def get_objdump() -> Path:
    p = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
    if not p.is_file():
        p = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"
    return p


def classify_fn(t: list[str], c: list[str]):
    """Return (tags Counter, region_details list)."""
    regs = regions(t, c)
    tags = Counter()
    details = []

    t_only_li, c_only_li = Counter(), Counter()
    t_blocks, c_blocks = [], []

    for tag, i1, i2, j1, j2 in regs:
        tt, cc = t[i1:i2], c[j1:j2]
        for i in tt:
            m = LI_RE.match(i)
            if m:
                t_only_li[m.group(2)] += 1
        for i in cc:
            m = LI_RE.match(i)
            if m:
                c_only_li[m.group(2)] += 1
        if len(tt) >= 2 and any(BRANCH_RE.match(i) or CMP_RE.match(i) for i in tt):
            t_blocks.append(tuple(tt))
        if len(cc) >= 2 and any(BRANCH_RE.match(i) or CMP_RE.match(i) for i in cc):
            c_blocks.append(tuple(cc))

    moved_li = sum((t_only_li & c_only_li).values())
    if moved_li:
        tags["LI-PLACEMENT"] += moved_li

    moved_blocks = set(t_blocks) & set(c_blocks)
    if moved_blocks:
        tags["PREEVAL-HOIST"] += len(moved_blocks)

    trip_t = trip_consts(t)
    trip_c = trip_consts(c)
    if trip_t != trip_c:
        tags["UNROLL-MISMATCH"] += 1

    for tag, i1, i2, j1, j2 in regs:
        tt, cc = t[i1:i2], c[j1:j2]
        tm = [mnem(i) for i in tt if mnem(i)]
        cm = [mnem(i) for i in cc if mnem(i)]
        label = None

        t_rel = [RELOC_RE.match(i).group(1) for i in tt if RELOC_RE.match(i)]
        c_rel = [RELOC_RE.match(i).group(1) for i in cc if RELOC_RE.match(i)]
        if t_rel and c_rel and t_rel != c_rel:
            if any(r.startswith("@") for r in t_rel + c_rel) and not (
                all(r.startswith("@") for r in t_rel)
                and all(r.startswith("@") for r in c_rel)
            ):
                label = "POOL-NEUTRAL"
            elif set(t_rel) != set(c_rel):
                if all(same_address_reloc(a, b) for a, b in zip(t_rel, c_rel)) and len(t_rel) == len(c_rel):
                    label = "SPLIT-SYMBOL"
                else:
                    label = "WRONG-SYMBOL"

        ext = {"extsb", "extsh", "clrlwi"}
        if label is None:
            t_ext, c_ext = set(tm) & ext, set(cm) & ext
            if (t_ext and not c_ext and set(tm) <= ext) or (
                c_ext and not t_ext and set(cm) <= ext
            ):
                label = "EXT-DELTA"
            elif t_ext != c_ext and (set(tm) - set(cm) <= ext or set(cm) - set(tm) <= ext):
                label = "EXT-DELTA"

        if label is None and "mr" in tm and "mr" not in cm and "li" in cm:
            zero = any(LI_RE.match(i) and LI_RE.match(i).group(2) == "0" for i in cc)
            label = "MR-COPY-SKIP-ZERO" if zero else "MR-COPY"

        if label is None and not tm and cm:
            if all(LI_RE.match(i) and LI_RE.match(i).group(1) == "r3" or i.startswith("mr r3,")
                   for i in cc if not i.startswith("RELOC")):
                before = [mnem(x) for x in c[max(0, j1 - 4):j1]]
                after = [mnem(x) for x in c[j2:j2 + 4]]
                if "bl" in before and "bl" in after:
                    label = "CALL-RESULT"

        if label is None:
            t_rmw = any(RMW_RE.match(i) and RMW_RE.match(i).group(1) == RMW_RE.match(i).group(2) for i in tt)
            c_rmw = any(RMW_RE.match(i) and RMW_RE.match(i).group(1) == RMW_RE.match(i).group(2) for i in cc)
            if t_rmw and not c_rmw and ("lwz" in tm or "add" in tm or "addi" in tm):
                label = "RMW-CHAIN"

        if label is None:
            if regs_only_diff(tt, cc):
                label = "REG-PERM"
            elif tm and cm and sorted(tm) == sorted(cm):
                label = "SCHED-ORDER"
            elif tuple(tt) in moved_blocks or tuple(cc) in moved_blocks:
                label = "PREEVAL-HOIST-SITE"
            elif any(LI_RE.match(i) and LI_RE.match(i).group(2) in c_only_li and LI_RE.match(i).group(2) in t_only_li for i in tt + cc):
                label = "LI-PLACEMENT-SITE"
            else:
                label = "OTHER"

        tags[label] += 1
        details.append((label, tt, cc))

    return tags, details


def trip_consts(stream: list[str]) -> Counter:
    out = Counter()
    for idx, ins in enumerate(stream):
        if ins.startswith("mtctr "):
            reg = ins.split()[1]
            for back in range(idx - 1, max(-1, idx - 6), -1):
                m = LI_RE.match(stream[back])
                if m and m.group(1) == reg:
                    out[m.group(2)] += 1
                    break
    return out


ACTIONABLE = {
    "LI-PLACEMENT", "LI-PLACEMENT-SITE", "RMW-CHAIN", "MR-COPY",
    "UNROLL-MISMATCH", "PREEVAL-HOIST", "PREEVAL-HOIST-SITE",
    "WRONG-SYMBOL", "EXT-DELTA", "CALL-RESULT",
}


def collect_targets(report_path: Path, min_fuzzy: float, max_fuzzy: float, unit_filter: str):
    report = json.load(open(report_path))
    out = []
    for u in report["units"]:
        un = u.get("name", "")
        if not un.startswith("main/main/"):
            continue
        if unit_filter and unit_filter not in un:
            continue
        for f in u.get("functions", []):
            fz = f.get("fuzzy_match_percent", 100.0)
            if min_fuzzy <= fz < max_fuzzy:
                out.append((fz, un, f.get("name", ""), int(f.get("size", "0"))))
    out.sort()
    return out


def resolve(units_cfg, report_unit):
    p = report_unit[len("main/"):]
    if p.endswith(".c"):
        p = p[:-2]
    for q in (report_unit, report_unit[len("main/"):], Path(p).name + ".c", Path(p).name):
        try:
            return resolve_unit(units_cfg, q)
        except BaseException:
            continue
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--min-fuzzy", type=float, default=90.0)
    ap.add_argument("--max-fuzzy", type=float, default=100.0)
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--unit", default="", help="substring filter on unit name")
    ap.add_argument("--report", default=str(REPO / f"build/{VER}/report.json"))
    ap.add_argument("--detail", nargs=2, metavar=("UNIT", "SYM"),
                    help="print tagged regions for one function and exit")
    args = ap.parse_args()

    objdump = get_objdump()
    units_cfg = load_units(REPO / "build" / VER / "config.json")

    if args.detail:
        un, sym = args.detail
        unit = resolve(units_cfg, un if un.startswith("main/") else "main/" + un)
        if unit is None:
            unit = resolve_unit(units_cfg, un)
        tobj = REPO / Path(unit["object"])
        cobj = REPO / Path(unit["object"].replace(f"build/{VER}/obj/", f"build/{VER}/src/"))
        t = normalize(strip_preamble(objdump_symbol(objdump, tobj, sym)))
        c = normalize(strip_preamble(objdump_symbol(objdump, cobj, sym)))
        tags, details = classify_fn(t, c)
        for label, tt, cc in details:
            print(f"[{label}]")
            print(f"  T: {tt}")
            print(f"  C: {cc}")
        print(f"-- tags: {dict(tags)}")
        return

    targets = collect_targets(Path(args.report), args.min_fuzzy, args.max_fuzzy, args.unit)
    rows = []
    errors = 0
    for fz, un, sym, size in targets:
        unit = resolve(units_cfg, un)
        if unit is None:
            errors += 1
            continue
        tobj = REPO / Path(unit["object"])
        cobj = REPO / Path(unit["object"].replace(f"build/{VER}/obj/", f"build/{VER}/src/"))
        try:
            t = normalize(strip_preamble(objdump_symbol(objdump, tobj, sym)))
            c = normalize(strip_preamble(objdump_symbol(objdump, cobj, sym)))
        except Exception:
            errors += 1
            continue
        if not t or not c:
            errors += 1
            continue
        tags, _ = classify_fn(t, c)
        act = sum(v for k, v in tags.items() if k in ACTIONABLE)
        rows.append((act, tags, fz, un, sym, len(t), len(c)))

    rows.sort(key=lambda r: (-r[0], r[2]))
    print(f"scanned {len(targets)} fns, errors {errors}")
    print(f"{'act':>3} {'fuzzy':>6} {'T/C':>9}  unit  sym  tags")
    for act, tags, fz, un, sym, tl, cl in rows[: args.top]:
        tagstr = " ".join(f"{k}:{v}" for k, v in tags.most_common() if k != "REG-PERM")
        rp = tags.get("REG-PERM", 0)
        if rp:
            tagstr += f" (regperm:{rp})"
        print(f"{act:3d} {fz:6.2f} T{tl:4d}/C{cl:<4d} {un.replace('main/', '', 1):40s} {sym:40s} {tagstr}")


if __name__ == "__main__":
    main()
