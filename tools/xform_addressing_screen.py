"""Screen for the indexed-addressing (x-form) deficit lever.

Retail shape:  addi r0,IV,K ; lfsx/lwzx/stfsx base,r0   (base re-dereferenced per access)
Our shape:     add  rX,base,off ; lfs K(rX)             (base pinned in a stable local)

Ranks sub-100 functions by how many x-form indexed memory ops retail emits that we
do not, weighted by missing bytes.

Usage: python3 tools/xform_addressing_screen.py [--min-wb N] [--unit NAME]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBJDUMP = ROOT / "build/binutils/powerpc-eabi-objdump"
CONFIG = ROOT / "build/GSAE01/config.json"
REPORT = ROOT / "build/GSAE01/report.json"
NINJA = ROOT / "build.ninja"

XFORM = re.compile(
    r"^\s*(lfsx|lfsux|lfdx|lfdux|stfsx|stfsux|stfdx|stfdux|"
    r"lwzx|lwzux|lwax|stwx|stwux|lbzx|lbzux|stbx|stbux|"
    r"lhzx|lhzux|lhax|lhaux|sthx|sthux)\b"
)
INSTR = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\S+)")


ADDR = re.compile(r"^\s*add\s+r\d+,r\d+,r\d+")


def disasm_counts(obj: Path) -> dict[str, tuple[int, int, int]]:
    """symbol -> (xform_count, add_count, total_instrs) for each function."""
    try:
        out = subprocess.run(
            [str(OBJDUMP), "-M", "gekko", "-drz", str(obj)],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    counts: dict[str, tuple[int, int, int]] = {}
    sym = None
    xf = ad = tot = 0
    for line in out.splitlines():
        head = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if head:
            if sym:
                counts[sym] = (xf, ad, tot)
            sym, xf, ad, tot = head.group(1), 0, 0, 0
            continue
        m = INSTR.match(line)
        if m and sym:
            tot += 1
            body = line[line.index(m.group(1)):]
            if XFORM.match(body):
                xf += 1
            elif ADDR.match(body):
                ad += 1
    if sym:
        counts[sym] = (xf, ad, tot)
    return counts


def ninja_objects() -> set[str]:
    if not NINJA.exists():
        return set()
    text = NINJA.read_text(errors="ignore")
    return set(re.findall(r"build/GSAE01/src/[^\s:]*\.o", text))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-wb", type=float, default=20.0)
    ap.add_argument("--unit")
    args = ap.parse_args()

    live = ninja_objects()
    cfg = {u["name"]: u["object"] for u in json.load(CONFIG.open())["units"]}
    report = json.load(REPORT.open())

    rows = []
    for unit in report["units"]:
        meta = unit.get("metadata", {})
        src = meta.get("source_path")
        if not src or meta.get("auto_generated"):
            continue
        if args.unit and args.unit not in unit["name"]:
            continue
        fns = [f for f in unit.get("functions", [])
               if f.get("fuzzy_match_percent", 100.0) < 100.0]
        if not fns:
            continue

        ours = ROOT / ("build/GSAE01/" + src.replace(".c", ".o"))
        if str(ours.relative_to(ROOT)) not in live or not ours.exists():
            continue
        retail_rel = cfg.get(src.replace("src/", ""))
        if not retail_rel:
            continue
        retail = ROOT / retail_rel
        if not retail.exists():
            continue

        rc, oc = disasm_counts(retail), disasm_counts(ours)
        if not rc or not oc:
            continue
        for f in fns:
            name = f["name"]
            if name not in rc or name not in oc:
                continue
            xd = rc[name][0] - oc[name][0]
            addd = oc[name][1] - rc[name][1]
            score = xd + addd
            if score <= 0:
                continue
            size = int(f["size"])
            wb = size * (1.0 - f["fuzzy_match_percent"] / 100.0)
            if wb < args.min_wb:
                continue
            rows.append((score, wb, unit["name"], name,
                         f["fuzzy_match_percent"], xd, addd))

    rows.sort(key=lambda r: (-r[0] * r[1]))
    print(f"{'unit':30} {'function':40} {'fuzzy':>8} {'wB':>7} {'xΔ':>4} {'addΔ':>5}")
    for score, wb, unit, fn, fuzzy, xd, addd in rows:
        print(f"{unit[:30]:30} {fn[:40]:40} {fuzzy:8.3f} {wb:7.1f} {xd:4d} {addd:5d}")
    print(f"\n{len(rows)} hits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
