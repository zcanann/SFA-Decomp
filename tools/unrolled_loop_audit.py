#!/usr/bin/env python3
"""unrolled_loop_audit.py -- find recipe-#28 candidates: functions where the
TARGET emits more runtime `slw` (variable shift) instructions than current.

Recipe #28: a `li rX,1; slw r0,rX,rBIT` (RUNTIME shift, 1<<bit over a run of
bit positions 0,1,2..) that the import hand-unrolled into manual constant
bit-tests (`if (flags & 1)... if (flags & 2)...`), which MWCC folds to
clrlwi / rlwinm / ori. The original was a small `for (bit=0; bit<N; bit++)
{ if (flags & (1<<bit)) ... }` loop that MWCC unrolls while KEEPING the slw
(it folds the induction-derived OFFSET to per-copy constants but does not
re-fold `1<<bit`). Rewrite the manual unroll as the for-loop. Also covers a
running-mask `mask <<= 1` variable (-> strength-reduced rlwinm) that should be
spelled `(1 << k)` inline.

  Confirmed: sky skyFn_80088c94 69.8->99.2 (two loops), skyFn_80089710
  80.2->86.9.

  GUARD (#28): only fires when the per-iteration body is ~<=4 simple instrs;
  a larger body makes MWCC keep a REAL loop (1 slw, not N) and the manual
  unroll fold `1<<const` -- such fns sit ~66-70%, bank them. Watch the
  while-PREDICATE variant (objfsa RomCurve_*: the `1<<bit` lives in a
  multi-term `while(!(...))` predicate that needs a predicate-loop
  restructure, not a body for-loop).

NOTE: this counts the 3-register runtime `slw` ONLY -- it excludes `slwi`
(the rlwinm-alias constant shift the disassembler also prints as "slw...").

*** STALE-.o CAVEAT: run after a FULL `ninja` build (same as callset_audit). ***

Usage:
    python3 tools/unrolled_loop_audit.py [--unit-filter SUBSTR] [--limit N]
"""
import argparse
import json
import os
import re
import subprocess

OBJDUMP = "build/binutils/powerpc-eabi-objdump"
REPORT = "build/GSAE01/report.json"


def slw_counts(path):
    """{sym: count of runtime `slw` (3-reg, not slwi)}."""
    try:
        out = subprocess.run([OBJDUMP, "-d", path], capture_output=True,
                             text=True, timeout=120).stdout
    except Exception:
        return {}
    res, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if m:
            cur = m.group(1)
            res[cur] = 0
            continue
        if cur:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].strip().split()[0:1] == ["slw"]:
                res[cur] += 1
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit-filter", default="")
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()

    d = json.load(open(REPORT))
    out = []
    for u in d["units"]:
        name = u["name"]
        if args.unit_filter and args.unit_filter not in name:
            continue
        sp = u.get("metadata", {}).get("source_path")
        parts = [f for f in u.get("functions", [])
                 if f.get("fuzzy_match_percent", 100) < 100]
        if not sp or not parts:
            continue
        rel = sp[4:] if sp.startswith("src/") else sp
        if not rel.endswith(".c"):
            continue
        tgt = "build/GSAE01/obj/" + rel[:-2] + ".o"
        src = "build/GSAE01/src/" + rel[:-2] + ".o"
        if not (os.path.exists(tgt) and os.path.exists(src)):
            continue
        ts, cs = slw_counts(tgt), slw_counts(src)
        for f in parts:
            n = f["name"]
            if ts.get(n, 0) > cs.get(n, 0):
                out.append((f.get("fuzzy_match_percent", 100),
                            ts.get(n, 0), cs.get(n, 0), name, n))
    out.sort()
    for pct, t, c, un, n in out[:args.limit]:
        print("%5.1f  Tslw=%d Cslw=%d  %-40s %s"
              % (pct, t, c, un.replace("main/main/", ""), n))
    print("TOTAL", len(out))


if __name__ == "__main__":
    main()
