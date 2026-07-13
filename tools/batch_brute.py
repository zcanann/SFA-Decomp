#!/usr/bin/env python3
"""Batch-run brute_match --apply-best across all sub-100 -O4,p game functions.
Cheap (asm-free, self-measuring) sweep for the one reliably-yielding lever:
decl-order register re-homing. Applies any variant that strictly beats baseline;
logs applied wins for review + path-scoped commit. Skips hot/owned files.

Usage: python3 tools/batch_brute.py [min_fuzzy] [--exclude f1,f2] [--budget N]
Then review /tmp/batch_brute.log; git diff shows applied wins to verify+commit.
"""
import json, subprocess, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VER = "GSAE01"
MIN = float(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else 90.0
BUDGET = 100.0
EXCLUDE_UNITS = {"player", "dll_0000_gameui", "objseq", "objhits", "gameloop",
                 "track_dolphin", "newshadows", "shader", "bossdrakor"}
for i, a in enumerate(sys.argv):
    if a == "--budget" and i + 1 < len(sys.argv):
        BUDGET = float(sys.argv[i + 1])
    if a == "--exclude" and i + 1 < len(sys.argv):
        EXCLUDE_UNITS |= set(sys.argv[i + 1].split(","))

report = json.load(open(REPO / f"build/{VER}/report.json"))
# skip noopt/audio/dolphin: brute_match's decl re-home only bites in -O4,p; and
# skip units where we can't cheaply tell config. Use basename heuristic.
targets = []
for u in report["units"]:
    un = u.get("name", "")
    if not un.startswith("main/"):
        continue
    if any(x in un for x in ("dolphin/", "MSL", "audio", "/play", "dll_0000_game")):
        continue
    base = Path(un[len("main/"):]).stem
    if base in EXCLUDE_UNITS:
        continue
    for f in u.get("functions", []):
        fz = f.get("fuzzy_match_percent", 100.0)
        if MIN <= fz < 100.0:
            targets.append((fz, base, f.get("name", "")))
targets.sort()  # lowest fuzzy first = most headroom

log = open("/tmp/batch_brute.log", "w")
def out(s):
    print(s); log.write(s + "\n"); log.flush()

out(f"# batch_brute: {len(targets)} sub-100 candidates >= {MIN}%, budget {BUDGET}s each")
wins = []
for fz, base, sym in targets:
    try:
        r = subprocess.run(
            ["python3", "tools/brute_match.py", base + ".c", sym,
             "--strategy", "all", "--time-budget", str(BUDGET), "--apply-best"],
            cwd=REPO, capture_output=True, text=True, timeout=BUDGET + 240)
    except subprocess.TimeoutExpired:
        out(f"  TIMEOUT {base} {sym}")
        continue
    tail = r.stdout.strip().splitlines()[-4:] if r.stdout else []
    applied = any("APPLIED best variant" in ln for ln in (r.stdout or "").splitlines())
    if applied:
        newfz = ""
        for ln in tail:
            if "APPLIED" in ln:
                newfz = ln
        out(f"  *** WIN {base} {sym} ({fz:.3f}) :: {newfz}")
        wins.append((base, sym, fz))
    elif r.returncode != 0 or "report generate failed" in (r.stderr or "") + (r.stdout or ""):
        out(f"  skip {base} {sym} (measure-fail/parse: {(r.stderr or '')[:60].strip()})")
    else:
        out(f"  --   {base} {sym} ({fz:.3f}) welded")

out(f"\n# DONE. {len(wins)} wins applied (in working tree, verify+commit):")
for base, sym, fz in wins:
    out(f"  {base}.c {sym} (was {fz:.3f})")
