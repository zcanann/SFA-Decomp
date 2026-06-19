#!/usr/bin/env python3
"""Rebuild touched units + re-split + filtered objdiff report; fail on regression.

Workaround for an unrelated upstream compile break (objprint.c et al.) that
blocks the full `ninja report.json`: we rebuild only the units changed in the
working tree, re-split the target objects from symbols.txt, then run objdiff-cli
on a config filtered to units whose base .o exists, and compare per-unit fuzzy%
against build/GSAE01/lbl_baseline.json.

Usage: lbl_build_verify.py            # uses `git diff --name-only` for touched .c
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)


def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def touched_units():
    out = run(["git", "diff", "--name-only", "HEAD"]).stdout.split()
    return [f for f in out if f.startswith("src/") and f.endswith(".c")]


def obj_for(src):
    return f"build/GSAE01/{src[:-2]}.o"


def main():
    units = touched_units()
    objs = [obj_for(u) for u in units]
    print(f"touched units: {len(units)}")
    # re-split target objects from symbols.txt (dtk; no C compile)
    r = run(["ninja", "build/GSAE01/config.json"])
    if r.returncode != 0:
        print("config.json re-split FAILED:\n", r.stderr[-2000:]); sys.exit(1)
    # rebuild only touched unit .o explicitly (avoids the broken-unit cascade)
    for o in objs:
        Path(o).unlink(missing_ok=True)
    failed = []
    if objs:
        run(["ninja", "-k", "0"] + objs)  # -k0: keep going so all failures are visible
        failed = [o for o in objs if not Path(o).exists()]
        if failed:
            print("BUILD FAILED for (revert these units' renames before commit):")
            for m in failed:
                print("  ", m)
    # filtered objdiff report
    cfg = json.load(open("objdiff.json"))
    cfg["units"] = [u for u in cfg["units"]
                    if not (u.get("base_path") and not os.path.exists(u["base_path"]))]
    json.dump(cfg, open("/tmp/objdiff_filtered.json", "w"))
    bak = Path("objdiff.json").read_bytes()
    Path("objdiff.json").write_text(json.dumps(cfg))
    try:
        r = run(["build/tools/objdiff-cli", "report", "generate", "-o", "build/GSAE01/report.json"])
    finally:
        Path("objdiff.json").write_bytes(bak)
    if r.returncode != 0:
        print("report FAILED:\n", r.stderr[-2000:]); sys.exit(1)
    def regressions():
        base = json.load(open("build/GSAE01/lbl_baseline.json"))
        cur = {u["name"]: u["measures"].get("fuzzy_match_percent")
               for u in json.load(open("build/GSAE01/report.json"))["units"]}
        return [(n, base[n], cur[n]) for n in cur
                if n in base and cur[n] is not None and base[n] is not None and cur[n] < base[n] - 1e-6], cur

    reg, cur = regressions()
    # Stale-.o false alarms: a flagged unit we didn't touch may just need rebuilding
    # (its .o went stale from an upstream shared-header change). Rebuild flagged units
    # fresh and re-report before treating any regression as real.
    if reg:
        objdiff = json.load(open("objdiff.json"))
        by_name = {u["name"]: u for u in objdiff["units"]}
        rebuilt = []
        for n, _, _ in reg:
            u = by_name.get(n)
            if u and u.get("base_path"):
                Path(u["base_path"]).unlink(missing_ok=True)
                rebuilt.append(u["base_path"])
        if rebuilt:
            run(["ninja", "-k", "0"] + rebuilt)
            run(["build/tools/objdiff-cli", "report", "generate", "-o", "build/GSAE01/report.json"])
            reg, cur = regressions()
    if reg:
        print(f"REGRESSIONS ({len(reg)}):")
        for n, b, c in sorted(reg, key=lambda x: x[2] - x[1])[:30]:
            print(f"  {n}: {b:.3f} -> {c:.3f}")
        sys.exit(1)
    if failed:
        print(f"NOTE: {len(failed)} touched unit(s) failed to build (see above) — revert them.")
        sys.exit(2)
    print(f"OK: no regressions across {len(cur)} units ({len(units)} rebuilt)")


if __name__ == "__main__":
    main()
