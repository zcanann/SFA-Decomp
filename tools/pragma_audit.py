#!/usr/bin/env python3
"""pragma_audit.py -- find <100% fns whose effective pragma state is an
OUTLIER against their unit's majority state.

Rationale (harvester-7's CFchuckobj rule, industrialized on pi_dolphin):
in files with PARTIAL pragma coverage, low-fuzzy fns frequently sit OUTSIDE
the wrapped regions and compile scheduling/peephole-ON against OFF targets.
A per-fn recipe-#1 wrap alone has been worth +3 to +26pp (pi_dolphin:
textureFn_8004c264 96.7->100, selectTexture 94.5->100 from one build).
Check this BEFORE any shape work on a partial.

Semantics:
- Pragma state is modeled as a STACK per kind (recipe #1: `reset` POPS and
  restores the SURROUNDING state -- it is NOT reset-to-default). `on`/`off`
  push. A fn between an outer `off` and an inner `reset` is still `off`.
- A fn whose effective state differs from its unit's MAJORITY state is an
  outlier candidate. This is a TRIAGE signal, not a verdict: A/B the
  opposite-state wrap and keep it only if the fn score moves UP.
- INERT-WRAP CAVEAT (task #173 sweep): a wrap that does not change the .o
  is dead weight -- never keep a wrap whose A/B is score-neutral. Also note
  the recipe-#1 caveats: peephole-off can kill jump tables; the
  scheduling/peephole choice is PER-FUNCTION (A/B both pragmas separately).
- The fn-definition detector is heuristic (col-0 definition lines); odd
  formatting can be missed. Trust the A/B, not this listing.

Usage:
  python3 tools/pragma_audit.py [--max-pct N] [--unit-filter SUBSTR]
                                [--all]   # include non-outliers in listing
"""
import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VERSION = "GSAE01"

PRAGMA_RE = re.compile(r"\s*#pragma\s+(scheduling|peephole)\s+(on|off|reset)")
FNCALL_RE = re.compile(r"(\w+)\s*\(")
KINDS = ("scheduling", "peephole")


def map_fn_states(path: Path):
    """Return {fnname: (line, sched_state, peep_state)} for one source file."""
    try:
        text = path.read_bytes().decode("latin-1")
    except FileNotFoundError:
        return {}
    state = {k: [] for k in KINDS}
    out = {}
    for ln, line in enumerate(text.split("\n"), 1):
        m = PRAGMA_RE.match(line)
        if m:
            kind, act = m.groups()
            if act == "reset":
                if state[kind]:
                    state[kind].pop()
            else:
                state[kind].append(act)
            continue
        if (
            line
            and line[0] not in " \t#/}"
            and "(" in line
            and ";" not in line
            and "=" not in line
            and not line.startswith("extern")
            and not line.startswith("typedef")
        ):
            m2 = FNCALL_RE.search(line)
            if m2:
                eff = tuple(
                    state[k][-1] if state[k] else "def-on" for k in KINDS
                )
                out[m2.group(1)] = (ln,) + eff
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pct", type=float, default=100.0)
    ap.add_argument("--unit-filter", default="")
    ap.add_argument("--all", action="store_true",
                    help="list every mapped partial, not just outliers")
    args = ap.parse_args()

    report = json.loads((REPO / "build" / VERSION / "report.json").read_text())
    config = json.loads((REPO / "build" / VERSION / "config.json").read_text())
    src_by_key = {}
    for u in config["units"]:
        name = u.get("name", "")
        if name.endswith(".c"):
            src_by_key[name[:-2]] = REPO / "src" / name

    rows = []
    for unit in report["units"]:
        uname = unit["name"]
        if args.unit_filter and args.unit_filter not in uname:
            continue
        src = None
        for key, path in src_by_key.items():
            if uname.endswith(key):
                src = path
                break
        if src is None:
            continue
        fnstate = map_fn_states(src)
        if not fnstate:
            continue
        mapped = [
            (f, fnstate[f["name"]])
            for f in unit.get("functions", [])
            if f["name"] in fnstate
        ]
        if not mapped:
            continue
        from collections import Counter

        maj = tuple(
            Counter(st[1 + i] for _, st in mapped).most_common(1)[0][0]
            for i in range(2)
        )
        for f, (ln, sch, pe) in mapped:
            pct = f["fuzzy_match_percent"]
            if pct >= args.max_pct or pct >= 100.0:
                continue
            outlier = (sch, pe) != maj
            if not outlier and not args.all:
                continue
            size = int(f.get("size", 0))
            potential = (100.0 - pct) * size / 100.0
            rows.append(
                (potential, pct, size, uname, f["name"], ln, sch, pe, maj)
            )

    rows.sort(reverse=True)
    print(f"{'pot.B':>7} {'pct':>7} {'size':>6}  unit / fn  (line, state vs majority)")
    for potential, pct, size, uname, fname, ln, sch, pe, maj in rows:
        print(
            f"{potential:7.0f} {pct:7.2f} {size:6d}  {uname} / {fname}"
            f"  (L{ln}, sched={sch}/peep={pe} vs maj={maj[0]}/{maj[1]})"
        )
    print(f"-- {len(rows)} listed")


if __name__ == "__main__":
    main()
