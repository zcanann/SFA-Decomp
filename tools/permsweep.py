"""Permute a block of local declarations and measure each ordering by BYTES.

!! READ THIS BEFORE TRUSTING AN "INERT" RESULT !!
This tool ranks by POSITIONAL INSTRUCTION-DIFF COUNT, which is NOT a proxy for
fuzzy_match_percent -- the two can move in OPPOSITE directions.  Measured case:
in shader.c mapLoadUnloadObjects an address-form rewrite took positional diffs
419 -> 418 while the score fell 96.87 -> 94.73; and a diff-gated declaration
sweep of that same function reported EVERY ordering inert (all 419) while the
identical sweep gated on report.json found a +0.073 win.  A uniform diff count
across permutations therefore does NOT establish that declaration order is
inert.

Use this only to find byte-IDENTICAL orderings (ndiff==0, which is exact).
For "which ordering scores best", use tools/brute_match.py --strategy moves,
which gates on true objdiff fuzzy_match_percent from report.json.

The declaration-order lever permutes saved-register assignment among locals
with disjoint live ranges.  This sweeps orderings of a contiguous decl block
and scores every one against the retail object.

Gating is on EXTRACTED FUNCTION BYTES via fnbytes.compare().  A build failure
or an absent symbol is recorded as ERROR and never as a match -- several
tools in this repo print nothing both when a function matches and when the
build failed, which has produced spurious "match" reports before.

Usage:
  python3 tools/permsweep.py <file.c> <unit> <symbol> --lines A:B [--max N]
      A:B is the 1-based inclusive line range of the decl block to permute.
      Lines must be independent declarations (no initializers depending on
      each other).  ARRAY declarations set the stack frame layout -- permuting
      them moves stack offsets, so keep them out of the range unless that is
      what you intend to test.

  --keep-best   leave the best-scoring ordering in the file (default: restore)
  --dry-run     print the permutations without building

Always restores the original file on exit unless --keep-best improved things.
"""
from __future__ import annotations

import argparse
import itertools
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fnbytes import REPO, disassemble, find_unit, load_units, objdump_path


def compare(unit_q: str, symbol: str, version: str = "GSAE01"):
    """-> (ndiff, ntgt, ncur). ndiff==0 and sizes equal means byte-identical.

    Raises LookupError on any condition that means "no result".
    """
    units = load_units(REPO / "build" / version / "config.json")
    unit = find_unit(units, unit_q)
    od = objdump_path()
    tgt = disassemble(od, REPO / Path(unit["object"]), symbol)
    cur = disassemble(
        od,
        REPO / Path(unit["object"].replace(f"build/{version}/obj/", f"build/{version}/src/")),
        symbol,
    )
    if not tgt:
        raise LookupError(f"no instructions for {symbol} in target")
    if not cur:
        raise LookupError(f"no instructions for {symbol} in current (build failed / inlined)")
    n = min(len(tgt), len(cur))
    ndiff = sum(1 for i in range(n) if tgt[i][0] != cur[i][0]) + abs(len(tgt) - len(cur))
    return ndiff, len(tgt), len(cur)


def rebuild(obj_rel: str) -> bool:
    obj = REPO / obj_rel
    obj.unlink(missing_ok=True)
    # Go through the build mutex: a bare `ninja` here races parallel matching
    # agents and corrupts .ninja_log / loses .d writes, which shows up as
    # spurious BUILD-FAIL entries mid-sweep.
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "tools/locked_ninja.sh", obj_rel],
        cwd=REPO, capture_output=True, text=True
    )
    return proc.returncode == 0 and obj.is_file()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("unit")
    ap.add_argument("symbol")
    ap.add_argument("--lines", required=True, help="1-based inclusive A:B")
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--max", type=int, default=0, help="cap permutations")
    ap.add_argument("--keep-best", action="store_true")
    ap.add_argument("--mode", choices=("perm","moves"), default="perm",
                    help="perm: all n! orderings. moves: O(n^2) single-decl relocations")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src = REPO / args.source
    original = src.read_bytes()
    text = original.decode("utf-8", errors="surrogateescape").split("\n")

    a, b = (int(x) for x in args.lines.split(":"))
    block = text[a - 1 : b]
    if not all(ln.strip().endswith(";") for ln in block):
        print("ERROR: every line in the range must be a simple declaration", file=sys.stderr)
        return 2
    print(f"permuting {len(block)} declarations:")
    for ln in block:
        print("   ", ln.strip())

    units = load_units(REPO / "build" / args.version / "config.json")
    obj_rel = find_unit(units, args.unit)["object"].replace(
        f"build/{args.version}/obj/", f"build/{args.version}/src/"
    )

    n = len(block)
    if args.mode == "moves":
        # Every "lift one declaration, reinsert it at position j" ordering.
        # O(n^2) instead of n!, and it is enough to retarget a single local's
        # saved-register home -- which is what a 2-register swap needs.
        seen, perms = set(), []
        for i in range(n):
            for j in range(n):
                rest = [k for k in range(n) if k != i]
                cand = tuple(rest[:j] + [i] + rest[j:])
                if cand not in seen:
                    seen.add(cand)
                    perms.append(cand)
    else:
        perms = list(itertools.permutations(range(n)))
    if args.max:
        perms = perms[: args.max]
    print(f"{len(perms)} permutations, object {obj_rel}\n")
    if args.dry_run:
        return 0

    results = []
    best = None
    try:
        for idx, perm in enumerate(perms):
            text[a - 1 : b] = [block[i] for i in perm]
            src.write_bytes("\n".join(text).encode("utf-8", errors="surrogateescape"))

            if not rebuild(obj_rel):
                print(f"[{idx:4d}] {perm}  BUILD-FAIL")
                results.append((None, perm))
                continue
            try:
                ndiff, nt, nc = compare(args.unit, args.symbol, args.version)
            except LookupError as exc:
                print(f"[{idx:4d}] {perm}  ERROR {exc}")
                results.append((None, perm))
                continue

            tag = "MATCH" if ndiff == 0 else f"diffs {ndiff}"
            if best is None or ndiff < best[0]:
                best = (ndiff, perm)
                tag += "  <-- best"
            print(f"[{idx:4d}] {perm}  {tag}")
            results.append((ndiff, perm))
            if ndiff == 0:
                break
    finally:
        if args.keep_best and best and best[0] == 0:
            text[a - 1 : b] = [block[i] for i in best[1]]
            src.write_bytes("\n".join(text).encode("utf-8", errors="surrogateescape"))
            rebuild(obj_rel)
            print(f"\nkept MATCHING ordering {best[1]}")
        else:
            src.write_bytes(original)
            rebuild(obj_rel)
            print("\nrestored original source")

    scored = [r for r in results if r[0] is not None]
    print(f"\n{len(scored)}/{len(results)} permutations scored ({len(results)-len(scored)} errors)")
    if best:
        print(f"best: diffs {best[0]} at {best[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
