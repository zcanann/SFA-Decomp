#!/usr/bin/env python3
"""Does STATEMENT order key the register ASSIGNMENT once the allocator reuses?

Two measured laws are in tension and nobody had crossed them:

  * priced_classes.md **§27** (A86): "declaration order is the ONLY source key
    for the register assignment; statement order is the source key for emission
    ORDER."  Its control pinned declarations and permuted four assignment
    statements through all 24 orders -- one register assignment, 24 times.

  * `colouring_reach_control.py` (A99): once the live locals outnumber the
    callee-saved band the allocator must host several webs per register, and in
    that REUSE regime a declaration-order change stops being a permutation at
    all (259 NONFUNC / 31 NOTPERM / 10 PERM in 300 orders).

§27's control lives entirely in the NO-REUSE regime: four locals, four homes,
nothing to pack.  The open question was whether its law survives reuse, because
an allocator that packs by LIVE RANGE reads live ranges off the statement order.

IT DOES NOT SURVIVE, BUT REUSE IS NOT WHAT BREAKS IT.  Reuse turns out to be
irrelevant here: `reuse` and `stagger` below pack the band hard, give the run's
webs ten different death points, and still never move a home in 200 orders.
What breaks the law is the run's SHAPE.  §27's control -- and the first three
regimes here -- permute statements that are structurally IDENTICAL to each
other (`ci = gT[n+i]` eight times over), and no permutation of interchangeable
statements can change which webs interfere or what the value numberer sees.
The `hetero` regime differs only in that its eight statements have eight
different shapes, and it moves the band in 81 of 100 orders.  Real runs are
heterogeneous, and the real-code arm agrees: eight frontier rows, 64 legal
statement permutations, disassembled and compared band-signature to
band-signature, **31 ASSIGN / 33 BAND-HELD**.

So statement order IS a source key for the register assignment.  §27 measured a
body in which it could not be one and generalised.

THE DISCRIMINATOR is neither the score nor the raw instruction multiset.  A
statement move legitimately reshuffles VOLATILE registers and slides an address
base's materialisation without touching one named local's home -- the no-reuse
control does exactly that in 48 of 60 orders -- so a multiset comparison reports
"the assignment moved" when nothing of the sort happened.  The discriminator is
the CALLEE-SAVED BAND SIGNATURE (`saved_sig`): the stream restricted to lines
mentioning `r14`-`r31`, every volatile abstracted away.  It moves if and only if
some web's home moved.

  * ASSIGN   band signature differs  -> statement order keyed the colouring
  * SCRATCH  band held, volatiles moved
  * ORDER    whole multiset held, instructions resequenced

`--self-test` runs the POSITIVE CONTROL the verdict needs: the same bodies swept
on DECLARATION order, where `saved_sig` must report ASSIGN.  Without that arm a
flat statement-order result is indistinguishable from a blind instrument.

EVERY body's permuted run -- `hetero` included -- is pairwise INDEPENDENT by
construction: distinct non-address-taken locals on the left, and no local of the
run on any right-hand side.  So all n! orders are dependence-legal and each
permutation is semantics-preserving without needing a filter.  (The first
`hetero` draft read `h0` and `h3` inside the run, which makes most orders
use-before-definition; a control that changes the computation measures nothing.)

MEASURED RESULT (A100), 100 orders per regime:
    noreuse   0 ASSIGN     reuse   0 ASSIGN     stagger  0 ASSIGN
    hetero   81 ASSIGN / 15 SCRATCH / 4 ORDER
declaration-order positive control 50 of 50 ASSIGN.

The practical reading is NOT "sweep statement order for colouring": the
frontier sweep that followed this control built 5717 dependence-legal statement
orders over 37 non-bijective rows and improved nothing.  The tree already sits
at the statement-order optimum as well as the declaration-order one.  What the
control is for is stopping the next lane from pruning the axis on §27's law, and
from reading a flat synthetic as proof.

Usage:
  stmt_reuse_control.py --self-test      + the declaration-order positive control
  stmt_reuse_control.py --sweep N        N random statement orders per regime
"""
from __future__ import annotations

import argparse
import collections
import itertools
import random
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from colouring_reach_control import REPO, build
from perm_class_scan import permutation

# --------------------------------------------------------------- the bodies
# NO-REUSE: 6 locals, all live across the calls, band is 18 wide -> no packing.
NOREUSE_RUN = ["c%d = gT[n+%d];" % (i, i) for i in range(6)]
NOREUSE = """extern int fetch(int);
extern void sink(int,int,int,int);
extern int gT[64];

int probe(int n)
{
    int c0, c1, c2, c3, c4, c5, r;
    r = 0;
%s
    sink(c0, c1, c2, c3);
    r += c4 + c5 + c0 * c3;
    sink(c1, c2, c4, c5);
    return r + c0 + c1 + c2 + c3 + c4 + c5;
}
"""

# REUSE: 20 locals live across calls plus an accumulator -> the band (18) must
# host more than one web per register, which is A99's regime.
REUSE_RUN = ["a%d = gT[n+%d];" % (i, i) for i in range(10)]
REUSE = """extern int fetch(int);
extern void sink(int,int,int,int);
extern int gT[64];

int probe(int n)
{
    int a0, a1, a2, a3, a4, a5, a6, a7, a8, a9;
    int b0, b1, b2, b3, b4, b5, b6, b7, b8, b9;
    int r;
    r = 0;
%s
    sink(a0 + a1, a2 + a3, a4 + a5, a6 + a7);
    r += a8 + a9 + a0 * a3;
    sink(a1, a4, a7, a9);
    r ^= a2 - a5 + a6 * a8;
    b0 = fetch(r); b1 = fetch(r + 1); b2 = fetch(r + 2); b3 = fetch(r + 3);
    b4 = fetch(r + 4); b5 = fetch(r + 5); b6 = fetch(r + 6); b7 = fetch(r + 7);
    b8 = fetch(r + 8); b9 = fetch(r + 9);
    sink(b0 + b1, b2 + b3, b4 + b5, b6 + b7);
    r += b8 + b9 + b0 * b3;
    sink(b1, b4, b7, b9);
    r ^= b2 - b5 + b6 * b8;
    return r + a0 + a2 + a5 + a9 + b0 + b3 + b6;
}
"""

# STAGGERED REUSE: same packing pressure, but the run's ten webs now DIE at ten
# different points, so a permutation of the run changes each web's live range
# by a different amount.  This is the strongest form of the "the allocator packs
# by live range and statement order sets live ranges" hypothesis.
STAGGER_RUN = ["a%d = gT[n+%d];" % (i, i) for i in range(10)]
STAGGER = """extern int fetch(int);
extern void sink(int,int,int,int);
extern int gT[64];

int probe(int n)
{
    int a0, a1, a2, a3, a4, a5, a6, a7, a8, a9;
    int b0, b1, b2, b3, b4, b5, b6, b7, b8, b9;
    int r;
    r = fetch(n);
%s
    sink(a0, a1, a2, a3);
    b0 = fetch(r); b1 = fetch(r + 1); b2 = fetch(r + 2); b3 = fetch(r + 3);
    b4 = fetch(r + 4); b5 = fetch(r + 5); b6 = fetch(r + 6); b7 = fetch(r + 7);
    b8 = fetch(r + 8); b9 = fetch(r + 9);
    sink(b0, b1, b2, b3);
    r += a4 + a5;
    sink(b4, b5, b6, b7);
    r ^= a6 + a7 + a8 + a9 + b8 + b9;
    return r;
}
"""

# HETEROGENEOUS: the run's statements no longer share one shape.  This is what
# separates the synthetic regimes above from real code, and it is the regime
# that REFUTES the law: when every statement of the run is the same shape over
# the same kind of operand, no permutation of them can change which webs
# interfere or what the value numberer sees, so the band cannot move for
# reasons that have nothing to do with reuse.  Real runs are not like that.
HETERO_RUN = [
    "h0 = gT[n];",
    "h1 = n + 7;",
    "h2 = gT[n + 3] * 5;",
    "h3 = n - 2;",
    "h4 = gT[(n + 9) & 15];",
    "h5 = gT[n] + gT[n + 2];",
    "h6 = gT[n + 1] ^ 0x40;",
    "h7 = n * 3;",
]
HETERO = """extern int fetch(int);
extern void sink(int,int,int,int);
extern int gT[64];

int probe(int n)
{
    int h0, h1, h2, h3, h4, h5, h6, h7;
    int a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11;
    int r;
    r = fetch(n);
    a0 = fetch(r); a1 = fetch(r + 1); a2 = fetch(r + 2); a3 = fetch(r + 3);
    a4 = fetch(r + 4); a5 = fetch(r + 5); a6 = fetch(r + 6); a7 = fetch(r + 7);
    a8 = fetch(r + 8); a9 = fetch(r + 9); a10 = fetch(r + 10); a11 = fetch(r + 11);
%s
    sink(h0, h1, h2, h3);
    sink(a0 + a1, a2 + a3, a4 + a5, a6 + a7);
    r += h4 + h5 + h6 + h7 + a8 + a9 + a10 + a11;
    sink(h1, h4, a2, a7);
    return r + h0 + h2 + h3 + h5 + h6 + h7 + a0 + a5 + a11;
}
"""

REGIMES = {
    "noreuse": (NOREUSE, NOREUSE_RUN),
    "reuse": (REUSE, REUSE_RUN),
    "stagger": (STAGGER, STAGGER_RUN),
    "hetero": (HETERO, HETERO_RUN),
}


def render(regime, order):
    body, run = REGIMES[regime]
    return body % "".join("    %s\n" % run[i] for i in order)


SAVED = re.compile(r"\br(\d+)\b")


def saved_sig(stream):
    """The stream restricted to the CALLEE-SAVED band, scratch abstracted.

    A statement move can legitimately shuffle scratch registers and slide the
    materialisation of an address base without touching a single named local's
    home -- the no-reuse control shows exactly that.  Comparing raw multisets
    therefore reports "the assignment moved" when nothing of the sort happened.
    The band signature keeps only lines that mention a saved register and
    replaces every volatile register with a placeholder, so it moves if and
    only if some web's HOME moved."""
    out = collections.Counter()
    for line in stream:
        if line.startswith("RELOC"):
            continue
        regs = [int(x) for x in SAVED.findall(line)]
        if not any(14 <= r <= 31 for r in regs):
            continue
        out[SAVED.sub(lambda m: m.group(0) if 14 <= int(m.group(1)) <= 31 else "rS",
                      line)] += 1
    return out


def classify(base, other):
    """The BAND SIGNATURE is the discriminator, not the raw multiset."""
    if base == other:
        return "IDENTICAL"
    if saved_sig(base) != saved_sig(other):
        return "ASSIGN"
    if collections.Counter(base) == collections.Counter(other):
        return "ORDER"                      # same instructions, resequenced
    return "SCRATCH"                        # band held, volatiles/addressing moved


def sweep(regime, orders, workdir):
    run = REGIMES[regime][1]
    base = build(render(regime, range(len(run))), workdir, regime + "_base")
    counts, example = collections.Counter(), {}
    for n, o in enumerate(orders):
        cls = classify(base, build(render(regime, o), workdir, "%s_%d" % (regime, n)))
        counts[cls] += 1
        example.setdefault(cls, list(o))
    return counts, example


REAL_ROWS = [
    ("dlls/objects/488_SB_Galleon/SB_Galleon.c", "SB_Galleon_updateFlight"),
    ("main/objhits.c", "ObjHits_CheckHitVolumes"),
    ("dlls/engine/6/6.c", "sky2_run"),
    ("dlls/engine/71/71.c", "pathcam_buildWindowSamples"),
    ("main/gametext.c", "gameTextWrapLines"),
    ("dlls/objects/229/229.c", "Shield_update"),
    ("main/pi_pathsearch.c", "pathSearchAddNeighbor"),
    ("main/dll_80136a40.c", "debugPrintDrawRecord"),
]


def real_control(per_row=8, version="GSAE01"):
    """The arm that actually decides it: real frontier bodies, real objects.

    A synthetic can only show that the axis reaches the band in SOME body.  This
    permutes dependence-legal statement runs in eight sub-100 rows, rebuilds the
    unit, disassembles the symbol out of the unit's own object and compares band
    signatures -- no score anywhere in the loop, because a score is a summary and
    two different colourings can share one.  Every file is restored and rebuilt
    in a `finally`."""
    import stmt_sweep as SS
    from brute_match import (find_function_body, rebuild, objdump_norm,
                             objdump_paths, find_objdump)
    from function_objdump import load_units, resolve_unit

    units = load_units(REPO / "build" / version / "config.json")
    objdump = find_objdump()
    rng = random.Random(5)
    total = collections.Counter()
    for unit, sym in REAL_ROWS:
        cfg = resolve_unit(units, unit)
        src = REPO / "src" / cfg["name"].replace("\\", "/")
        _tgt, ours = objdump_paths(cfg, version)
        original = src.read_bytes()
        text = original.decode("latin-1")
        bo, be = find_function_body(text, sym)
        runs = [r for r in SS.collect_runs(text, bo, be, sym, 2)
                if len(r["items"]) >= 3]
        if not runs:
            print("   %-46s no run of 3+; SKIPPED (not cleared)" % sym)
            continue

        def emit(orders):
            out = text
            for ri in sorted(orders, reverse=True):
                r = runs[ri]
                it, order = r["items"], orders[ri]
                body = it[order[0]].lstrip() + "".join(
                    "\n" + r["indent"] + it[k].lstrip() for k in order[1:])
                out = out[:r["start"]] + body + out[r["end"]:]
            return out

        try:
            rebuild(cfg["object"], version)
            base = saved_sig(objdump_norm(objdump, ours, sym))
            seen = collections.Counter()
            for _ in range(per_row):
                orders = {}
                for ri, r in enumerate(runs):
                    n = len(r["items"])
                    for _try in range(50):
                        o = tuple(rng.sample(range(n), n))
                        if o != tuple(range(n)) and SS.valid(o, r["deps"]):
                            orders[ri] = o
                            break
                if not orders:
                    break
                new = emit(orders)
                if new == text:
                    seen["NO-OP"] += 1
                    continue
                src.write_bytes(new.encode("latin-1"))
                rebuild(cfg["object"], version)
                seen["ASSIGN" if saved_sig(objdump_norm(objdump, ours, sym)) != base
                     else "BAND-HELD"] += 1
            total.update(seen)
            print("   %-46s %s" % (sym, dict(seen)))
        finally:
            src.write_bytes(original)
            rebuild(cfg["object"], version)
    print("   REAL TOTAL %s" % dict(total))
    return total


def decl_control(k, workdir):
    """POSITIVE CONTROL: `saved_sig` must SEE a declaration-order change.

    Reuses `colouring_reach_control`'s two bodies, whose only source key for the
    band is the declaration list.  If this arm is not ASSIGN across the board the
    statement-order result above means nothing."""
    from colouring_reach_control import (NOREUSE as CR_NOREUSE, REUSE as CR_REUSE,
                                         REUSE_NAMES)
    ok = True
    for tag, body, names in (("noreuse", CR_NOREUSE, list("abcdefghi")),
                             ("reuse", CR_REUSE, list(REUSE_NAMES))):
        render = lambda o: body % ("    int " + ", ".join(o) + ";\n")
        base = build(render(names), workdir, "pc_" + tag)
        counts = collections.Counter()
        for i in range(k):
            o = random.sample(names, len(names))
            counts[classify(base, build(render(o), workdir, "pc_%s_%d" % (tag, i)))] += 1
        print("   decl-order %-8s %s" % (tag, dict(counts)))
        ok = ok and counts["ASSIGN"] == k
    print("   POSITIVE CONTROL %s" % ("PASSED" if ok else "FAILED -- instrument is blind"))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--sweep", type=int, default=0)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--real", action="store_true",
                    help="the real-code arm: permute statement runs in eight "
                         "frontier rows and compare band signatures")
    a = ap.parse_args()
    random.seed(a.seed)

    if a.real:
        print("== real frontier bodies, statement order, band signature")
        real_control()
        return 0

    with tempfile.TemporaryDirectory(prefix="stmtreuse_") as td:
        wd = Path(td)
        total = collections.Counter()
        for regime in ("noreuse", "reuse", "stagger", "hetero"):
            n = len(REGIMES[regime][1])
            if a.self_test and regime == "noreuse":
                orders = list(itertools.permutations(range(n)))       # 720
            else:
                k = a.sweep or 100
                orders = [tuple(random.sample(range(n), n)) for _ in range(k)]
            counts, example = sweep(regime, orders, wd)
            total.update(counts)
            print("== %s regime, %d locals in the run, %d orders" % (regime, n, len(orders)))
            for cls, c in counts.most_common():
                print("   %-16s %4d   e.g. %s" % (cls, c, example[cls]))
            print()
        print("== statement order, all regimes: %s" % dict(total))
        print("== declaration-order positive control")
        if not decl_control(25, wd):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
