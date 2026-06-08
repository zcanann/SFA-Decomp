#!/usr/bin/env python3
"""callset_audit.py -- find functions whose CALL SET (bl reloc targets)
diverges from the target binary. The call-set-diff field (task #21).

This is the highest-yield triage signal on the project right now: a per-fn
diff of the set of `bl` reloc targets in target.o vs current.o surfaces two
recurring import-damage sub-classes, both routinely worth +15pp/fn:

  (1) AUTO-INLINE VICTIM  -- a TGT-only call is a function DEFINED IN THE
      SAME TU that the caller auto-inlined (so current emits the callee's
      leaf calls instead of one `bl`). Shows as TGT-only={Helper} and often
      CUR-only={Helper's leaves}. FIX: wrap the callee in
      `#pragma dont_inline on` ... `#pragma dont_inline reset` (BALANCED;
      inside a push/pop block the pop restores it, no explicit reset needed).
      Confirmed: drakorhoverpad_init (+16.7pp), skyFn_80088c94 into Sky_func03
      (+15pp), objSeqFindConditional, newclouds_snowKillSnowCloud,
      findRomCurvePointNearObject.

      *** dont_inline CAUTION (from CLAUDE.md) *** -- dont_inline disables
      inlining in BOTH directions: it stops the fn being inlined into callers
      AND stops it inlining ITS OWN leaves. Only wrap a callee that does NOT
      itself need to inline same-TU leaves that target keeps inlined; else
      use the SOURCE-ORDER fix (place the caller BEFORE the helper's
      definition so MWCC can't inline upward). After wrapping, VERIFY the
      callee's own call set stayed clean (no leaf-inline regression) and A/B
      that no OTHER caller regressed (a helper inlined into several callers in
      target will regress them all). A/B IS MANDATORY -- some "victims" are
      false (target actually inlines; e.g. isSpace into textMeasureFn
      regressed when wrapped).

  (2) WRONG-SYMBOL PHANTOM -- the import called a Ghidra phantom extern
      (FUN_<addr>, or a mis-suffixed name like PSMTXMultVecSR2) that resolves
      to a DIFFERENT address than the canonical symbol target calls. Often a
      genuine BEHAVIORAL BUG (wrong function at runtime). FIX: replace the
      call with the canonical symbol. VERIFY by reading the target's bl order
      (function_objdump.py) and mapping each call by body order + arg shape;
      cross-check addresses in config/GSAE01/symbols.txt (the FUN_<addr>
      name encodes its wrong address). Confirmed behavioral bugs:
      staffAction fn_801659B8 (FUN_8016693c->fn_80166444), titleDoLoadSave
      (FUN_80244e58->OSSetSaveRegion), CameraModeViewfinder_free (ALL SIX
      calls wrong), Obj_SteerVelocityTowardVector (PSMTXMultVecSR2->SR).
      Spurious discarded calls (a trailing FUN_xxx() / a doubled getter that
      target CSEs) are a sub-shape -- drop/hoist them (ring_update,
      SHthorntail_update, vortex_render).

  NOT a clean call-set fix: when CUR-only is a SET of unrelated calls with
  no same-TU helper to inline (e.g. Landed_Arwing_SeqFn's loadMapAndParent/
  unlockLevel/...), the import MIS-STRUCTURED the function's logic -- that's
  a reconstruction job, treat separately.

  Parked: the MSL math cluster (savefpr/restfpr-only diffs -> #99
  optimize_for_size) is a delicate -O0 batch, left for a dedicated session.

*** STALE-.o CAVEAT -- run after a FULL `ninja` build. *** The audit objdumps
build/GSAE01/src/<unit>.o, which is only as fresh as the last build of that
unit. A stale .o (e.g. one you rebuilt under an experiment and reverted in
source) produces FALSE POSITIVES (isSpace was one). Rebuild everything, then
audit.

Usage:
    python3 tools/callset_audit.py [--max-pct N] [--unit-filter SUBSTR]
                                   [--limit N] [--same-tu-only]
"""
import argparse
import json
import os
import re
import subprocess
from collections import Counter

OBJDUMP = "build/binutils/powerpc-eabi-objdump"
REPORT = "build/GSAE01/report.json"
CONFIG = "build/GSAE01/config.json"


def bl_targets(path):
    """Return {symbol: [reloc-target, ...]} for every fn in an object."""
    try:
        out = subprocess.run([OBJDUMP, "-dr", path], capture_output=True,
                             text=True, timeout=120).stdout
    except Exception:
        return {}
    res, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if m:
            cur = m.group(1)
            res[cur] = []
            continue
        if cur and "R_PPC_REL24" in line:
            tgt = line.split("R_PPC_REL24")[1].strip().split()[0]
            res[cur].append(re.sub(r"\+0x[0-9a-f]+", "", tgt))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pct", type=float, default=100.0,
                    help="only fns below this fuzzy_match_percent")
    ap.add_argument("--unit-filter", default="",
                    help="only units whose report name contains this substring")
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--same-tu-only", action="store_true",
                    help="only show inline-victim candidates (TGT-only call "
                         "is a function defined in the same .o)")
    args = ap.parse_args()

    d = json.load(open(REPORT))
    out = []
    for u in d["units"]:
        name = u["name"]
        if args.unit_filter and args.unit_filter not in name:
            continue
        sp = u.get("metadata", {}).get("source_path")
        parts = [f for f in u.get("functions", [])
                 if f.get("fuzzy_match_percent", 100) < args.max_pct]
        if not sp or not parts:
            continue
        rel = sp[4:] if sp.startswith("src/") else sp
        if not rel.endswith(".c"):
            continue
        tgt = "build/GSAE01/obj/" + rel[:-2] + ".o"
        src = "build/GSAE01/src/" + rel[:-2] + ".o"
        if not (os.path.exists(tgt) and os.path.exists(src)):
            continue
        tc, cc = bl_targets(tgt), bl_targets(src)
        local_fns = set(tc) | set(cc)  # functions defined in this .o
        for f in parts:
            n = f["name"]
            ta, ca = Counter(tc.get(n, [])), Counter(cc.get(n, []))
            if ta == ca:
                continue
            only_t, only_c = ta - ca, ca - ta
            keys = set(only_t) | set(only_c)
            # ignore pure savegpr/restgpr (frame-size, not a call bug)
            if all("savegpr" in k or "restgpr" in k or "savefpr" in k
                   or "restfpr" in k for k in keys):
                continue
            victims = [k for k in only_t if k in local_fns]
            if args.same_tu_only and not victims:
                continue
            out.append((f.get("fuzzy_match_percent", 100), name, n,
                        dict(only_t), dict(only_c), victims))

    out.sort()
    for pct, un, n, ot, oc, victims in out[:args.limit]:
        tag = "  [INLINE-VICTIM: %s]" % ",".join(victims) if victims else ""
        print("%5.1f  %-44s %s%s" % (pct, un.replace("main/main/", ""), n, tag))
        if ot:
            print("      TGT-only:", ot)
        if oc:
            print("      CUR-only:", oc)
    print("TOTAL", len(out))


if __name__ == "__main__":
    main()
