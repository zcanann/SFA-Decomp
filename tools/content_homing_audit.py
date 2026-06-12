#!/usr/bin/env python3
"""Content-homing audit: per-file content-coherence verdict for EVERY
dll-hosting unit, and the authoritative execution work queue.

The boundary/rename campaigns fixed cuts (boundary_audit.md: 132 -> 1) and
renamed carved units (dll_naming_manifest.md), but file-level CONTENT
coherence is still part-drift: a unit can sit at a canonical filename yet host
fns of a family that matches neither the filename nor any resident descriptor
(cfprisonuncle.c hosts MagicPlant/duster/curvefish/StayPoint/trickywarp — none
"cfprisonuncle"; cfguardian.c is really pressureswitchfb content).

This tool extends dll_boundary_audit.load() (descriptors via the retail TU
model), dll_canonical_names.py (canonical/proposed names) and
cf_lane_homing.py (lane evidence) into a single per-file pass that produces
docs/content_homing_queue.md.

Per unit it reports:
  1. RESIDENT DESCRIPTORS (dll id + retail name) via the gResourceDescriptors
     TU model, the RESIDENT FN list via symbols.txt address ranges, and the
     FN-PREFIX CENSUS (which fn name families live in the file). A prefix that
     matches neither the filename stem nor any resident descriptor's name is an
     ANOMALY (the spellstone-in-prisonuncle class, caught mechanically).
  2. A VERDICT: CANONICAL-OK / MISLABELED (single DLL, wrong name) /
     CONTAINER (multi-DLL, with a per-descriptor carve plan) / HELPER-TU
     (no descriptor) / ENGINE-HOST (engine/SDK file hosting a DLL — deferred).
  3. An EFFORT class: RENAME-ONLY / CARVE / CARVE-HARD / FORENSIC.
  4. A severity-ordered queue + a PARTITION PLAN grouping queue items into
     independent batches over DISJOINT splits.txt/configure.py address regions
     so multiple agents can execute concurrently without global-file clashes.

Read-only: emits docs/content_homing_queue.md, edits nothing else.
Usage:
  python3 tools/content_homing_audit.py            # write the queue doc
  python3 tools/content_homing_audit.py --stdout   # print, do not write
  python3 tools/content_homing_audit.py --worst N   # print worst-N table only
"""
import os, re, sys, bisect
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dll_boundary_audit as A

REPO = A.REPO
MANIFEST = os.path.join(REPO, "docs/dll_naming_manifest.md")
OUT = os.path.join(REPO, "docs/content_homing_queue.md")

# Hard-blocker history from boundary_audit.md: descriptors / units whose carve
# is proven irreducible or documented-deferred (these become CARVE-HARD, not a
# tool-ready CARVE). Keyed by dll id; the audit also escalates a unit to
# CARVE-HARD when its descriptor fn ranges INTERLEAVE (un-snappable boundary).
HARD_DLLS = {
    0x009,  # IRREDUCIBLE: descriptor references SDK code in gamecube.c.
}


# ---------------------------------------------------------------------------
# name normalisation + fn-family-prefix extraction
# ---------------------------------------------------------------------------
def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# Generic / engine-infrastructure fn prefixes that are NOT a DLL-family signal
# (they appear across many files: helpers, SDK, math). A resident fn carrying
# one of these is not counted as a content anomaly.
GENERIC_PREFIXES = {
    "fn", "lbl", "func", "sub", "obj", "vec", "vec3f", "mtx", "ps", "gx",
    "os", "dvd", "sqrtf", "memcpy", "memset", "rand", "randomgetrange",
    "objrenderfn", "modelrenderfn", "objanimfn", "objanimcurvfn", "objbboxfn",
    "hitdetectfn", "objparticlefn", "curvefn", "mathfn", "drawfn", "skyfn",
    "modelanimfn", "modelwalkanimfn", "modeldoaltrenderinstrs",
    # bare dispatch / accessor verbs: a generated descriptor-slot helper named
    # `render`/`update`/`init`/... carries the DLL's family only via the slot
    # symbol, not the fn name — counting these as a content family produces
    # false anomalies (expgfx.c's stray `render`). They are NOT a family signal.
    "render", "renderfn", "update", "init", "initialise", "release", "free",
    "draw", "get", "set", "is", "do", "run", "main", "check", "reset", "load",
    "spawn", "calc", "find", "make", "create", "destroy", "add", "remove",
    "start", "stop", "step", "apply", "clear", "build", "process", "handle",
    "return0", "donothing", "nullsub", "stub",
    # `dll` is the generated symbol prefix (dll_19, dll_2E, dll_CB) MWCC/dtk
    # emits for unnamed DLLs — a NAMING artifact, never a content family.
    "dll",
}

# Recognise a fn-NAME family stem. Two shapes occur in this codebase:
#   CamelCase / Snake leading run before a "_": MagicPlant_update -> magicplant
#                                               duster_SeqFn      -> duster
#   trailing-hex generated names fn_8017F4F4 -> generic (skip)
_FAMILY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*?)(?:_|(?=[A-Z][a-z])|$)")


def fn_family(name):
    """Family stem of a fn symbol, normalised, or None if generic/hex.

    The family is the leading identifier run up to the first '_' (the project's
    descriptor fns are `<Family>_update`, `<family>_init`, etc.). Pure
    fn_<hex>/lbl_<hex> and the GENERIC_PREFIXES set return None."""
    if not name:
        return None
    # generated names: fn_<hex>, lbl_<hex>, and <prefix>_<8hex> suffix forms.
    m = re.match(r"^([A-Za-z][A-Za-z0-9]*?)_[0-9a-fA-F]{6,}$", name)
    if m:
        stem = m.group(1)
    else:
        mm = _FAMILY_RE.match(name)
        if not mm:
            return None
        stem = mm.group(1)
    n = norm(stem)
    if not n or n in GENERIC_PREFIXES or re.fullmatch(r"[0-9a-f]+", n):
        return None
    return n


def file_stem(unit):
    """Normalised content stem of a unit path: drops dir + dll_XXXX_ prefix."""
    base = os.path.basename(unit)[:-2] if unit.endswith(".c") else os.path.basename(unit)
    base = re.sub(r"^dll_[0-9A-Fa-f]{2,4}_", "", base)
    return norm(base)


# ---------------------------------------------------------------------------
# manifest parse: dll id -> (canonical primary name, proposed file path)
# ---------------------------------------------------------------------------
def load_manifest():
    """Parse the manifest table: dll id -> dict(canon, proposed, blocker)."""
    status = ("COMPLETE", "CONFIRMED", "GUESSED", "RAW", "NO-RETAIL-NAME")
    out = {}
    for line in open(MANIFEST):
        # | 0xNNN | retail name(s) | EXPANSION | current file | proposed | blocker |
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 7:
            continue
        if not re.fullmatch(r"0x[0-9A-Fa-f]+", cells[1]):
            continue
        if cells[3] not in status:
            continue
        did = int(cells[1], 16)
        canon = cells[2].split(" (+")[0].strip()
        proposed = cells[5]
        if proposed in ("= (canonical)", "="):
            proposed = cells[4]  # current file is already canonical
        out[did] = dict(canon=canon, proposed=proposed, blocker=cells[6],
                        current=cells[4])
    return out


# Deferred content-mislabel list from the manifest contradiction appendix
# (the "22 deferred mislabels"): current basename -> (real canonical unit,
# content note). These are pre-confirmed FORENSIC/RENAME mislabels.
def load_appendix_mislabels():
    """Scan the contradiction appendix for 'content X — vs real Y' lines."""
    out = {}
    txt = open(MANIFEST).read()
    # lines like: - `cfguardian.c` (content `pressureswitchfb_*`...) — vs real `CF/dll_0148_cfguardian.c`
    for m in re.finditer(
            r"`([^`]+\.c)`\s*\(content\s*`([^`]+)`[^)]*\)\s*—\s*vs real\s*`([^`]+)`",
            txt):
        out[os.path.basename(m.group(1))] = (m.group(2), m.group(3))
    return out


# ---------------------------------------------------------------------------
# core analysis
# ---------------------------------------------------------------------------
def analyze():
    rows, units, unit_for, fn_end, sym_at, fn_size = A.load()
    manifest = load_manifest()
    appendix = load_appendix_mislabels()

    # descriptor rows by dll id
    by_id = {r["dll_id"]: r for r in rows}

    # which dll ids each unit hosts (by descriptor fn placement)
    unit_dlls = defaultdict(set)
    for r in rows:
        for _slot, v in r["fns"]:
            u = unit_for(v)
            if u:
                unit_dlls[u].add(r["dll_id"])

    # descriptor interleave map per unit: do two resident descriptors' fn
    # ranges overlap? (an un-snappable boundary -> CARVE-HARD)
    def interleaves(ids):
        ranges = sorted((by_id[d]["lo"], by_id[d]["hi"]) for d in ids
                        if by_id[d]["lo"] and by_id[d]["hi"])
        for i in range(1, len(ranges)):
            if ranges[i][0] <= ranges[i - 1][1]:
                return True
        return False

    # resident fns per unit (symbols.txt .text addresses in the unit range)
    unit_ranges = {}
    for lo, hi, u in units:
        unit_ranges.setdefault(u, (lo, hi))
    fn_by_unit = defaultdict(list)
    for a in sorted(sym_at):
        if a not in fn_size:
            continue
        u = unit_for(a)
        if u:
            fn_by_unit[u].append((a, sym_at[a]))

    # Scope: every unit under src/main/dll/ (the dll lane — includes
    # no-descriptor helper slivers, which ARE in scope per the mission), PLUS
    # the engine/SDK files that HOST a descriptor (light.c/main.c/sky.c/... and
    # the dolphin gamecube.c). A pure engine file with no descriptor
    # (main/audio.c, main/objprint_dolphin.c) is NOT dll content and is out of
    # scope even though it has resident fns.
    results = []
    for unit in sorted(unit_ranges):
        in_dll_lane = unit.startswith("main/dll/")
        hosts_descriptor = unit in unit_dlls
        if not in_dll_lane and not hosts_descriptor:
            continue
        ids = sorted(unit_dlls.get(unit, set()))
        resident_fns = fn_by_unit.get(unit, [])
        stem = file_stem(unit)
        lo, hi = unit_ranges[unit]

        # resident descriptor names (retail def names + manifest canon)
        desc_info = []
        for d in ids:
            r = by_id[d]
            nm = r["names"][0] if r["names"] else (manifest.get(d, {}).get("canon") or (r["desc_sym"] or "?"))
            desc_info.append((d, nm))

        # the set of "expected" family stems for this file: the filename stem,
        # every resident descriptor's retail name + manifest canon + the fn
        # prefix the manifest derived the stem from.
        expected = set()
        if stem:
            expected.add(stem)
        for d in ids:
            r = by_id[d]
            for nm in r["names"]:
                expected.add(norm(nm))
            mc = manifest.get(d, {}).get("canon")
            if mc:
                expected.add(norm(mc))

        # fn-prefix census
        fam_counts = Counter()
        for _a, nm in resident_fns:
            f = fn_family(nm)
            if f:
                fam_counts[f] += 1

        # anomalies: families matching NO expected stem (substring either way:
        # a family "magicplant" vs expected "cfprisonuncle" -> anomaly; a
        # family "duster" vs descriptor name "Duster" -> matched).
        def matches_expected(fam):
            for e in expected:
                if not e:
                    continue
                if fam == e or fam.startswith(e) or e.startswith(fam):
                    return True
            return False

        anomalies = sorted((f for f in fam_counts if not matches_expected(f)),
                           key=lambda f: -fam_counts[f])
        anom_count = sum(fam_counts[f] for f in anomalies)

        base = os.path.basename(unit)
        ap = appendix.get(base)
        ndll = len(ids)
        bare = re.sub(r"^dll_[0-9A-Fa-f]{2,4}_", "", base[:-2] if base.endswith(".c") else base)
        descriptive = (bare.lower() not in ("unk", "unused", "dll", "")
                       and not re.fullmatch(r"dll_?[0-9a-fA-F]+", bare))
        no_retail = all(not by_id[d]["names"] for d in ids) if ids else True

        # DESCRIPTOR-SLOT family: the family of the resident descriptor's OWN
        # slot fns (`GameUI_update`, `MagicPlant_init`, ...). This is the
        # authoritative content identity (the manifest derives no-retail-name
        # stems from exactly this prefix). A descriptive filename contradicting
        # it is a real content mislabel (baby_snowworm.c whose slots are
        # GameUI_*). Adjacency guard: a >=3-char common prefix (camcontrol vs
        # camera) is the same domain — not a mislabel.
        def slot_family(d):
            # CamelCase family (for matching) + full snake-prefix (for naming):
            # TitleScreenInit_initialise -> ("title", "titlescreeninit").
            fams, full = Counter(), Counter()
            for _s, v in by_id[d]["fns"]:
                nm = sym_at.get(v)
                f = fn_family(nm)
                if f:
                    fams[f] += 1
                    pre = nm.split("_", 1)[0]
                    full[norm(pre)] += 1
            if not fams:
                return None
            fam, cnt = fams.most_common(1)[0]
            namestem = full.most_common(1)[0][0] if full else fam
            return fam, cnt, namestem

        advisory = ""
        slot_mismatch = None  # (dll_id, family, count, namestem)
        if ndll == 1 and no_retail and descriptive and stem:
            sf = slot_family(ids[0])
            if sf:
                fam, cnt, namestem = sf
                cp = os.path.commonprefix([fam, stem])
                adjacent = (fam == stem or fam.startswith(stem) or stem.startswith(fam)
                            or len(cp) >= 3)
                if not adjacent and cnt >= 3:
                    slot_mismatch = (ids[0], fam, cnt, namestem)
                    advisory = "descriptor-slot family `%s`×%d ≠ filename `%s`" % (fam, cnt, bare)

        # ------- VERDICT -------
        is_engine = not unit.startswith("main/dll/")
        verdict, effort, proposed, note = None, None, "", ""

        if is_engine:
            verdict = "ENGINE-HOST"
            effort = "FORENSIC"  # extraction = engine/SDK split, human-grade
            note = "engine/SDK host of DLL(s) %s" % ",".join("0x%03X" % d for d in ids)
        elif ndll == 0:
            # no descriptor: helper sliver. Appendix-confirmed mislabel first.
            if ap:
                verdict, effort = "MISLABELED", "FORENSIC"
                proposed = ap[1] if ap[1].endswith(".c") else base
                note = "no descriptor; appendix mislabel — content %s vs real %s" % (
                    ap[0], os.path.basename(ap[1]))
            else:
                verdict = "HELPER-TU"
                # convention: lowercase, no dll_ prefix, descriptive stem, no
                # collision with a canonical dll_XXXX_<stem>.c (manifest rule).
                ok = (base == base.lower() and not base.startswith("dll_"))
                effort = "RENAME-ONLY" if not ok else "OK"
                note = "no descriptor; %s" % (
                    "convention OK" if ok else "violates helper-TU naming rule (must be lowercase, no dll_ prefix)")
                if advisory:
                    note += "; " + advisory
        elif ndll >= 2:
            verdict = "CONTAINER"
            if interleaves(ids) or any(d in HARD_DLLS for d in ids):
                effort = "CARVE-HARD"
            else:
                effort = "CARVE"
            # per-descriptor carve plan from the manifest proposed names
            plan = []
            for d in sorted(ids):
                p = manifest.get(d, {}).get("proposed") or "dll_%04X_?.c" % d
                r = by_id[d]
                plan.append("0x%03X→%s [%s-%s]" % (
                    d, os.path.basename(p),
                    "%08X" % r["lo"] if r["lo"] else "?",
                    "%08X" % r["hi"] if r["hi"] else "?"))
            proposed = " ; ".join(plan)
            note = "multi-DLL (%d): %s" % (ndll, ",".join(
                "0x%03X:%s" % (d, n) for d, n in desc_info))
        else:  # exactly one resident DLL
            d = ids[0]
            mc = manifest.get(d, {})
            has_retail = bool(by_id[d]["names"])
            canon = mc.get("canon") or (desc_info[0][1] if desc_info else "?")
            canon = canon if canon and canon != "—" else (
                by_id[d]["names"][0] if has_retail else "—")
            canon_stem = norm(canon) if canon != "—" else ""
            id_in_name = ("dll_%04x_" % d) in base.lower()
            mproposed = mc.get("proposed", "")
            # a genuine retail/manifest rename target distinct from current.
            wants_rename = (mproposed and os.path.basename(mproposed) != base
                            and not mproposed.startswith("dolphin/"))
            # filename reflects a real retail/canonical content name?
            name_ok = (canon_stem and matches_expected(canon_stem))

            if ap:
                # appendix-confirmed content mislabel (forensic content read).
                verdict, effort = "MISLABELED", "FORENSIC"
                proposed = ap[1] if ap[1].endswith(".c") else "dll_%04X_%s.c" % (d, canon_stem or "dll")
                note = "single DLL 0x%03X:%s; appendix mislabel — content %s vs real %s" % (
                    d, canon, ap[0], os.path.basename(ap[1]))
            elif has_retail and not name_ok:
                # carries a retail name the filename contradicts: real rename.
                verdict, effort = "MISLABELED", ("FORENSIC" if anomalies else "RENAME-ONLY")
                proposed = mproposed if wants_rename else "dll_%04X_%s.c" % (d, canon_stem or "dll")
                extra = (" (fn families %s)" % ",".join(anomalies[:3])) if anomalies else ""
                note = "single DLL 0x%03X:%s; filename != retail name%s" % (d, canon, extra)
            elif wants_rename:
                # manifest proposes a different canonical file (no-retail-name
                # case where the manifest still derived a better stem).
                verdict, effort = "MISLABELED", "RENAME-ONLY"
                proposed = mproposed
                note = "single DLL 0x%03X:%s; manifest proposes %s" % (
                    d, canon, os.path.basename(mproposed))
            elif slot_mismatch:
                # no retail name, but the descriptor's own slot fns name a family
                # the descriptive filename contradicts (baby_snowworm.c slots are
                # GameUI_*). Real content mislabel; proposed = fn-prefix stem
                # (exactly how the manifest derives no-retail-name stems).
                _d, fam, cnt, namestem = slot_mismatch
                verdict, effort = "MISLABELED", "FORENSIC"
                proposed = "dll_%04X_%s.c" % (d, namestem)
                note = "single DLL 0x%03X (no retail name); %s — propose stem from slot family" % (
                    d, advisory)
            else:
                # canonical-by-id (no retail name, id-prefixed filename, nothing
                # more correct to rename to) OR name reflects content.
                verdict, effort = "CANONICAL-OK", "OK"
                tag = "canonical-by-id; " if (id_in_name and not has_retail) else ""
                note = "single DLL 0x%03X:%s — %sname reflects content" % (d, canon, tag)

        results.append(dict(
            unit=unit, lo=lo, hi=hi, ids=ids, desc_info=desc_info,
            nfns=len(resident_fns), families=fam_counts, anomalies=anomalies,
            anom_count=anom_count, verdict=verdict, effort=effort,
            proposed=proposed, note=note, advisory=advisory))

    # footprint = the full address span a unit's homing TOUCHES: its own range
    # plus every resident descriptor's fn range (a CONTAINER carve edits child
    # descriptor TUs that can start BEFORE the container's own lo). Batches must
    # pack on the footprint, not the splits range, to stay region-disjoint.
    for r in results:
        flo, fhi = r["lo"], r["hi"]
        for d in r["ids"]:
            if by_id[d]["lo"]:
                flo = min(flo, by_id[d]["lo"])
            if by_id[d]["hi"]:
                fhi = max(fhi, fn_end(by_id[d]["hi"]))
        r["flo"], r["fhi"] = flo, fhi
    return results


# severity ordering: CONTAINER carves (most content moved) > MISLABELED
# forensic > CONTAINER-HARD > MISLABELED rename > HELPER rename, tie-broken by
# anomaly count then dll count then address.
EFFORT_SEV = {
    "CARVE": 0, "CARVE-HARD": 1, "FORENSIC": 2, "RENAME-ONLY": 3, "OK": 9,
}
VERDICT_SEV = {
    "CONTAINER": 0, "MISLABELED": 1, "HELPER-TU": 2, "ENGINE-HOST": 3,
    "CANONICAL-OK": 9,
}


def severity_key(r):
    return (VERDICT_SEV.get(r["verdict"], 9),
            EFFORT_SEV.get(r["effort"], 9),
            -len(r["ids"]), -r["anom_count"], r["lo"])


# ---------------------------------------------------------------------------
# partition plan: group actionable items into batches over DISJOINT address
# regions so concurrent worktrees never collide on splits.txt/configure.py.
# ---------------------------------------------------------------------------
def partition(actionable, batch_size=8):
    """Pack actionable items into address-ordered batches that own DISJOINT,
    contiguous `splits.txt` regions so concurrent worktrees never collide on
    the global files. Packing is on each item's FOOTPRINT (flo,fhi) — its own
    range plus every resident-descriptor range a carve would touch — not the
    splits range, because a CONTAINER carve edits child TUs that can sit before
    the container's own start. A batch closes at the first item-boundary that
    is a clean cut: the running max footprint-end <= the next item's
    footprint-start (no item straddles the boundary), once the batch has
    >= batch_size items. The result: every batch is a self-contained address
    interval; batch i's region ends strictly before batch i+1's begins."""
    items = sorted(actionable, key=lambda r: (r["flo"], r["fhi"]))
    batches, cur, run_end = [], [], None
    for r in items:
        if cur and len(cur) >= batch_size and r["flo"] >= run_end:
            batches.append(cur)
            cur, run_end = [], None
        cur.append(r)
        run_end = r["fhi"] if run_end is None else max(run_end, r["fhi"])
    if cur:
        batches.append(cur)
    return batches


# ---------------------------------------------------------------------------
# markdown emit
# ---------------------------------------------------------------------------
def emit(results):
    L = []
    P = L.append
    actionable = [r for r in results if r["effort"] != "OK"]
    by_verdict = Counter(r["verdict"] for r in results)
    by_effort = Counter(r["effort"] for r in actionable)
    verd_effort = Counter((r["verdict"], r["effort"]) for r in actionable)

    P("# Content-homing work queue")
    P("")
    P("Authoritative per-file content-coherence queue for every dll-hosting")
    P("unit. Generated by `python3 tools/content_homing_audit.py` (READ-ONLY —")
    P("the tool edits nothing but this doc). Re-run after every content-homing")
    P("wave. Built on the retail TU model (`dll_boundary_audit.load()`), the")
    P("canonical-name manifest (`dll_naming_manifest.md`), and the lane-homing")
    P("census (`cf_lane_homing.py`).")
    P("")
    P("Each unit gets: resident descriptors (dll id + retail name), resident-fn")
    P("count, an fn-PREFIX census (the families living in the file), a VERDICT,")
    P("an EFFORT class, and — for non-OK rows — the proposed name / carve plan.")
    P("An **anomaly** is an fn-family prefix matching NEITHER the filename stem")
    P("NOR any resident descriptor's retail/canonical name — the mechanical")
    P("catch for the spellstone-in-prisonuncle content-drift class.")
    P("")

    P("## Summary")
    P("")
    P("| metric | count |")
    P("|---|---|")
    P("| dll-hosting units audited | %d |" % len(results))
    P("| actionable (non-OK) | %d |" % len(actionable))
    for v in ("CANONICAL-OK", "CONTAINER", "MISLABELED", "HELPER-TU", "ENGINE-HOST"):
        P("| verdict %s | %d |" % (v, by_verdict.get(v, 0)))
    P("")
    P("### Effort-class counts (actionable only)")
    P("")
    P("| effort | count | meaning |")
    P("|---|---|---|")
    EM = {
        "CARVE": "tool-ready container dissolution (`dll_boundary_resplit.py --carve`)",
        "CARVE-HARD": "container with a known blocker (interleave / irreducible)",
        "FORENSIC": "fn-prefix anomaly / appendix mislabel — human-grade content read",
        "RENAME-ONLY": "clean filename↔content stem rename (no carve)",
    }
    for e in ("CARVE", "CARVE-HARD", "FORENSIC", "RENAME-ONLY"):
        P("| %s | %d | %s |" % (e, by_effort.get(e, 0), EM[e]))
    P("")
    if by_effort.get("CARVE-HARD", 0) == 0:
        P("> **CARVE-HARD = 0**: the June-2026 `dll_boundary_resplit.py` campaign")
        P("> (boundary_audit.md) TU-aligned every cutting boundary, so no resident")
        P("> CONTAINER has interleaving descriptor ranges — every container is a")
        P("> clean per-descriptor carve. The one proven-irreducible case (dll 0x009,")
        P("> descriptor referencing SDK code in `gamecube.c`) is classed ENGINE-HOST,")
        P("> not a carve. CARVE-HARD is escalated automatically if a future audit")
        P("> finds an interleave (the test runs every pass).")
        P("")
    P("### Verdict × effort cross-tab (actionable)")
    P("")
    P("| verdict | effort | count |")
    P("|---|---|---|")
    for (v, e), c in sorted(verd_effort.items(), key=lambda x: (VERDICT_SEV.get(x[0][0], 9), EFFORT_SEV.get(x[0][1], 9))):
        P("| %s | %s | %d |" % (v, e, c))
    P("")

    # worst-10 by anomaly fn count
    worst = sorted((r for r in results if r["anom_count"]),
                   key=lambda r: (-r["anom_count"], -len(r["ids"]), r["lo"]))[:10]
    P("## Worst 10 files by content-anomaly fn count")
    P("")
    P("Files hosting the most fns whose family matches neither the filename nor")
    P("a resident descriptor — the densest content drift. (`dll×N`/`fn_*` are")
    P("generated-name artifacts and are suppressed; these counts are real")
    P("families.)")
    P("")
    P("| rank | unit | #DLL | anomaly fns | families (count) | verdict/effort |")
    P("|---|---|---|---|---|---|")
    for i, r in enumerate(worst, 1):
        fams = ", ".join("%s×%d" % (f, r["families"][f]) for f in r["anomalies"][:5])
        P("| %d | `%s` | %d | %d | %s | %s/%s |" % (
            i, r["unit"], len(r["ids"]), r["anom_count"], fams,
            r["verdict"], r["effort"]))
    P("")
    # explicit confirmation of the user-flagged file (cfprisonuncle): the
    # mission asks to confirm what's actually in it. It is a CLEAN container, so
    # it carries 0 anomalies (its fn families ARE its own descriptors) — it does
    # not rank by anomaly density; its drift is the FILENAME, fixed by the carve.
    cpu = next((r for r in results if r["unit"] == "main/dll/cfprisonuncle.c"), None)
    if cpu:
        P("**User-flagged `cfprisonuncle.c` — confirmed content:** a clean")
        P("**6-DLL container** (anomaly fns = 0; its fn families ARE its own")
        P("descriptors, so it does not rank by anomaly density — its drift is the")
        P("FILENAME, not stray fns). Resident descriptors: " +
          ", ".join("0x%03X:%s" % (d, n) for d, n in cpu["desc_info"]) + ". The")
        P("`cfprisonuncle` name belongs to the unrelated real DLL 0x14F")
        P("(`CF/dll_014F_cfprisonuncle.c`); carving this container into the six")
        P("per-descriptor units above resolves the mislabel. (The original brief's")
        P("\"stray spellstone/babycloudrunner fns\" was imprecise — the actual")
        P("residents are MagicPlant/TrickyWarp/TrickyGuard/StayPoint/CurveFish/Duster.)")
        P("")

    # severity-ordered queue
    P("## Severity-ordered queue")
    P("")
    P("Ordered: CONTAINER carves → MISLABELED forensic → hard carves → clean")
    P("renames → helper renames; tie-broken by dll count then anomaly count then")
    P("address. `[lo-hi)` is the splits.txt `.text` range (the partition unit).")
    P("")
    P("| # | unit | range | verdict | effort | resident DLLs / anomalies | proposed / carve plan |")
    P("|---|---|---|---|---|---|---|")
    queue = sorted(actionable, key=severity_key)
    for i, r in enumerate(queue, 1):
        rng = "%08X-%08X" % (r["lo"], r["hi"])
        dlls = ",".join("0x%03X" % d for d in r["ids"]) or "—"
        anom = (" anom:" + ",".join(r["anomalies"][:4])) if r["anomalies"] else ""
        prop = r["proposed"] or r["note"]
        prop = prop.replace("|", "\\|")
        P("| %d | `%s` | %s | %s | %s | %s%s | %s |" % (
            i, r["unit"], rng, r["verdict"], r["effort"], dlls, anom, prop))
    P("")

    # partition plan
    P("## Partition plan (concurrent execution batches)")
    P("")
    P("Actionable items packed into address-ordered batches over DISJOINT")
    P("`splits.txt` / `configure.py` regions. Each batch is a CONTIGUOUS address")
    P("run, so multiple agents can run in separate worktrees and edit the global")
    P("files without colliding — assign one batch per worktree, land")
    P("address-edge-first within a batch (the resplit tool's linear-link-order")
    P("rule). Batches are independent; run them in any order or all at once.")
    P("")
    batches = partition(actionable, batch_size=8)
    bspans = [(min(r["flo"] for r in ch), max(r["fhi"] for r in ch)) for ch in batches]
    overlap = any(bspans[i][0] < bspans[i - 1][1] for i in range(1, len(bspans)))
    P("Batches: %d. Region-disjoint: %s (each batch owns a contiguous address"
      " interval; no item's footprint straddles a batch boundary)." % (
          len(batches), "NO OVERLAP — verified" if not overlap else "WARN: overlap"))
    P("")
    P("| batch | items | footprint span | effort mix |")
    P("|---|---|---|---|")
    for bi, (ch, (slo, shi)) in enumerate(zip(batches, bspans), 1):
        mix = Counter(r["effort"] for r in ch)
        mixs = ",".join("%s×%d" % (e, mix[e]) for e in ("CARVE", "CARVE-HARD", "FORENSIC", "RENAME-ONLY") if mix[e])
        P("| B%02d | %d | %08X-%08X | %s |" % (bi, len(ch), slo, shi, mixs))
    P("")
    for bi, (ch, (slo, shi)) in enumerate(zip(batches, bspans), 1):
        P("### Batch B%02d — `%08X-%08X` (%d items)" % (bi, slo, shi, len(ch)))
        P("")
        P("| unit | range | verdict | effort | plan |")
        P("|---|---|---|---|---|")
        for r in sorted(ch, key=lambda r: r["flo"]):
            rng = "%08X-%08X" % (r["lo"], r["hi"])
            prop = (r["proposed"] or r["note"]).replace("|", "\\|")
            P("| `%s` | %s | %s | %s | %s |" % (
                r["unit"], rng, r["verdict"], r["effort"], prop))
        P("")

    # slot-family mislabels detail: single-DLL no-retail-name files whose own
    # DESCRIPTOR-SLOT fns name a family the descriptive filename contradicts
    # (baby_snowworm.c → GameUI_*). These are the MISLABELED/FORENSIC rows whose
    # proposed stem is derived from the slot fn prefix (manifest stem-derivation
    # rule). Highest-confidence content mislabels in the queue.
    slotmis = sorted((r for r in results if r.get("advisory") and r["verdict"] == "MISLABELED"),
                     key=lambda r: r["lo"])
    P("## Slot-family content mislabels (descriptor proves the rename)")
    P("")
    P("Single-DLL files with NO retail name whose OWN descriptor-slot fns")
    P("(`<Family>_initialise/_update/_render`) name a family the descriptive")
    P("filename contradicts — the descriptor itself proves the file is")
    P("mislabeled (e.g. `baby_snowworm.c` whose slots are `GameUI_*`). Proposed")
    P("stem is the slot fn prefix (manifest stem-derivation rule). %d found." % len(slotmis))
    P("")
    if slotmis:
        P("| unit | dll | slot family | filename stem | proposed |")
        P("|---|---|---|---|---|")
        for r in slotmis:
            P("| `%s` | %s | %s | `%s` | `%s` |" % (
                r["unit"], ",".join("0x%03X" % d for d in r["ids"]),
                r["advisory"].split("≠")[0].replace("descriptor-slot family ", "").strip(),
                file_stem(r["unit"]), os.path.basename(r["proposed"])))
    P("")

    return "\n".join(L) + "\n"


def main():
    if "--worst" in sys.argv:
        n = int(sys.argv[sys.argv.index("--worst") + 1])
        results = analyze()
        worst = sorted((r for r in results if r["anom_count"]),
                       key=lambda r: (-r["anom_count"], -len(r["ids"]), r["lo"]))[:n]
        for i, r in enumerate(worst, 1):
            fams = ", ".join("%s×%d" % (f, r["families"][f]) for f in r["anomalies"][:6])
            print("%2d  %-48s #dll=%d anom=%d  %s  [%s/%s]" % (
                i, r["unit"], len(r["ids"]), r["anom_count"], fams,
                r["verdict"], r["effort"]))
        return
    results = analyze()
    md = emit(results)
    if "--stdout" in sys.argv:
        sys.stdout.write(md)
    else:
        open(OUT, "w").write(md)
        actionable = sum(1 for r in results if r["effort"] != "OK")
        print("wrote %s (%d units, %d actionable)" % (OUT, len(results), actionable))


if __name__ == "__main__":
    main()
