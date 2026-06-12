#!/usr/bin/env python3
"""Mechanized DLL TU-boundary surgery (docs/boundary_audit.md Phase 2/3).

Consumes the descriptor-forensics TU model from tools/dll_boundary_audit.py
(imported as a library) and re-splits drift-era unit boundaries onto TU
edges, conservation-gated.

Per-case pipeline:
  1. geometry: snap every boundary that cuts a descriptor's fn range onto a
     TU edge (prev-initialise-end ts or own-initialise-end te, min |move|,
     monotonicity-checked at region level);
  2. source ops, all skeleton-projection based (decl environment + pragma
     stacks preserved verbatim, defs collapse to one-line prototypes at the
     same position):
       ABSORB  whole donor file appended to the span owner's file;
       MOVE    projection of the donor keeping only the moved fns appended
               to the span owner; donor keeps everything, moved defs
               collapse to prototypes;
       CARVE   single donor owning 2+ spans: each piece = full projection
               keeping that span's fns.
     Appends land at EOF in address order => moved fns sit AFTER their
     in-file callers (helper-last; MWCC cannot inline upward).
  3. splits.txt + configure.py edits (assert-counted; new units inherit the
     owner's cflags; junk-named merged units get canonical
     dll_XXXX_<defname> names);
  4. gates: full ninja green, no sjiswrap warning on touched files,
     main.dol md5 unchanged, EXACT conservation (per-symbol fuzzy+size by
     virtual address, summed matched_code) over the affected units;
  5. commit on pass. On conservation failure confined to moved/absorbed
     fns: one auto-retry with donor-unit-default pragma wrappers. Otherwise
     full revert + flag.

Classes: a = pure whole-unit merges; c = boundary nudges (partial fn
moves); b = single-donor carves; d = flagged for manual work (multi-donor
scatter, interleaved descriptors, data-owning deleted units, MatchingFor
units, geometry conflicts).

Usage:
  python3 tools/dll_boundary_resplit.py --plan [--class a|b|c|d] [--case ID]
  python3 tools/dll_boundary_resplit.py --run --case ID [--no-commit]
  python3 tools/dll_boundary_resplit.py --run --class a [--limit N]
All file IO is byte-wise (latin-1 round-trip) for SJIS safety.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS = os.path.join(REPO, "config/GSAE01/splits.txt")
CONFIGURE = os.path.join(REPO, "configure.py")
REPORT = os.path.join(REPO, "build/GSAE01/report.json")
DOL = os.path.join(REPO, "build/GSAE01/main.dol")
DOL_MD5 = "7b955850ea4bd7ceda0109493203ff5b"
LEDGER = os.path.join(REPO, "build/resplit_ledger.json")

_spec = importlib.util.spec_from_file_location(
    "dll_boundary_audit", os.path.join(REPO, "tools/dll_boundary_audit.py"))
dba = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dba)


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1")


def write(path, text):
    with open(path, "wb") as f:
        f.write(text.encode("latin-1"))


# ---------------------------------------------------------------- model ---

class World:
    """splits/symbols/descriptor model via dll_boundary_audit.load()."""

    def __init__(self):
        (self.rows, self.units, self.unit_for, self.fn_end,
         self.sym_at, self.fn_size) = dba.load()
        self.cuts = dba.cut_rows(self.rows, self.units, self.unit_for, self.fn_end)
        self.unit_sections = defaultdict(list)
        cur = None
        for line in read(SPLITS).split("\n"):
            if line and line[0] not in " \t" and line.endswith(":"):
                cur = line[:-1]
            elif cur:
                m = re.match(r"^\s*(\S+)\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)", line)
                if m:
                    self.unit_sections[cur].append(m.group(1))
        self.cfg_lines = {}
        for ln in read(CONFIGURE).split("\n"):
            m = re.search(r'Object\((\w+(?:\("[^"]*"\))?),\s*"([^"]+)"(.*?)\),?\s*$', ln)
            if m:
                self.cfg_lines[m.group(2)] = (m.group(1), m.group(3), ln)

    def fns_in(self, lo, hi):
        return [(a, self.sym_at[a], self.fn_size[a])
                for a in sorted(self.fn_size) if lo <= a < hi]

    def unit_before(self, addr):
        prev = None
        for us, ue, un in self.units:
            if ue <= addr:
                prev = un
            else:
                break
        return prev


# ---------------------------------------------------- geometry / cases ---

class Case:
    def __init__(self, cid):
        self.id = cid
        self.dlls = []        # [(dll_id, names)]
        self.units = []       # ordered [(start,end,name)], no floaters
        self.floaters = []    # zero-size units riding a boundary: (name, addr)
        self.moves = {}       # old boundary -> new addr
        self.spans = []       # [(start, end)] new partition
        self.klass = "?"
        self.flags = []
        self.plan = None      # dict(ops=[...], owner={span: unit})
        self.dissolve = False # container carve: every piece gets a new name

    def dll_str(self):
        return ", ".join("0x%03X%s" % (d, (":" + ns[0]) if ns else "")
                         for d, ns in self.dlls)


def carve_case(w: World, unit_name):
    """Synthesize a container-dissolution case: split a clean multi-DLL unit
    into one unit per descriptor TU (skeleton-copy carve)."""
    u = next((x for x in w.units if x[2] == unit_name), None)
    if u is None:
        raise SystemExit(f"unit {unit_name} not found")
    us, ue, un = u
    case = Case("carve_" + os.path.basename(un))
    case.units = [u]
    case.dissolve = True
    edges = set()
    for r in w.rows:
        if r["lo"] is None:
            continue
        if us <= r["lo"] and r["hi"] < ue:
            te = w.fn_end(r["hi"])
            case.dlls.append((r["dll_id"], r["names"]))
            if te < ue:
                edges.add(te)
        elif r["lo"] < us <= r["hi"] < ue:
            # tail fragment of a still-cut descriptor at the unit start:
            # carve it off at its TU end (the cut itself stays documented)
            te = w.fn_end(r["hi"])
            case.dlls.append((r["dll_id"], r["names"]))
            if us < te < ue:
                edges.add(te)
        elif r["lo"] < ue <= r["hi"]:
            pass  # head fragment at the unit end stays the trailing piece
    if not case.dlls:
        case.flags.append("no descriptor TU inside unit")
    bounds = [us] + sorted(edges) + [ue]
    case.spans = [(bounds[k], bounds[k + 1]) for k in range(len(bounds) - 1)
                  if bounds[k] < bounds[k + 1]]
    return case


def snap_boundaries(interior, cand_map, lo, hi):
    """Choose a monotonic assignment of targets (min total move). interior is
    the ordered old boundary list; cand_map[b] = candidate target list."""
    best = None
    cands = [cand_map[b] for b in interior]
    total = 1
    for cl in cands:
        total *= len(cl)
    if total > 65536:
        return None
    import itertools
    for combo in itertools.product(*cands):
        if any(v < lo or v > hi for v in combo):
            continue
        if any(combo[k] > combo[k + 1] for k in range(len(combo) - 1)):
            continue
        cost = sum(abs(v - b) for v, b in zip(combo, interior))
        if best is None or cost < best[0]:
            best = (cost, combo)
    return None if best is None else list(best[1])


def build_cases(w: World):
    real_units = [u for u in w.units if u[0] < u[1]]
    floaters = [u for u in w.units if u[0] == u[1]]
    bdll = defaultdict(dict)
    for r, inner, ts, te in w.cuts:
        for (b, left, right) in inner:
            bdll[b][r["dll_id"]] = (r, ts, te)
    bmoves = {}
    for b, per_dll in bdll.items():
        rows = list(per_dll.values())
        r, ts, te = rows[0]
        cands = sorted(set(v for v in (ts, te) if v is not None))
        tgt = min(cands, key=lambda v: abs(v - b))
        bmoves[b] = (tgt, cands, r["dll_id"], len(per_dll) > 1)

    parent = list(range(len(real_units)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    touched = set()
    for b, (tgt, cands, did, multi) in bmoves.items():
        lo, hi = min([b] + cands), max([b] + cands)
        ids = [i for i, u in enumerate(real_units)
               if (u[1] > lo and u[0] < hi) or u[0] == b or u[1] == b]
        for i in ids[1:]:
            union(ids[0], i)
        touched.update(ids)

    groups = defaultdict(list)
    for i in sorted(touched):
        groups[find(i)].append(i)

    cases = []
    for g in sorted(groups.values(), key=lambda ids: real_units[ids[0]][0]):
        units = [real_units[i] for i in sorted(g)]
        case = Case("r%08X" % units[0][0])
        case.units = units
        if not all(units[k][1] == units[k + 1][0] for k in range(len(units) - 1)):
            case.flags.append("region units not contiguous")
        interior = [u[0] for u in units[1:]]
        cand_map = {}
        for b in interior:
            if b in bmoves:
                tgt, cands, did, multi = bmoves[b]
                if multi:
                    case.flags.append(
                        "boundary 0x%08X cuts 2+ descriptors (true interleave)" % b)
                cand_map[b] = cands
            else:
                cand_map[b] = [b]
        dids = sorted(set(bmoves[b][2] for b in interior if b in bmoves))
        for did in dids:
            r = next(x for x in w.rows if x["dll_id"] == did)
            case.dlls.append((did, r["names"]))
        lo, hi = units[0][0], units[-1][1]
        newb = snap_boundaries(interior, cand_map, lo, hi)
        if newb is None:
            case.flags.append("geometry: no monotonic TU-edge assignment")
        else:
            for b, v in zip(interior, newb):
                if v != b:
                    case.moves[b] = v
            edges = [lo] + newb + [hi]
            case.spans = sorted(set((edges[k], edges[k + 1])
                                    for k in range(len(edges) - 1)
                                    if edges[k] < edges[k + 1]))
            # zero-size floater units inside the region ride their boundary
            move_map = dict(zip(interior, newb))
            for fs, fe, fname in floaters:
                if lo < fs < hi:
                    case.floaters.append((fname, fs, move_map.get(fs, fs)))
        case.flags = sorted(set(case.flags))
        cases.append(case)
    return cases


def plan_case(w: World, case: Case):
    if case.flags:
        case.klass = "d"
        return
    contrib = defaultdict(list)   # span -> [(unit, ov_lo, ov_hi)]
    for sp in case.spans:
        for us, ue, un in case.units:
            ov_lo, ov_hi = max(sp[0], us), min(sp[1], ue)
            if ov_lo < ov_hi:
                contrib[sp].append((un, ov_lo, ov_hi))
    owner, owned = {}, defaultdict(list)
    for sp, lst in contrib.items():
        def rank(t):
            un, ov_lo, ov_hi = t
            us, ue, _ = next(u for u in case.units if u[2] == un)
            whole = (ov_lo == us and ov_hi == ue)
            owns_data = any(s != ".text" for s in w.unit_sections.get(un, []))
            # a data-owning unit must never be deleted: prefer it as owner
            # when its whole range sits in this span
            return (1 if (owns_data and whole) else 0, ov_hi - ov_lo)
        un = max(lst, key=rank)[0]
        owner[sp] = un
        owned[un].append(sp)

    ops = []   # (kind, donor, span, lo, hi)
    for sp, lst in contrib.items():
        for un, ov_lo, ov_hi in lst:
            if un == owner[sp]:
                continue
            us, ue, _ = next(u for u in case.units if u[2] == un)
            kind = "absorb" if (ov_lo == us and ov_hi == ue) else "move"
            ops.append((kind, un, sp, ov_lo, ov_hi))
    carves = sorted(un for un, sps in owned.items() if len(sps) >= 2)

    survivors = set(owner.values())
    for us, ue, un in case.units:
        non_text = [s for s in w.unit_sections.get(un, []) if s != ".text"]
        if un not in survivors and non_text:
            case.flags.append(f"deleted unit {un} owns data sections {non_text}")
        if not un.startswith("main/"):
            case.flags.append(f"unit {un} outside main/ lane (SDK/foreign)")
        st = w.cfg_lines.get(un)
        if st is None:
            case.flags.append(f"unit {un} not in configure.py")
        elif st[0] != "NonMatching":
            case.flags.append(f"unit {un} is {st[0]} (gated)")
        if not os.path.isfile(os.path.join(REPO, "src", un)):
            case.flags.append(f"src/{un} missing")
    donors_per_span = defaultdict(set)
    for kind, un, sp, lo, hi in ops:
        if kind == "move":
            donors_per_span[sp].add(un)
    for sp, dns in donors_per_span.items():
        if len(dns) >= 3:
            case.flags.append(
                "span %08X-%08X receives partial fns from %d donors" % (sp[0], sp[1], len(dns)))
    if case.flags:
        case.klass = "d"
        return
    case.plan = dict(ops=sorted(ops, key=lambda t: t[3]), owner=owner,
                     owned={k: sorted(v) for k, v in owned.items()},
                     contrib=dict(contrib), carves=carves)
    case.klass = "b" if carves else (
        "c" if any(k == "move" for k, *_ in ops) else "a")


# ------------------------------------------------------- source surgery ---

PRAGMA_RE = re.compile(r"^\s*#pragma\s+(scheduling|peephole)\s+(on|off|reset)\s*$")
STACK_PRAGMAS = ("scheduling", "peephole", "fp_contract", "optimization_level",
                 "opt_strength_reduction", "opt_unroll_loops", "opt_common_subs",
                 "opt_propagation", "opt_dead_assignments", "opt_loop_invariants",
                 "dont_inline", "optimize_for_size", "opt_unroll_count")
ANY_PRAGMA_RE = re.compile(r"^\s*#pragma\s+(\w+)\s+(\S+)\s*$")
ABS_PRAGMAS = ("ppc_unroll_speculative", "ppc_unroll_factor_limit",
               "ppc_unroll_instructions_limit")


def balance_pragmas(seg_text):
    """Make a segment NET-ZERO on every stacked pragma kind so its internal
    pragma forest cannot leak state into source that follows it in the
    assembled file (reset POPS a stack — recipe #1). Bare over-popping
    resets (no matching push within the segment) are dropped; unmatched
    pushes get appended resets. Returns (text, notes, flags)."""
    lines = seg_text.split("\n")
    depth = {k: 0 for k in STACK_PRAGMAS}
    drop = set()
    notes, flags = [], []
    for i, l in enumerate(lines):
        m = ANY_PRAGMA_RE.match(l)
        if not m:
            continue
        kind, act = m.groups()
        if kind in ABS_PRAGMAS:
            flags.append(f"segment uses absolute pragma {kind} (manual)")
        if kind not in STACK_PRAGMAS:
            continue
        if act == "reset":
            if depth[kind] == 0:
                drop.add(i)
                notes.append(f"dropped over-popping '#pragma {kind} reset'")
            else:
                depth[kind] -= 1
        else:
            depth[kind] += 1
    out = [l for i, l in enumerate(lines) if i not in drop]
    tail = []
    for kind, d in depth.items():
        for _ in range(d):
            tail.append(f"#pragma {kind} reset")
    if tail:
        notes.append(f"balanced segment pragma stack: appended {len(tail)} reset(s)")
        out.append("/* segment pragma-stack balance (re-split): */")
        out.extend(tail)
    return "\n".join(out), notes, flags
FNHEAD_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9 \t\*]*?([A-Za-z_]\w*)\s*\(")
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do"}


def strip_code(line, in_block=False):
    """Code content of one line with comments and literal bodies removed."""
    out, i, n = [], 0, len(line)
    state = "block" if in_block else None
    while i < n:
        c = line[i]
        if state == "block":
            if c == "*" and line[i + 1:i + 2] == "/":
                state = None
                i += 2
                continue
            i += 1
        elif state == "str":
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state = None
            i += 1
        elif state == "chr":
            if c == "\\":
                i += 2
                continue
            if c == "'":
                state = None
            i += 1
        elif c == "/" and line[i + 1:i + 2] == "/":
            break
        elif c == "/" and line[i + 1:i + 2] == "*":
            state = "block"
            i += 2
        else:
            if c == '"':
                state = "str"
            elif c == "'":
                state = "chr"
            out.append(c)
            i += 1
    return "".join(out), state == "block"


def _classify_head(stripped, i, pos, max_lines=60):
    """From '(' position (line i, char pos just after it) decide whether the
    construct is a fn 'def' (incl. one-line and K&R), 'proto', or None."""
    n = len(stripped)
    pd = 1
    j, p = i, pos
    while j < n and j <= i + max_lines:
        s = stripped[j]
        while p < len(s):
            ch = s[p]
            if ch == "(":
                pd += 1
            elif ch == ")":
                pd -= 1
                if pd == 0:
                    return _after_paren(stripped, j, p + 1, i, max_lines)
            p += 1
        j += 1
        p = 0
    return None


def _after_paren(stripped, j, p, head, max_lines):
    n = len(stripped)
    seen_text = False
    while j < n and j <= head + max_lines:
        s = stripped[j]
        while p < len(s):
            ch = s[p]
            if ch == "{":
                return "def"
            if ch == "=":
                return None
            if ch == ";":
                if not seen_text:
                    return "proto"
            elif not ch.isspace():
                seen_text = True   # K&R param decls between ')' and '{'
            p += 1
        j += 1
        p = 0
    return None


def parse_fn_spans(text):
    """[(name, head_line, end_line)] 0-based inclusive spans of top-level fn
    definitions (incl. one-line bodies and K&R); brace depth tracked through
    strings/comments."""
    lines = text.split("\n")
    stripped = []
    in_block = False
    for l in lines:
        c, in_block = strip_code(l, in_block)
        stripped.append(c)
    spans = []
    depth = 0
    i, n = 0, len(lines)
    while i < n:
        line, code = lines[i], stripped[i]
        if (depth == 0 and line and line[0] not in " \t#/}{"
                and "(" in code
                and not line.startswith("extern") and not line.startswith("typedef")):
            m = FNHEAD_RE.match(code)
            if m and m.group(1) not in KEYWORDS:
                kind = _classify_head(stripped, i, m.end())
                if kind == "def":
                    d, started = 0, False
                    e = i
                    for e in range(i, n):
                        d += stripped[e].count("{") - stripped[e].count("}")
                        if "{" in stripped[e]:
                            started = True
                        if started and d <= 0:
                            break
                    name = m.group(1)
                    head = i
                    # return-type-on-own-line form (Ghidra phantoms:
                    # "undefined4\nFUN_xxxx(...)"): FNHEAD_RE eats the first
                    # char of the leading identifier as a return-type token
                    # (FUN -> UN). When the head line itself starts with the
                    # full callable identifier directly before '(' and the
                    # line above is a bare type token, take the real name and
                    # extend the span upward so projection collapses the type
                    # line too (else it orphans as broken syntax).
                    bm = re.match(r"^([A-Za-z_]\w*)\s*\(", code)
                    if bm and head > 0:
                        prev = stripped[head - 1].strip()
                        if prev and re.fullmatch(
                                r"[A-Za-z_][\w \t\*]*", prev) and \
                                "(" not in prev and ";" not in prev:
                            name = bm.group(1)
                            head -= 1
                    spans.append((name, head, e))
                    i = e + 1
                    continue
        depth += code.count("{") - code.count("}")
        i += 1
    return spans


def fn_prototype(lines, head, end):
    sig = []
    for k in range(head, end + 1):
        code, _ = strip_code(lines[k])
        if "{" in code:
            sig.append(lines[k].split("{", 1)[0])
            break
        sig.append(lines[k])
    s = re.sub(r"\s+", " ", " ".join(x.strip() for x in sig)).strip()
    if not s.endswith(")"):
        p = s.rfind(")")
        if p >= 0:
            s = s[:p + 1]
    return s + ";"


def project(text, keep_names):
    """Skeleton projection: all top-level fn defs NOT in keep_names collapse
    to one-line prototypes at the same position."""
    lines = text.split("\n")
    cut = sorted((h, e, nm) for nm, h, e in parse_fn_spans(text)
                 if nm not in keep_names)
    out, pos = [], 0
    for h, e, nm in cut:
        out.extend(lines[pos:h])
        out.append(fn_prototype(lines, h, e))
        pos = e + 1
    out.extend(lines[pos:])
    return "\n".join(out)


def prune_unused_externs(seg_text, keep_names):
    """Drop top-level extern/proto decls from a MOVE/CARVE segment whose
    declared name is referenced NOWHERE in the RETAINED segment. These are
    dead drift-era phantoms (v1.1 FUN_xxxx, donor-local helper externs the
    moved fns don't call) the projection drags along verbatim. Carrying a
    dead extern into the owner is harmless UNLESS its signature conflicts
    with the owner's own decl/calls (e.g. a 2-arg `GameBit_Set` prototype
    breaking a 1-arg owner call -> phantom in_fN), which #57 repair cannot
    auto-fix because the resulting error is not a redecl. Pruning the dead
    decl removes the conflict at the source. Only extern/proto are touched
    (typedef/tagdef/vardef/define kept: transitive-dep and reconcile-safe).

    The reference scan is over the ENTIRE retained segment EXCEPT the
    extern/proto decl lines themselves — not just kept fn bodies — so a
    decl referenced by a RETAINED descriptor/jump-table initializer (a
    vardef like gAppleOnTreeObjDescriptor referencing appleontree_init /
    appleontree_update + K) is kept (r8017AC2C)."""
    lines = seg_text.split("\n")
    decl_lines = set()
    for kind, name, h, e in parse_top_items(seg_text):
        if kind in ("extern", "proto") and name:
            decl_lines.update(range(h, e + 1))
    scan = "\n".join(l for i, l in enumerate(lines) if i not in decl_lines)
    dropped = []
    drop = set()
    for kind, name, h, e in parse_top_items(seg_text):
        if kind in ("extern", "proto") and name:
            if not re.search(r"\b%s\b" % re.escape(name), scan):
                drop.update(range(h, e + 1))
                dropped.append(name)
    if not drop:
        return seg_text, []
    out = [l for i, l in enumerate(lines) if i not in drop]
    return "\n".join(out), sorted(set(dropped))


def defined_fns(text):
    return set(n for n, h, e in parse_fn_spans(text))


def comment_start(lines, head):
    """Extend a fn head upward over its attached comment block."""
    k = head
    while k > 0:
        prev = lines[k - 1].rstrip()
        if prev.endswith("*/"):
            j = k - 1
            while j >= 0 and "/*" not in lines[j]:
                j -= 1
            if j < 0:
                break
            k = j
            continue
        if prev.lstrip().startswith("//"):
            k -= 1
            continue
        break
    return k


def demote_fns(text, names, note):
    """Helper-last relocation: collapse the named defs to prototypes in place
    and append the definitions (with their comments) at EOF, AFTER all their
    callers, so MWCC cannot inline them upward."""
    lines = text.split("\n")
    spans = sorted((h, e, n) for n, h, e in parse_fn_spans(text) if n in names)
    if not spans:
        return text
    out, extracted, pos = [], [], 0
    for h, e, nm in spans:
        cs = max(comment_start(lines, h), pos)
        out.extend(lines[pos:cs])
        out.append(fn_prototype(lines, h, e))
        extracted.extend(lines[cs:e + 1])
        extracted.append("")
        pos = e + 1
    out.extend(lines[pos:])
    out.append("")
    out.append(f"/* === helper-last relocation ({note}; defs moved below their "
               f"callers to suppress cross-TU-merge auto-inlining) === */")
    out.extend(extracted)
    return "\n".join(out)


# ------------------------------------------------- decl reconciliation ---

DEFINE_RE = re.compile(r"^#define\s+([A-Za-z_]\w*)")
EXTERN_RE = re.compile(r"^extern\b")
TYPEDEF_RE = re.compile(r"^(typedef\b|struct\s+\w+\s*\{|union\s+\w+\s*\{|enum\s+\w+\s*\{)")


def parse_top_items(text):
    """Classify top-level constructs: [(kind, name, head, end)] with kinds
    define/extern/proto/typedef/fn. Lines 0-based inclusive."""
    lines = text.split("\n")
    fn_spans = {(h, e) for _, h, e in parse_fn_spans(text)}
    fn_by_head = {h: (n, e) for n, h, e in parse_fn_spans(text)}
    items = []
    in_block = False
    i, n = 0, len(lines)
    while i < n:
        if i in fn_by_head:
            nm, e = fn_by_head[i]
            items.append(("fn", nm, i, e))
            i = e + 1
            continue
        line = lines[i]
        code, nb = strip_code(line, in_block)
        if in_block or not line or line[0] in " \t/}":
            in_block = nb
            i += 1
            continue
        m = DEFINE_RE.match(line)
        if m:
            e = i
            while e < n and lines[e].rstrip().endswith("\\"):
                e += 1
            items.append(("define", m.group(1), i, e))
            i = e + 1
            continue
        if TYPEDEF_RE.match(line) or EXTERN_RE.match(line) or \
                (code.strip() and ("(" in code or ";" in code or "=" in code or "{" in code)):
            # scan to terminating ';' at depth 0
            d = 0
            e = i
            bc = in_block
            found = False
            for e in range(i, min(i + 400, n)):
                ce, bc = strip_code(lines[e], bc)
                for ch in ce:
                    if ch == "{":
                        d += 1
                    elif ch == "}":
                        d -= 1
                    elif ch == ";" and d == 0:
                        found = True
                if found:
                    break
            full = "\n".join(lines[i:e + 1])
            scode = " ".join(strip_code(l)[0] for l in lines[i:e + 1])
            scode = re.sub(r"\s+", " ", scode).strip()
            kind, name = classify_decl(scode)
            if kind:
                items.append((kind, name, i, e))
            in_block = bc
            i = e + 1
            continue
        in_block = nb
        i += 1
    return items


def decl_target_name(scode):
    """The declared identifier of an extern/proto statement (handles fn
    pointers: extern void (*fp)(int);)."""
    m = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*[\)\[]", scode)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z_]\w*)\s*\(", scode)
    if m and m.group(1) not in ("extern", "static", "const", "volatile",
                                "struct", "union", "enum"):
        return m.group(1)
    m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\]\s*)*;$", scode)
    return m.group(1) if m else None


def classify_decl(scode):
    """(kind, name) for a flattened top-level decl/def statement."""
    m = re.match(r"typedef\b.*?[\s\*\}]([A-Za-z_]\w*)(\[[^\]]*\])?\s*;$", scode)
    if m:
        return "typedef", m.group(1)
    m = re.match(r"(struct|union|enum)\s+([A-Za-z_]\w*)\s*\{", scode)
    if m and scode.endswith(";") and "typedef" not in scode:
        return "tagdef", m.group(2)
    if scode.startswith("extern"):
        return "extern", decl_target_name(scode)
    m = re.match(r"[A-Za-z_][\w \t\*]*?([A-Za-z_]\w*)\s*\([^;]*\)\s*;$", scode)
    if m and m.group(1) not in KEYWORDS:
        return "proto", m.group(1)
    if "=" in scode or scode.endswith(";"):
        m = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\]\s*)*(=|;)", scode)
        if m:
            return "vardef", m.group(1)
    return None, None


def decl_tag(scode):
    m = re.match(r"typedef\s+(struct|union|enum)\s+([A-Za-z_]\w*)\s*\{", scode)
    return m.group(2) if m else None


def norm_item_text(lines, h, e):
    s = " ".join(strip_code(l)[0] for l in lines[h:e + 1])
    return re.sub(r"\s+", " ", s).strip()


def reconcile_segment(host_text, seg_text):
    """Static-phase conflict pass for an appended segment: identical
    typedef/tagdef dups dropped (MWCC errors even on identical redefs),
    #define conflicts get #undef, duplicate fn/var DEFINITIONS flag.
    extern/proto conflicts are left to the compile-error-driven #57 repair.
    Returns (new_seg, notes, flags)."""
    notes, flags = [], []
    hl = host_text.split("\n")
    sl = seg_text.split("\n")
    host_by = defaultdict(list)
    for kind, name, h, e in parse_top_items(host_text):
        if not name:
            continue
        t = norm_item_text(hl, h, e)
        host_by[name].append((kind, t))
        if kind == "typedef":
            tag = decl_tag(t)
            if tag:
                host_by["tag:" + tag].append((kind, t))

    drop_lines = set()
    undef_before = {}

    for kind, name, h, e in parse_top_items(seg_text):
        if not name:
            continue
        seg_norm = norm_item_text(sl, h, e)
        keys = [name]
        if kind == "typedef":
            tag = decl_tag(seg_norm)
            if tag:
                keys.append("tag:" + tag)
        if kind == "tagdef":
            keys.append("tag:" + name)
        hk = [x for k in keys for x in host_by.get(k, [])]
        if not hk:
            continue
        same = any(t == seg_norm for _, t in hk)
        if kind == "fn":
            if any(k == "fn" for k, t in hk):
                flags.append(f"duplicate fn definition {name}")
        elif kind in ("typedef", "tagdef"):
            if same:
                drop_lines.update(range(h, e + 1))
                notes.append(f"dropped duplicate {kind} {name}")
            else:
                flags.append(f"conflicting {kind} {name}")
        elif kind == "define":
            if not same:
                undef_before[h] = name
                notes.append(f"#undef {name} before segment redefinition")
        elif kind in ("extern", "proto"):
            # MWCC GC/2.0 rejects a redundant IDENTICAL file-scope extern/proto
            # with "illegal name overloading" (not a redecl error #57 can
            # catch), so drop a segment extern/proto whose normalized text
            # equals a host extern/proto of the same name. Non-identical
            # forms stay for the compile-error-driven #57 repair.
            if same and any(k in ("extern", "proto") for k, t in hk):
                drop_lines.update(range(h, e + 1))
                notes.append(f"dropped duplicate {kind} {name}")
        elif kind == "vardef":
            if any(k == "vardef" for k, t in hk):
                flags.append(f"duplicate variable definition {name}")
    if flags:
        return seg_text, notes, flags
    out = []
    for idx, l in enumerate(sl):
        if idx in undef_before:
            out.append(f"#undef {undef_before[idx]}")
        if idx not in drop_lines:
            out.append(l)
    return "\n".join(out), notes, flags


# --------------------------------------------------------------- editing ---

def edit_splits(text, range_changes, deletions, insertions):
    """insertions: ordered [(anchor_old_unit, new_unit, s, e)] — stacked after
    the anchor's block in list order."""
    lines = text.split("\n")
    out, i, n = [], 0, len(lines)
    handled = set()
    while i < n:
        line = lines[i]
        if line and line[0] not in " \t" and line.endswith(":"):
            un = line[:-1]
            j = i + 1
            block = [line]
            while j < n and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                block.append(lines[j])
                j += 1
            if un in deletions:
                handled.add(un)
                if j < n and lines[j] == "":
                    j += 1
                i = j
                continue
            if un in range_changes:
                ns, ne = range_changes[un]
                block = [re.sub(r"(\.text\s+)start:0x[0-9A-Fa-f]+ end:0x[0-9A-Fa-f]+",
                                lambda m: f"{m.group(1)}start:0x{ns:08X} end:0x{ne:08X}",
                                bl) if ".text" in bl else bl for bl in block]
                handled.add(un)
            out.extend(block)
            for (after, new_un, s, e) in insertions:
                if after == un:
                    out.append("")
                    out.append(f"{new_un}:")
                    out.append(f"\t.text       start:0x{s:08X} end:0x{e:08X}")
                    handled.add(new_un)
            i = j
            continue
        out.append(line)
        i += 1
    missing = (set(range_changes) | set(deletions) |
               set(x[1] for x in insertions)) - handled
    if missing:
        raise RuntimeError(f"splits.txt edit missed: {missing}")
    return "\n".join(out)


def edit_configure(text, deletions, insertions):
    """insertions: ordered [(anchor_old_unit, new_unit, cflags_suffix)]."""
    lines = text.split("\n")

    def obj_unit(l):
        m = re.search(r'Object\(\w+(?:\("[^"]*"\))?,\s*"([^"]+)"', l)
        return m.group(1) if m else None

    for unit in deletions + [a for a, _, _ in insertions]:
        cnt = sum(1 for l in lines if obj_unit(l) == unit)
        if cnt != 1:
            raise RuntimeError(f"configure.py: {unit} matched {cnt} Object lines")

    out = []
    del_units = set(deletions)
    for l in lines:
        un = obj_unit(l)
        if un in del_units:
            del_units.discard(un)
            continue
        out.append(l)
        if un:
            for (anchor, new_un, suffix) in insertions:
                if anchor == un:
                    indent = re.match(r"^\s*", l).group(0)
                    out.append(f'{indent}Object(NonMatching, "{new_un}"{suffix}),')
    if del_units:
        raise RuntimeError(f"configure.py deletions missed: {del_units}")
    return "\n".join(out)


# ---------------------------------------------------------------- naming ---

def derive_name(w, did):
    r = next(x for x in w.rows if x["dll_id"] == did)
    if r["names"]:
        base = re.sub(r"[^A-Za-z0-9]", "", r["names"][0]).lower()
    else:
        names = [w.sym_at.get(v, "") for _, v in r["fns"] if v in w.sym_at]
        names = [n for n in names if n and not n.startswith("fn_")]
        pre = os.path.commonprefix(names).rstrip("_") if names else ""
        base = re.sub(r"[^A-Za-z0-9]", "", pre).lower()
    return f"dll_{did:04X}_{base or 'unk'}.c"


def span_descriptor(w, span):
    """dll id whose TU end == span end (initialise-end pin), else None."""
    for r in w.rows:
        if r["hi"] and w.fn_end(r["hi"]) == span[1] and r["lo"] is not None \
                and r["lo"] >= span[0]:
            return r["dll_id"]
    return None


def name_is_junk(un):
    b = os.path.basename(un)
    return bool(re.match(r"^(dll_[0-9A-Fa-f]{2,3}\.c|modgfx\d+\.c|modcloudrunner2\.c|"
                         r"modanimeflash\d+\.c)$", b))


# ------------------------------------------------------------- executor ---

def run_cmd(cmd, timeout=1200):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          timeout=timeout)


def fresh_report():
    if os.path.exists(REPORT):
        os.remove(REPORT)
    r = run_cmd(["ninja", "build/GSAE01/report.json"], timeout=600)
    if r.returncode != 0 or not os.path.exists(REPORT):
        raise RuntimeError("report build failed:\n" + (r.stdout + r.stderr)[-2000:])
    return json.load(open(REPORT))


def snapshot(report, src_paths):
    fns, mc = {}, 0
    for u in report["units"]:
        sp = u.get("metadata", {}).get("source_path", u["name"])
        if sp not in src_paths:
            continue
        mc += int(u.get("measures", {}).get("matched_code", "0") or 0)
        for f in u.get("functions", []) or []:
            va = int(f.get("metadata", {}).get("virtual_address", "0"))
            fns[va] = (f["name"], int(f["size"]), f.get("fuzzy_match_percent", 0.0))
    return fns, mc


def conservation_diff(before, after):
    msgs = []
    bf, bmc = before
    af, amc = after
    for va in sorted(set(bf) | set(af)):
        b, a = bf.get(va), af.get(va)
        if b is None:
            msgs.append(f"  +{va:08X} {a[0]} appeared (size {a[1]}, fuzzy {a[2]})")
        elif a is None:
            msgs.append(f"  -{va:08X} {b[0]} disappeared (size {b[1]}, fuzzy {b[2]})")
        elif (b[1], round(b[2], 4)) != (a[1], round(a[2], 4)):
            msgs.append(f"  ~{va:08X} {b[0]}: size {b[1]}->{a[1]} fuzzy {b[2]}->{a[2]}")
    if bmc != amc:
        msgs.append(f"  matched_code sum {bmc} -> {amc}")
    return msgs


class Executor:
    def __init__(self, w: World, case: Case, base_report, verbose=True):
        self.w = w
        self.case = case
        self.base_report = base_report
        self.touched = set()
        self.created = set()
        self.deleted = set()
        self.notes = []
        self.verbose = verbose
        self.final_name = {}

    def say(self, msg):
        self.notes.append(msg)
        if self.verbose:
            print("    " + msg)

    # ---------- naming ----------
    def compute_names(self):
        w, case = self.w, self.case
        plan = case.plan
        owner, owned = plan["owner"], plan["owned"]
        final = {}
        for sp in case.spans:
            un = owner[sp]
            if len(owned[un]) == 1:
                merged = len(plan["contrib"][sp]) > 1
                new_un = un
                if merged and name_is_junk(un):
                    did = span_descriptor(w, sp)
                    if did is not None:
                        new_un = os.path.join(os.path.dirname(un),
                                              derive_name(w, did)).replace("\\", "/")
                final[sp] = new_un
            else:
                keep = None
                if not case.dissolve:
                    # donor name stays on the piece without a descriptor-pinned
                    # canonical name (the fragment piece), else on the largest
                    unnamed = [s for s in owned[un] if span_descriptor(w, s) is None]
                    keep = (unnamed[0] if len(unnamed) == 1
                            else max(owned[un], key=lambda s: s[1] - s[0]))
                if sp == keep:
                    final[sp] = un
                else:
                    did = span_descriptor(w, sp)
                    nm = derive_name(w, did) if did is not None else "dll_%08X.c" % sp[0]
                    final[sp] = os.path.join(os.path.dirname(un), nm).replace("\\", "/")
        if len(set(final.values())) != len(final):
            raise RuntimeError("final unit name collision")
        self.final_name = final

    # ---------- pragma wrapping (retry mode) ----------
    def unit_default(self, un):
        ent = self.w.cfg_lines.get(un)
        suffix = ent[1] if ent else ""
        if "noopt" in suffix:
            return ("off", "off")
        if "nosched" in suffix:
            return ("off", "on")
        if "nopeep" in suffix:
            return ("on", "off")
        return ("on", "on")

    def wrap_segment(self, seg, donor_unit, host_suffix):
        d = self.unit_default(donor_unit)
        h = (("off", "off") if "noopt" in host_suffix else
             ("off", "on") if "nosched" in host_suffix else
             ("on", "off") if "nopeep" in host_suffix else ("on", "on"))
        if d == h:
            return seg
        pre, post = [], []
        if d[0] != h[0]:
            pre.append(f"#pragma scheduling {d[0]}")
            post.append("#pragma scheduling reset")
        if d[1] != h[1]:
            pre.append(f"#pragma peephole {d[1]}")
            post.append("#pragma peephole reset")
        return "\n".join(pre) + "\n" + seg.rstrip("\n") + "\n" + "\n".join(post)

    # ---------- inline-regression analysis (helper-last retry) ----------
    def compute_demote(self, regressed):
        """For each regressed fn, find co-resident callees defined ABOVE it
        in the applied final files: the auto-inline suspects. Returns
        {final_unit: set(fn names)} safe to demote (no other caller below
        would lose an existing inline).

        A MOVED-in fn (address in self.moved_addrs) is a suspect even when
        the address-order assembly interleaved it into the owner's own
        segment region (the segment-mark test alone misses it — e.g. a 264B
        donor fn auto-inlining into its owner caller, r801159E4)."""
        moved_names = {self.w.sym_at[a] for a in getattr(self, "moved_addrs", [])
                       if a in self.w.sym_at}
        out = {}
        for sp in self.case.spans:
            fin = self.final_name[sp]
            path = os.path.join(REPO, "src", fin)
            if not os.path.exists(path):
                continue
            text = read(path)
            lines = text.split("\n")
            marks = [i for i, l in enumerate(lines)
                     if l.startswith("/* === merged from") or
                     l.startswith("/* === moved from")]

            def seg_of(line):
                s = 0
                for m in marks:
                    if m <= line:
                        s = m
                    else:
                        break
                return s

            fns = parse_fn_spans(text)
            bodies = {n: "\n".join(strip_code(l)[0] for l in lines[h:e + 1])
                      for n, h, e in fns}
            for rn in regressed:
                r = next(((n, h, e) for n, h, e in fns if n == rn), None)
                if r is None:
                    continue
                rseg = seg_of(r[1])
                for n, h, e in fns:
                    if e >= r[1] or n == rn:
                        continue
                    if seg_of(h) == rseg and n not in moved_names:
                        continue
                    if not re.search(r"\b%s\b" % re.escape(n), bodies[rn]):
                        continue
                    # unsafe if a NON-regressed same-segment sibling below n
                    # already calls it (demoting n past that sibling would
                    # lose an existing inline); the regressed fns are exactly
                    # the callers whose unwanted inline we are suppressing, so
                    # they must not veto the demote.
                    nseg = seg_of(h)
                    unsafe = any(seg_of(h2) == nseg and h2 > e and n2 != n
                                 and n2 not in regressed
                                 and re.search(r"\b%s\b" % re.escape(n), bodies[n2])
                                 for n2, h2, e2 in fns)
                    if not unsafe:
                        out.setdefault(fin, set()).add(n)
        return out

    # ---------- apply ----------
    def apply(self, pragma_wrap=False, helper_last=None):
        w, case = self.w, self.case
        plan = case.plan
        owner = plan["owner"]
        self.compute_names()
        final = self.final_name

        # host cflags suffix per final unit = owner's suffix
        host_suffix = {final[sp]: (w.cfg_lines.get(owner[sp]) or ("", "", ""))[1]
                       for sp in case.spans}

        # 1. base texts (carve owners get projected per piece)
        texts = {}
        moved_addrs = []
        for sp in case.spans:
            un = owner[sp]
            text = read(os.path.join(REPO, "src", un))
            if un in plan["carves"]:
                keep = set(n for a, n, s in w.fns_in(*sp))
                others = set()
                for osp in plan["owned"][un]:
                    if osp != sp:
                        others |= set(n for a, n, s in w.fns_in(*osp))
                # fns moving OUT of this donor also collapse in every piece
                for kind, dn2, sp2, lo2, hi2 in plan["ops"]:
                    if kind == "move" and dn2 == un:
                        others |= set(n for a, n, s in w.fns_in(lo2, hi2))
                present = defined_fns(text)
                text = project(text, present - (others & present))
                self.say(f"carve {un} piece [{sp[0]:08X}-{sp[1]:08X}) "
                         f"keeps {len(keep & present)} defined fns")
            texts[final[sp]] = text

        # 2. donor ops -> appended segments (address-ordered)
        seg_added = defaultdict(list)
        donor_remaining = {}    # donor unit -> evolving text (move donors)
        for kind, dn, sp, lo, hi in plan["ops"]:
            fin = final[sp]
            if kind == "absorb":
                seg = read(os.path.join(REPO, "src", dn))
                seg = self.wrap_segment(seg, dn, host_suffix[fin])
                seg_added[fin].append((lo, f"/* === merged from {dn} "
                                           f"[{lo:08X}-{hi:08X}) (TU re-split, "
                                           f"docs/boundary_audit.md) === */\n" + seg, dn))
                self.deleted.add("src/" + dn)
                self.say(f"absorb {dn} -> {fin}")
            else:
                names = [n for a, n, s in w.fns_in(lo, hi)]
                cur = donor_remaining.get(dn)
                if cur is None:
                    cur = read(os.path.join(REPO, "src", dn))
                present = defined_fns(cur)
                movable = [n for n in names if n in present]
                moved_addrs.extend(a for a, n, s in w.fns_in(lo, hi) if n in movable)
                if movable:
                    seg = project(cur, set(movable))
                    seg, pruned = prune_unused_externs(seg, set(movable))
                    if pruned:
                        self.say(f"pruned {len(pruned)} dead extern(s) from "
                                 f"{dn} move segment: {pruned}")
                    seg = self.wrap_segment(seg, dn, host_suffix[fin])
                    seg_added[fin].append(
                        (lo, f"/* === moved from {dn} [{lo:08X}-{hi:08X}) "
                             f"(TU re-split, docs/boundary_audit.md) === */\n" + seg, dn))
                    donor_remaining[dn] = project(cur, present - set(movable))
                    self.say(f"move {len(movable)} fns {movable} from {dn} -> {fin}")
                else:
                    self.say(f"move [{lo:08X}-{hi:08X}) from {dn}: "
                             f"no decompiled fns, splits-only")

        # donors that survive as owners pick up their reduced text (carve
        # donors skip this: their pieces already collapse moved-out fns)
        for dn, txt in donor_remaining.items():
            if dn in plan["carves"]:
                continue
            fins = [final[sp] for sp in case.spans if owner[sp] == dn]
            if fins:
                texts[fins[0]] = txt

        # assemble each final unit in ADDRESS order (mirrors the original TU
        # layout; callees keep their original position relative to callers)
        unit_start = {un: us for us, ue, un in case.units}
        for fin, segs in seg_added.items():
            base_owner = owner[next(sp for sp in case.spans if final[sp] == fin)]
            segs = sorted(segs + [(unit_start[base_owner], texts[fin], base_owner)],
                          key=lambda t: t[0])
            balanced = []
            for k, (addr, seg, dn) in enumerate(segs):
                if k < len(segs) - 1:
                    seg, bnotes, bflags = balance_pragmas(seg)
                    for nt in bnotes:
                        self.say(f"pragma-balance {dn}: {nt}")
                    if bflags:
                        raise RuntimeError(f"pragma balance {dn}: " + "; ".join(bflags))
                balanced.append((addr, seg, dn))
            segs = balanced
            acc = segs[0][1].rstrip("\n")
            for addr, seg, dn in segs[1:]:
                seg2, notes, flags = reconcile_segment(acc, seg)
                for nt in notes:
                    self.say(f"reconcile {dn}: {nt}")
                if flags:
                    raise RuntimeError(f"decl reconcile {dn}: " + "; ".join(flags))
                acc = acc + "\n\n" + seg2.rstrip("\n")
            texts[fin] = acc + "\n"

        # helper-last relocation of inline suspects (retry mode)
        if helper_last:
            for fin, names in helper_last.items():
                if fin in texts and names:
                    texts[fin] = demote_fns(texts[fin], names,
                                            "re-split inline suppression")
                    self.say(f"helper-last: demoted {sorted(names)} in {fin}")

        # 3. write sources
        survivors = set(final.values())
        for sp in case.spans:
            fin = final[sp]
            path = "src/" + fin
            existed = os.path.exists(os.path.join(REPO, path))
            write(os.path.join(REPO, path), texts[fin])
            (self.touched if existed else self.created).add(path)
            base_un = owner[sp]
            if fin != base_un and base_un not in survivors:
                self.deleted.add("src/" + base_un)
        for us, ue, un in case.units:
            if un not in survivors:
                self.deleted.add("src/" + un)
        for p in self.deleted:
            fp = os.path.join(REPO, p)
            if os.path.exists(fp):
                os.remove(fp)

        # 4. splits.txt + configure.py
        old_names = set(u[2] for u in case.units)
        prev_global = w.unit_before(case.units[0][0])
        range_changes, insertions = {}, []
        anchor = prev_global
        for sp in case.spans:
            fin = final[sp]
            if fin in old_names:
                range_changes[fin] = sp
                anchor = fin
            else:
                insertions.append((anchor, fin, sp))
        for fname, old_addr, new_addr in case.floaters:
            if new_addr != old_addr:
                range_changes[fname] = (new_addr, new_addr)
                self.say(f"floater {fname} rides 0x{old_addr:08X} -> 0x{new_addr:08X}")
        deletions = [un for us, ue, un in case.units if un not in survivors]
        write(SPLITS, edit_splits(read(SPLITS), range_changes, deletions,
                                  [(a, f, s, e) for a, f, (s, e) in insertions]))
        self.touched.add("config/GSAE01/splits.txt")

        cfg_ins = []
        for a, f, sp in insertions:
            cfg_ins.append((a, f, host_suffix[f]))
        # stack multiple inserts on one anchor in address order: emit in
        # reverse so insert-after keeps address order? edit_configure appends
        # in list order right after the anchor line as it streams -> multiple
        # entries for one anchor land in list order. keep address order.
        write(CONFIGURE, edit_configure(read(CONFIGURE), deletions, cfg_ins))
        self.touched.add("configure.py")
        self.moved_addrs = moved_addrs

    # ---------- compile-error-driven decl repair (recipe #57) ----------
    REDECL_RE = re.compile(
        r"#\s+(\d+): ([^\n]*)\n#\s+Error:[^\n]*\n"
        r"#\s+identifier '([^']+)'\s*(?:\n#)?\s*redeclared")
    FILE_RE = re.compile(r"#\s+File: (\S+)")

    def repair_unit(self, fin, budget=200):
        """Compile the final unit's .o; on each 'identifier redeclared' error,
        remove the conflicting top-level decl and inject it block-scope into
        the referencing fns that saw it (recipe #57). Other errors raise."""
        obj = "build/GSAE01/src/" + fin[:-2] + ".o"
        path = os.path.join(REPO, "src", fin)
        seen = set()
        while budget > 0:
            r = run_cmd(["ninja", obj], timeout=600)
            log = r.stdout + r.stderr
            if r.returncode == 0:
                return
            low = log.lower()
            if "sjis" in low and ("warn" in low or "error" in low) and "sjiswrap" not in low:
                raise RuntimeError("sjiswrap issue compiling " + fin)
            m = self.REDECL_RE.search(log)
            if not m:
                i = log.rfind("Error:")
                detail = log[max(0, i - 400):i + 600] if i >= 0 else log[-1800:]
                raise RuntimeError(f"compile error in {fin} (not a redecl):\n" + detail)
            lineno, decl_text, ident = int(m.group(1)), m.group(2).strip(), m.group(3)
            name = ident.split("(")[0].strip()
            if (name, lineno) in seen:
                raise RuntimeError(
                    f"redecl repair of {name} in {fin} made no progress "
                    f"(line {lineno}: {decl_text})")
            seen.add((name, lineno))
            files = self.FILE_RE.findall(log[:m.start()])
            err_file = (files[-1] if files else "").replace("\\", "/")
            text = read(path)
            lines = text.split("\n")
            # an injected override MWCC won't accept (type-pair-dependent
            # block-redecl tolerance): drop the injection, let the
            # conservation gate arbitrate whether the form was load-bearing
            if 0 <= lineno - 1 < len(lines) and "/* #57 */" in lines[lineno - 1]:
                l = lines[lineno - 1]
                if l.strip().startswith("extern"):
                    del lines[lineno - 1]
                else:
                    p, q = l.find("{"), l.find("/* #57 */")
                    lines[lineno - 1] = re.sub(r"\{.*?/\* #57 \*/", "{", l, count=1)
                write(path, "\n".join(lines))
                self.say(f"#57 injection for {name} rejected by MWCC, dropped "
                         f"(gate arbitrates)")
                budget -= 1
                continue
            ok = self._repair_redecl(lines, name)
            if not ok and 0 <= lineno - 1 < len(lines):
                # pre-existing BLOCK-scope extern conflicting with a decl now
                # visible after the merge (header side unremovable): drop the
                # block decl, conservation gate arbitrates the form
                l = lines[lineno - 1]
                if l.startswith((" ", "\t")) and l.strip().startswith("extern") \
                        and l.strip().endswith(";"):
                    del lines[lineno - 1]
                    write(path, "\n".join(lines))
                    self.say(f"dropped conflicting block-scope extern {name} "
                             f"(gate arbitrates)")
                    budget -= 1
                    continue
            if not ok:
                raise RuntimeError(
                    f"unrepairable redecl of {name} in {fin} (err file {err_file}, "
                    f"line {lineno}: {decl_text})")
            write(path, "\n".join(lines))
            self.say(f"#57 repair: {name} in {fin}")
            budget -= 1
        raise RuntimeError(f"repair budget exhausted for {fin}")

    def _repair_redecl(self, lines, name):
        """Remove ALL top-level extern/proto decls of `name` from the file;
        inject each removed form block-scope into the referencing fns in its
        region of influence (decl line .. next decl of the same name). Fns
        before the first decl keep whatever a header provides. Legal per the
        MWCC probes: block-scope externs without a visible file-scope object
        decl never conflict; incompatible FUNCTION block redecls under a
        visible header decl are accepted too."""
        text = "\n".join(lines)
        all_items = parse_top_items(text)
        items = [(k, n, h, e) for k, n, h, e in all_items
                 if n == name and k in ("extern", "proto")]
        if not items:
            return False
        pat = re.compile(r"\b%s\b" % re.escape(name))
        fns = parse_fn_spans(text)
        # top-level initializer references cannot be block-scoped: keep the
        # nearest decl ABOVE each such initializer (descriptor tables) unless
        # a DEFINITION above already satisfies it
        def_heads = [h for k, n2, h, e in all_items if k == "fn" and n2 == name]
        keep = set()
        for k2, n2, h2, e2 in all_items:
            if k2 == "vardef" and n2 != name and pat.search(norm_item_text(lines, h2, e2)):
                if any(dh < h2 for dh in def_heads):
                    continue
                above = [(h, i) for i, (k, n3, h, e) in enumerate(items) if e < h2]
                if not above:
                    return False
                keep.add(max(above)[1])
        items = [it for i, it in enumerate(items) if i not in keep]
        if not items:
            return False
        bounds = [h for k, n, h, e in items] + [len(lines)]
        injections = []   # (fn_head, decl)
        # an extern block-scope decl of `name` already present in a fn body
        block_decl_re = re.compile(
            r"^\s*extern\b.*\b%s\b" % re.escape(name))
        for idx, (k, n, h, e) in enumerate(items):
            decl = norm_item_text(lines, h, e)
            if not decl.startswith("extern"):
                decl = "extern " + decl
            lo, hi = e + 1, bounds[idx + 1]
            for fn, fh, fe in fns:
                if lo <= fh < hi and pat.search(
                        "\n".join(strip_code(l)[0] for l in lines[fh:fe + 1])):
                    # don't double-inject when the fn already block-declares it
                    if any(block_decl_re.match(lines[kk])
                           for kk in range(fh, fe + 1)):
                        continue
                    injections.append((fh, fe, decl))
        ops = []
        for fh, fe, decl in injections:
            bc = False
            for kk in range(fh, fe + 1):
                ck, bc = strip_code(lines[kk], bc)
                if "{" in ck:
                    # body code on the brace line (one-line defs): insert the
                    # decl INSIDE the braces, else on the next line
                    after = ck.split("{", 1)[1].strip()
                    ops.append(("inl" if after else "ins", kk, decl))
                    break
        for k, n, h, e in items:
            ops.append(("del", h, e))
        # apply bottom-up so earlier indexes stay valid
        for op in sorted(ops, key=lambda t: -t[1]):
            if op[0] == "ins":
                lines.insert(op[1] + 1, "    " + op[2] + " /* #57 */")
            elif op[0] == "inl":
                l = lines[op[1]]
                p = l.find("{")
                lines[op[1]] = l[:p + 1] + " " + op[2] + " /* #57 */" + l[p + 1:]
            else:
                del lines[op[1]:op[2] + 1]
        return True

    # ---------- gates ----------
    def gate(self):
        for sp in self.case.spans:
            self.repair_unit(self.final_name[sp])
        r = run_cmd(["bash", "-c", "timeout 1100 ninja"], timeout=1200)
        log = r.stdout + r.stderr
        if r.returncode != 0:
            return False, "ninja failed:\n" + log[-3000:]
        low = log.lower()
        if "sjis" in low and "warn" in low:
            return False, "sjiswrap warning during build:\n" + log[-2000:]
        md5 = hashlib.md5(open(DOL, "rb").read()).hexdigest()
        if md5 != DOL_MD5:
            return False, f"main.dol md5 {md5} != {DOL_MD5}"
        after_report = fresh_report()
        before_paths = set("src/" + u[2] for u in self.case.units)
        after_paths = set("src/" + self.final_name[sp] for sp in self.case.spans)
        b = snapshot(self.base_report, before_paths)
        a = snapshot(after_report, after_paths)
        msgs = conservation_diff(b, a)
        if msgs:
            return False, "conservation:\n" + "\n".join(msgs)
        return True, f"{len(b[0])} fns conserved, matched_code {b[1]} unchanged"

    def revert(self):
        if os.environ.get("RESPLIT_DEBUG_SNAPSHOT"):
            import shutil
            dbg = os.environ["RESPLIT_DEBUG_SNAPSHOT"]
            os.makedirs(dbg, exist_ok=True)
            for p in sorted(self.touched | self.created):
                fp = os.path.join(REPO, p)
                if os.path.exists(fp):
                    shutil.copy(fp, os.path.join(dbg, p.replace("/", "__")))
        paths = sorted(self.touched | self.deleted)
        if paths:
            run_cmd(["git", "checkout", "--"] + paths)
        for p in sorted(self.created):
            st = run_cmd(["git", "ls-files", "--error-unmatch", p])
            fp = os.path.join(REPO, p)
            if st.returncode != 0 and os.path.exists(fp):
                os.remove(fp)
            elif st.returncode == 0:
                run_cmd(["git", "checkout", "--", p])
        run_cmd(["bash", "-c", "timeout 1100 ninja"], timeout=1200)

    def commit(self, gate_msg):
        case = self.case
        paths = sorted(self.touched | self.created | self.deleted)
        lines = [f"re-split: TU-align {case.id} ({case.dll_str()})", ""]
        lines.append("Mechanized boundary surgery (tools/dll_boundary_resplit.py; TU model")
        lines.append("from descriptor forensics, docs/boundary_audit.md):")
        for b, t in sorted(case.moves.items()):
            lines.append(f"- boundary 0x{b:08X} -> 0x{t:08X}")
        for n in self.notes:
            lines.append(f"- {n}")
        lines.append("")
        lines.append(f"Gates: full ninja green; main.dol md5 {DOL_MD5}")
        lines.append(f"(byte-identical); conservation EXACT - {gate_msg}.")
        msg = "\n".join(lines)
        r = run_cmd(["git", "add", "-A", "--"] + paths)
        if r.returncode != 0:
            raise RuntimeError("git add failed: " + r.stderr)
        r = run_cmd(["git", "commit", "-m", msg])
        if r.returncode != 0:
            raise RuntimeError("git commit failed: " + r.stderr)
        return run_cmd(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()


# ------------------------------------------------------------------ cli ---

def case_summary(w, case, verbose=True):
    print(f"{case.id}  class={case.klass}  dlls=[{case.dll_str()}]")
    if not verbose:
        return
    for us, ue, un in case.units:
        print(f"    unit [{us:08X}-{ue:08X}) {un}")
    for b, t in sorted(case.moves.items()):
        print(f"    boundary {b:08X} -> {t:08X}")
    if case.plan:
        for kind, dn, sp, lo, hi in case.plan["ops"]:
            extra = ""
            if kind == "move":
                extra = " (%d fns)" % len(w.fns_in(lo, hi))
            print(f"    {kind.upper():6} {dn} [{lo:08X}-{hi:08X}){extra} -> "
                  f"{case.plan['owner'][sp]}")
        for un in case.plan["carves"]:
            print(f"    CARVE  {un} -> {len(case.plan['owned'][un])} pieces")
    for fl in case.flags:
        print(f"    FLAG: {fl}")


def fresh_cases():
    w = World()
    cases = build_cases(w)
    for c in cases:
        plan_case(w, c)
    return w, cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--case", default=None)
    ap.add_argument("--class", dest="klass", default=None)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-commit", action="store_true")
    ap.add_argument("--pragma-wrap", action="store_true")
    ap.add_argument("--brief", action="store_true")
    ap.add_argument("--carve", default=None,
                    help="dissolve a clean multi-DLL container unit into "
                         "per-descriptor TU units (skeleton-copy carve)")
    args = ap.parse_args()

    if args.carve:
        w = World()
        c = carve_case(w, args.carve)
        if not c.flags:
            plan_case(w, c)
        else:
            c.klass = "d"
        case_summary(w, c)
        if not args.run or c.klass == "d":
            return
        base_report = fresh_report()
        ok, msg, ex = attempt(w, c, base_report)
        if ok and not args.no_commit:
            sha = ex.commit(msg)
            print(f"    COMMIT {sha}: {msg}")
        elif ok:
            print(f"    PASS (uncommitted): {msg}")
        else:
            print("    FAIL: " + msg)
        return

    w, cases = fresh_cases()

    def select(cs):
        sel = cs
        if args.case:
            sel = [c for c in sel if c.id == args.case]
        if args.klass:
            sel = [c for c in sel if c.klass == args.klass]
        if args.limit:
            sel = sel[:args.limit]
        return sel

    if args.plan or not args.run:
        counts = defaultdict(int)
        for c in cases:
            counts[c.klass] += 1
        print("cases: " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        for c in select(cases):
            case_summary(w, c, verbose=not args.brief)
        return

    ledger = json.load(open(LEDGER)) if os.path.exists(LEDGER) else []
    # key on id+dlls: region-start IDs can be reused by a different region
    # after neighbouring surgeries land
    done_ids = set((e["case"], e.get("dlls", "")) for e in ledger
                   if e.get("status") == "committed")
    todo = [c.id for c in select(cases) if (c.id, c.dll_str()) not in done_ids]
    base_report = fresh_report()

    for cid in todo:
        w, cases = fresh_cases()
        c = next((x for x in cases if x.id == cid), None)
        if c is None:
            print(f"== {cid}: vanished after prior surgery, skipping")
            continue
        if c.klass == "d":
            print(f"== {cid}: class d, flagged")
            for fl in c.flags:
                print("    " + fl)
            ledger.append(dict(case=c.id, klass=c.klass, dlls=c.dll_str(),
                               status="flagged", reasons=c.flags))
            json.dump(ledger, open(LEDGER, "w"), indent=1)
            continue
        print(f"== {cid} ({c.klass}) dlls=[{c.dll_str()}]")
        ok, msg, ex = attempt(w, c, base_report, pragma_wrap=args.pragma_wrap)
        if ok and not args.no_commit:
            sha = ex.commit(msg)
            print(f"    COMMIT {sha}: {msg}")
            ledger.append(dict(case=c.id, klass=c.klass, dlls=c.dll_str(),
                               status="committed", sha=sha))
            base_report = json.load(open(REPORT))
        elif ok:
            print(f"    PASS (uncommitted): {msg}")
            ledger.append(dict(case=c.id, klass=c.klass, dlls=c.dll_str(),
                               status="applied-uncommitted"))
        else:
            print("    FAIL: " + msg.splitlines()[0])
            for l in msg.splitlines()[1:12]:
                print("    " + l)
            ledger.append(dict(case=c.id, klass=c.klass, dlls=c.dll_str(),
                               status="flagged", reasons=[msg[:800]]))
            base_report = fresh_report()
        json.dump(ledger, open(LEDGER, "w"), indent=1)


REGRESS_RE = re.compile(r"~[0-9A-F]+ (\S+): size \d+->\d+ fuzzy ([0-9.]+)->([0-9.]+)")


def attempt(w, c, base_report, pragma_wrap=False):
    """Apply + gate with auto-retries: helper-last (inline regressions),
    then donor-default pragma wrappers."""
    ex = Executor(w, c, base_report)
    try:
        ex.apply(pragma_wrap=pragma_wrap)
        ok, msg = ex.gate()
    except Exception as e:
        ok, msg = False, f"exception: {e}"
    if ok:
        return True, msg, ex
    msgs = [msg.splitlines()[0]]

    # retry 1: helper-last for fns whose fuzzy REGRESSED (inline suspects)
    regressed = [m.group(1) for m in REGRESS_RE.finditer(msg)
                 if float(m.group(3)) < float(m.group(2))]
    demote = ex.compute_demote(regressed) if (
        msg.startswith("conservation:") and regressed) else {}
    ex.revert()
    if demote:
        print(f"    retrying helper-last: { {k: sorted(v) for k, v in demote.items()} }")
        ex2 = Executor(w, c, base_report)
        try:
            ex2.apply(pragma_wrap=pragma_wrap, helper_last=demote)
            ok2, msg2 = ex2.gate()
        except Exception as e:
            ok2, msg2 = False, f"exception: {e}"
        if ok2:
            return True, msg2 + " (with helper-last inline suppression)", ex2
        msgs.append("[helper-last retry] " + msg2.splitlines()[0])
        ex2.revert()
    return False, msg + ("\n  " + "\n  ".join(msgs[1:]) if msgs[1:] else ""), ex


if __name__ == "__main__":
    main()
