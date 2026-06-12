#!/usr/bin/env python3
"""dll_canonical_names.py — authoritative dll-id -> canonical-filename mapping.

For every gResourceDescriptors entry (reusing tools/dll_boundary_audit.load()):
  1. RETAIL NAME: OBJECTS.bin def name(s) served by the dll id (def+0x50);
     primary = the def matching the lane-family stem (symbol-prefix evidence),
     the rest listed as aliases.
  2. TRUNCATION EXPANSION: OBJECTS.bin names live in an 11-char fixed field;
     expansions are cross-referenced against config/GSAE01/symbols.txt
     function-name prefixes / descriptor symbol names (CONFIRMED), existing
     src filenames (GUESSED), else kept truncated (RAW). Names <11 chars are
     COMPLETE.
  3. PROPOSED FILE: dll_XXXX_<name>.c, name lowercased/alnum per the existing
     convention (dll_0106_scarab.c, dll_0149_cfwindlift.c,
     dll_020C_wmspiritplace.c). Lane dir = the current host's lane dir when it
     already sits in one (address-lane ownership beats name prefix — see
     DR/dll_0149_cfwindlift.c), else derived from the name prefix, else
     main/dll/ root.
  4. CURRENT STATE: single-dll host = rename candidate; multi-dll host =
     blocked-on-carve; fns spanning units = blocked-on-cut; engine/SDK host =
     blocked-on-extraction; descriptors without .text fns = no-text-fns.
  5. No-def infrastructure dlls keep their current stem, flagged
     NO-RETAIL-NAME.

Usage:
  python3 tools/dll_canonical_names.py            # summary to stdout
  python3 tools/dll_canonical_names.py --print    # full manifest md to stdout
  python3 tools/dll_canonical_names.py --regen    # rewrite docs/dll_naming_manifest.md
"""
import os, re, sys, bisect
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dll_boundary_audit as B

REPO = B.REPO
MANIFEST = os.path.join(REPO, "docs/dll_naming_manifest.md")
NAME_FIELD = 11  # OBJECTS.bin fixed name-field width: ==11 chars may be truncated

JUNK_SYM = re.compile(r"^(fn|lbl|gap|FUN|DAT|jumptable|switchD?|__)_?")
GENERIC_PREFIX = {
    "init", "update", "render", "free", "release", "main", "draw", "get",
    "set", "obj", "data", "func", "state", "the",
}

# name-prefix -> lane dir (longest match first; applied only when the current
# host is not already inside a lane dir). KT_/KP_ map per existing placements;
# None = recognized prefix with no lane dir (file goes to main/dll/ root).
LANE_PREFIXES = [
    ("FRONT", "FRONT"), ("DFSH", "DF"), ("MMSH", "mmshrine"),
    ("ECSH", None), ("GPSH", None), ("DBSH", None), ("LINK", None),
    ("TREX", "TREX"), ("VFP", "VF"), ("DFP", "DF"),
    ("ARW", "ARW"), ("CAM", "CAM"), ("DIM", "DIM"), ("LGT", "LGT"),
    ("MMP", "MMP"), ("BW", "BW"), ("CC", "CC"), ("CF", "CF"), ("CR", "CR"),
    ("DB", "DB"), ("DF", "DF"), ("DR", "DR"), ("IM", "IM"), ("KT", "DR"),
    ("NW", "NW"), ("SB", "SB"), ("SC", "SC"), ("SH", "SH"), ("SP", "SP"),
    ("VF", "VF"), ("WC", "WC"), ("WM", "WM"),
]


def norm(s):
    return re.sub(r"[^0-9a-z]", "", s.lower())


def dedup(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def complete_name(defname, evid):
    """defname truncated, norm(evid) startswith norm(defname): splice evid's tail."""
    nd = len(norm(defname))
    cnt = i = 0
    while i < len(evid) and cnt < nd:
        if norm(evid[i]):
            cnt += 1
        i += 1
    return defname + evid[i:]


def cased_stem(defname, ne):
    """extract the substring of defname whose norm equals ne (family stem casing)."""
    idxs = [i for i, c in enumerate(defname) if norm(c)]
    flat = "".join(defname[i].lower() for i in idxs)
    pos = flat.find(ne)
    if pos < 0:
        return ne
    return defname[idxs[pos]:idxs[pos + len(ne) - 1] + 1]


def build_indexes(sym_at):
    """(sorted (norm, repr) token-prefix index over symbols, file-stem index)."""
    ent = {}
    for s in sym_at.values():
        if JUNK_SYM.match(s):
            continue
        cands = []
        m = re.match(r"^g(.+?)(Obj)?Descriptor\d*$", s)
        if m:
            cands.append(m.group(1))
        toks = s.split("_")
        for k in range(1, min(len(toks), 4) + 1):
            if re.fullmatch(r"[0-9a-fA-F]{6,8}", toks[k - 1]):
                break
            cands.append("_".join(toks[:k]))
        for tp in cands:
            n = norm(tp)
            if 4 <= len(n) <= 40:
                ent.setdefault(n, Counter())[tp] += 1
    symidx = sorted((n, c.most_common(1)[0][0]) for n, c in ent.items())

    fent = {}
    for root, dirs, files in os.walk(os.path.join(REPO, "src")):
        for f in files:
            if not (f.endswith(".c") or f.endswith(".h")):
                continue
            stem = re.sub(r"^dll_[0-9A-Fa-f]{2,4}_", "", f[:-2])
            n = norm(stem)
            if 4 <= len(n) <= 40:
                fent.setdefault(n, stem)
    fileidx = sorted(fent.items())
    return symidx, fileidx


def prefix_lookup(idx, nw):
    """entries whose norm strictly extends nw."""
    i = bisect.bisect_left(idx, (nw,))
    out = []
    while i < len(idx) and idx[i][0].startswith(nw):
        if len(idx[i][0]) > len(nw):
            out.append(idx[i][1])
        i += 1
    return out


def expand_def(defname, local_evid, symidx, fileidx):
    """-> (expanded, status). status: COMPLETE | CONFIRMED | GUESSED | RAW."""
    if len(defname) < NAME_FIELD:
        return defname, "COMPLETE"
    nd = norm(defname)
    for ev in local_evid:
        ne = norm(ev)
        if ne.startswith(nd) and len(ne) > len(nd):
            return complete_name(defname, ev), "CONFIRMED"
        if ne == nd:
            return defname, "CONFIRMED"
    rest = lane_rest(defname)
    if rest:
        # suffix overlap: lane-prefixed def, un-prefixed symbols — the fn
        # prefix must cover the def's ENTIRE post-lane tail
        # (VFP_seqpoin/seqpoint_*, LGTPointLig/pointlight_*)
        for ev in local_evid:
            ne = norm(ev)
            k = len(rest)
            if len(ne) > k and nd[-k:] == ne[:k] == rest:
                idxs = [i for i, c in enumerate(ev) if norm(c)]
                tail = ev[idxs[k - 1] + 1:]
                if tail and not tail[0].isdigit():
                    return defname + tail, "CONFIRMED"
    hits = prefix_lookup(symidx, nd)
    if hits:
        best = min(hits, key=lambda h: (len(norm(h)), h))
        return complete_name(defname, best), "CONFIRMED"
    fhits = prefix_lookup(fileidx, nd)
    if fhits:
        best = min(fhits, key=lambda h: (len(norm(h)), h))
        return complete_name(defname, best), "GUESSED"
    return defname, "RAW"


def lane_rest(defname):
    """norm of the def name after a leading lane prefix, or None."""
    for pfx, _ in sorted(LANE_PREFIXES, key=lambda p: -len(p[0])):
        if defname.startswith(pfx):
            r = defname[len(pfx):].lstrip("_")
            if r:
                return norm(r)
    return None


def sym_prefix_votes(names):
    votes = Counter()
    rep = {}
    for s in names:
        if not s or JUNK_SYM.match(s):
            continue
        toks = s.split("_")
        if re.fullmatch(r"[0-9a-fA-F]{6,8}", toks[-1]):
            continue
        p = "_".join(toks[:-1]) if len(toks) > 1 else s
        p = re.sub(r"_func[0-9A-Fa-f]{1,2}.*$", "", p)
        if re.match(r"^dll_?[0-9A-Fa-f]{1,4}($|_)", p) or len(norm(p)) < 4:
            continue
        if norm(p) in GENERIC_PREFIX:
            continue
        n = norm(p)
        votes[n] += 1
        rep.setdefault(n, p)
    return [(rep[n], c) for n, c in votes.most_common()]


def analyze():
    rows, units, unit_for, fn_end, sym_at, fn_size = B.load()
    symidx, fileidx = build_indexes(sym_at)

    txt_addrs = sorted(a for a in sym_at if a in fn_size)
    his = sorted((r["hi"], r["dll_id"]) for r in rows if r["hi"])

    def tu_start(r):
        prev = None
        for h, _ in his:
            if h < r["lo"]:
                prev = h
            else:
                break
        return fn_end(prev) if prev else r["lo"]

    unit_dlls = defaultdict(set)
    for r in rows:
        for _, v in r["fns"]:
            u = unit_for(v)
            if u:
                unit_dlls[u].add(r["dll_id"])

    lane_dirs = set(
        d for d in os.listdir(os.path.join(REPO, "src/main/dll"))
        if os.path.isdir(os.path.join(REPO, "src/main/dll", d))
    )

    recs = []
    for r in sorted(rows, key=lambda r: r["dll_id"]):
        rec = {
            "dll": r["dll_id"], "names": dedup(r["names"]), "reach": r["reach"],
            "desc_sym": r["desc_sym"] or "", "status": "", "blocker": "",
            "exp": "", "primary": "", "aliases": [], "proposed": "",
            "hosts": [], "prefix": "", "contradiction": None, "notes": [],
            "names_exp": [],
        }
        recs.append(rec)

        if not r["fns"]:
            rec["status"] = "no-text-fns"
            rec["blocker"] = "no .text fns (descriptor data only)"
            if not rec["names"]:
                rec["exp"] = "NO-RETAIL-NAME"
            else:
                exp, st = expand_def(rec["names"][0], [], symidx, fileidx)
                rec["primary"], rec["exp"] = exp, st
                rec["aliases"] = rec["names"][1:]
            continue

        host_count = Counter(unit_for(v) or "(unclaimed)" for _, v in r["fns"])
        hosts = [u for u, _ in host_count.most_common()]
        rec["hosts"] = hosts

        # naming evidence: own descriptor fns (weight 3) + TU-span symbols
        own = [sym_at.get(v) for _, v in r["fns"]]
        ts = tu_start(r)
        lo_i = bisect.bisect_left(txt_addrs, ts)
        hi_i = bisect.bisect_left(txt_addrs, fn_end(r["hi"]))
        span = [sym_at[a] for a in txt_addrs[lo_i:hi_i]]
        votes = Counter()
        rep = {}
        for plist, w in ((sym_prefix_votes(own), 3), (sym_prefix_votes(span), 1)):
            for p, c in plist:
                votes[norm(p)] += c * w
                rep.setdefault(norm(p), p)
        dom = rep[votes.most_common(1)[0][0]] if votes else ""
        rec["prefix"] = dom

        m = re.match(r"^g(.+?)(Obj)?Descriptor\d*$", rec["desc_sym"])
        desc_inner = m.group(1) if m else ""

        co_pre = sorted(set().union(*(unit_dlls[u] for u in hosts
                                      if u in unit_dlls)) - {r["dll_id"]})
        if rec["names"]:
            name_src, st, primary = pick_name(rec["names"], dom, desc_inner,
                                              symidx, fileidx)
            rec["primary"], rec["exp"] = name_src, st
            rec["aliases"] = [n for n in rec["names"] if n != primary]
            rec["names_exp"] = [expand_def(n, [dom, desc_inner] if dom else
                                           [desc_inner], symidx, fileidx)[0]
                                for n in rec["names"]]
            lcname = norm(name_src)
        else:
            rec["exp"] = "NO-RETAIL-NAME"
            stem = current_stem(hosts[0])
            shared = bool(co_pre) or len(hosts) > 1
            dom_ok = dom and votes.most_common(1)[0][1] >= 2
            if (not stem or shared) and dom_ok:
                rec["primary"] = dom
                lcname = norm(dom)
                rec["notes"].append("stem from fn prefix `%s_*`" % dom)
            else:
                rec["primary"] = stem
                lcname = stem
                if stem and shared:
                    rec["notes"].append("container stem, tentative")

        # proposed path
        cur = hosts[0]
        cur_dir = os.path.dirname(cur)
        lane = None
        mlane = re.match(r"^main/dll/([^/]+)$", cur_dir)
        if len(hosts) == 1 and mlane and mlane.group(1) in lane_dirs:
            lane = mlane.group(1)
        elif rec["primary"]:
            for pfx, ld in LANE_PREFIXES:
                if rec["primary"].startswith(pfx):
                    lane = ld
                    break
        base = ("dll_%04X_%s.c" % (r["dll_id"], lcname)) if lcname \
            else ("dll_%04X.c" % r["dll_id"])
        rec["proposed"] = "main/dll/%s/%s" % (lane, base) if lane else \
            "main/dll/%s" % base

        # state
        co = co_pre
        mid = re.match(r".*/dll_([0-9A-Fa-f]{2,4})(?:_|\.c)", cur)
        if mid and int(mid.group(1), 16) != r["dll_id"]:
            rec["notes"].append("current file id 0x%03X != descriptor id 0x%03X"
                                % (int(mid.group(1), 16), r["dll_id"]))
        if len(hosts) > 1:
            rec["status"] = "blocked-on-cut"
            rec["blocker"] = "cut across: " + " | ".join(hosts)
        elif not cur.startswith("main/dll/") and not re.match(
                r"^main/dll", cur):
            rec["status"] = "blocked-on-extraction"
            rec["blocker"] = "engine/SDK host: %s" % cur
        elif co:
            rec["status"] = "blocked-on-carve"
            ids = ["0x%03X" % d for d in co]
            if len(ids) > 6:
                ids = ids[:6] + ["+%d more" % (len(co) - 6)]
            rec["blocker"] = "container w/ " + ",".join(ids)
        else:
            cb = os.path.basename(cur)
            pb = os.path.basename(rec["proposed"])
            if cb == pb and cur == rec["proposed"]:
                rec["status"] = "already-canonical"
            elif norm(cb[:-2]) == norm(pb[:-2]) and \
                    os.path.dirname(cur) == os.path.dirname(rec["proposed"]):
                rec["status"] = "canonical-variant"
                rec["notes"].append("case/punct variant of canonical")
            else:
                rec["status"] = "rename-ready"

    resolve_conflicts(recs)
    classify_contradictions(recs)
    return recs, rows, units, unit_for, fn_end, sym_at, unit_dlls


def classify_contradictions(recs):
    """fn-symbol prefix vs retail names. cross-dll = the prefix names ANOTHER
    dll's retail object (strong evidence of a mislabel); unrelated = matches
    nothing (mislabel OR a deliberate descriptive family name — human call)."""
    import difflib
    name_index = []
    for rec in recs:
        for n in rec.get("names_exp", []):
            name_index.append((norm(n), rec["dll"]))
    for rec in recs:
        rec["contradiction"] = None
        dom = rec["prefix"]
        if not rec["names"] or not dom:
            continue
        ne = norm(dom)
        own = [norm(n) for n in rec.get("names_exp", [])]
        if any(ne.startswith(o) or o.startswith(ne) or
               (len(ne) >= 4 and ne in o) for o in own):
            continue
        best = 0
        for o in own:
            m = difflib.SequenceMatcher(None, ne, o).find_longest_match(
                0, len(ne), 0, len(o))
            best = max(best, m.size)
        others = sorted(set(d for nn, d in name_index
                            if d != rec["dll"] and len(ne) >= 5 and
                            (nn.startswith(ne) or ne.startswith(nn))))
        if others:
            rec["contradiction"] = ("cross-dll", dom, others)
        elif best < 4:
            rec["contradiction"] = ("unrelated", dom, [])


def pick_name(defs, dom, desc_inner, symidx, fileidx):
    """-> (name_for_filename, expansion_status, primary_def)."""
    evs = [e for e in (dom, desc_inner) if e]
    for ev in evs:
        ne = norm(ev)
        exps = {d: expand_def(d, [ev], symidx, fileidx)[0] for d in defs}
        hit = [d for d in defs if norm(exps[d]) == ne]
        if hit:
            d = max(hit, key=lambda d: len(norm(d)))
            return exps[d], ("COMPLETE" if len(d) < NAME_FIELD
                             else "CONFIRMED"), d
        sub = [d for d in defs if len(ne) >= 4 and ne in norm(exps[d])]
        if len(sub) >= 2:
            return cased_stem(exps[sub[0]], ne), "CONFIRMED", sub[0]
        if len(sub) == 1:
            return exps[sub[0]], "CONFIRMED", sub[0]
    if len(defs) == 1:
        exp, st = expand_def(defs[0], evs, symidx, fileidx)
        return exp, st, defs[0]
    # multi-def, no direct evidence: common-prefix family stem
    ns = [norm(d) for d in defs]
    cp = os.path.commonprefix(ns)
    cp = re.sub(r"[0-9]+$", "", cp)
    if dom and len(cp) >= 4 and norm(dom).startswith(cp):
        return dom, "CONFIRMED", defs[0]  # fn prefix extends the family stem
    if len(cp) >= 4:
        return cased_stem(defs[0], cp), "GUESSED", defs[0]
    if len(defs) > 1 and dom:
        # heterogeneous def family, no retail stem: the fn prefix is the
        # only family name available (precedent: wctemple, shopitem)
        return dom, "GUESSED", defs[0]
    exp, st = expand_def(defs[0], evs, symidx, fileidx)
    if st == "COMPLETE":
        st = "GUESSED"  # arbitrary pick among unrelated defs
    return exp, st, defs[0]


def current_stem(host):
    base = os.path.basename(host)
    stem = base[:-2] if base.endswith(".c") else base
    return re.sub(r"^dll_[0-9A-Fa-f]{2,4}_?", "", stem)


def resolve_conflicts(recs):
    """two dlls proposing the same <name> part: disambiguate via primary def."""
    def namepart(rec):
        m = re.match(r"dll_[0-9A-F]{4}_(.+)\.c$", os.path.basename(rec["proposed"]))
        return m.group(1) if m else ""

    groups = defaultdict(list)
    for rec in recs:
        if not rec["names"]:
            continue  # keep-current-stem proposals share stems by design
        np = namepart(rec)
        if np:
            groups[np].append(rec)
    for np, g in groups.items():
        if len(g) < 2:
            continue
        for rec in g:
            full = norm(rec["primary"]) if rec["primary"] else ""
            if full and full != np:
                rec["proposed"] = rec["proposed"].replace(
                    "_%s.c" % np, "_%s.c" % full)
                rec["notes"].append("name-conflict on '%s' -> used full def name" % np)
            else:
                note = "name-conflict on '%s' with dll(s) %s" % (
                    np, ",".join("0x%03X" % o["dll"] for o in g if o is not rec))
                if rec["prefix"]:
                    note += " — fn prefix `%s_*` may disambiguate" % rec["prefix"]
                rec["notes"].append(note)


def id_mismatches(unit_dlls):
    out = []
    for u, dset in sorted(unit_dlls.items()):
        m = re.match(r".*/dll_([0-9A-Fa-f]{2,4})(?:_|\.c)", u)
        if m and int(m.group(1), 16) not in dset:
            out.append((u, int(m.group(1), 16), sorted(dset)))
    return out


def headers_gate(recs):
    """same-stem include/ headers that must move with a renamed unit.
    -> (moves for rename-ready/variant dlls, global count over all hosts)."""
    hdrs = defaultdict(list)
    for root, dirs, files in os.walk(os.path.join(REPO, "include")):
        for f in files:
            if f.endswith(".h"):
                hdrs[f[:-2].lower()].append(
                    os.path.relpath(os.path.join(root, f), REPO))
    out = []
    seen = set()
    for rec in recs:
        if not rec["hosts"]:
            continue
        for u in rec["hosts"]:
            stem = os.path.basename(u)[:-2].lower()
            for h in hdrs.get(stem, []):
                seen.add((u, h))
                if rec["status"] in ("rename-ready", "canonical-variant") \
                        and u == rec["hosts"][0]:
                    out.append((rec["dll"], u, h))
    return out, len(seen)


def summarize(recs):
    c = Counter(rec["status"] for rec in recs)
    named = [r for r in recs if r["names"]]
    nodef = [r for r in recs if not r["names"]]
    conf = Counter(r["exp"] for r in named)
    conflicts = [r for r in recs if any("name-conflict" in n for n in r["notes"])]
    contras = [r for r in recs if r["contradiction"]]
    return c, named, nodef, conf, conflicts, contras


def emit_md(recs, unit_dlls, hdr_moves, hdr_global, out):
    c, named, nodef, conf, conflicts, contras = summarize(recs)
    w = out.write
    w("# DLL canonical-naming manifest\n\n")
    w("Authoritative dll-id -> canonical-filename mapping for the rename\n")
    w("campaign. Generated by `python3 tools/dll_canonical_names.py --regen`\n")
    w("(re-run after each boundary-surgery wave; READ-ONLY analysis — no\n")
    w("rename is executed by the tool).\n\n")
    w("Retail names come from OBJECTS.bin defs (name at def+0x91, 11-char\n")
    w("fixed field; handling dll id at def+0x50). Expansion status:\n")
    w("**COMPLETE** = name shorter than the 11-char field (cannot be\n")
    w("truncated); **CONFIRMED** = expansion/stem backed by symbols.txt\n")
    w("fn-name prefixes or descriptor symbol names; **GUESSED** = backed only\n")
    w("by an existing filename or a multi-def common stem; **RAW** = 11-char\n")
    w("name kept truncated, no evidence found.\n\n")
    w("Lane-dir rule: a unit already inside a `main/dll/<LANE>/` dir keeps\n")
    w("that dir (address-lane ownership beats name prefix — precedent:\n")
    w("`DR/dll_0149_cfwindlift.c`); otherwise the dir derives from the name\n")
    w("prefix (`WM_`->WM/ etc; `CC`/`SB` dirs do not exist yet —\n")
    w("create-listed, do not create until the first rename lands); names\n")
    w("with no lane prefix stay at `main/dll/` root.\n\n")

    w("## Summary\n\n")
    w("| metric | count |\n|---|---|\n")
    w("| descriptors (non-null) | %d |\n" % len(recs))
    w("| with retail def name(s) | %d |\n" % len(named))
    w("| no retail name (infrastructure) | %d |\n" % len(nodef))
    w("| already-canonical | %d |\n" % c.get("already-canonical", 0))
    w("| canonical-variant (case/punct only) | %d |\n" % c.get("canonical-variant", 0))
    w("| clean-rename-ready | %d |\n" % c.get("rename-ready", 0))
    w("| blocked-on-carve (multi-dll container) | %d |\n" % c.get("blocked-on-carve", 0))
    w("| blocked-on-cut (boundary splits the dll) | %d |\n" % c.get("blocked-on-cut", 0))
    w("| blocked-on-extraction (engine/SDK host) | %d |\n" % c.get("blocked-on-extraction", 0))
    w("| no-text-fns (data-only descriptor) | %d |\n" % c.get("no-text-fns", 0))
    w("| name-conflicts (disambiguated) | %d |\n" % len(conflicts))
    w("| naming contradictions (appendix) | %d |\n" % len(contras))
    w("| same-stem headers gating ready renames | %d |\n" % len(hdr_moves))
    w("| same-stem headers across all dll hosts | %d |\n" % hdr_global)
    w("\nExpansion status over the %d named dlls: " % len(named))
    w(", ".join("%s %d" % (k, v) for k, v in sorted(conf.items())) + "\n\n")

    w("## Manifest\n\n")
    w("| dll | retail name(s) | expansion | current file | proposed file | blocker |\n")
    w("|---|---|---|---|---|---|\n")
    for rec in recs:
        if rec["names"]:
            disp = rec["primary"]
            al = [a for a in dedup(rec["names"])
                  if not norm(rec["primary"]).startswith(norm(a))]
            if al:
                disp += " (+" + ", ".join(al) + ")"
        else:
            disp = "—"
        cur = " \\| ".join(rec["hosts"]) if rec["hosts"] else "*(none)*"
        prop = rec["proposed"] if rec["proposed"] else "—"
        if rec["status"] in ("already-canonical",):
            prop = "= (canonical)"
        blocker = "; ".join([p for p in [rec["blocker"]] + rec["notes"] if p]) \
            or "—"
        w("| 0x%03X | %s | %s | %s | %s | %s |\n" % (
            rec["dll"], disp.replace("|", "\\|"), rec["exp"], cur,
            prop.replace("|", "\\|"), blocker.replace("|", "\\|")))

    w("\n## Name-conflict resolutions\n\n")
    if conflicts:
        for rec in conflicts:
            w("- 0x%03X: %s\n" % (rec["dll"],
                                  "; ".join(n for n in rec["notes"]
                                            if "name-conflict" in n)))
    else:
        w("(none)\n")

    w("\n## Appendix: naming contradictions\n\n")
    w("Dlls whose hosted fn symbols carry a prefix matching NONE of the\n")
    w("dll's retail def names (evidence only — symbol naming vs retail truth\n")
    w("needs human arbitration before any rename). `cross-dll` = the prefix\n")
    w("matches ANOTHER dll's retail name (strong mislabel evidence);\n")
    w("`unrelated` = matches nothing — a mislabel OR a deliberate\n")
    w("descriptive family name (e.g. `collectible`, `softbody`).\n\n")
    if contras:
        w("| dll | retail name(s) | dominant fn prefix | class | host |\n")
        w("|---|---|---|---|---|\n")
        for rec in sorted(contras, key=lambda r: (r["contradiction"][0], r["dll"])):
            kind, dom, others = rec["contradiction"]
            cl = kind
            if others:
                cl += " (names dll %s)" % ",".join("0x%03X" % d for d in others)
            w("| 0x%03X | %s | `%s_*` | %s | %s |\n" % (
                rec["dll"], ", ".join(dedup(rec["names"])), dom, cl,
                rec["hosts"][0] if rec["hosts"] else "?"))
    else:
        w("(none)\n")

    w("\n## Appendix: canonical-format files whose proposal differs\n\n")
    w("Units already in `dll_XXXX_<name>.c` form where the evidence proposes\n")
    w("a DIFFERENT name/id (truncation expansions, id mislabels, stem-vs-def\n")
    w("choices). These need owner sign-off before renaming — the current\n")
    w("name was a deliberate choice by a previous carve:\n\n")
    rr = [rec for rec in recs
          if rec["status"] == "rename-ready" and rec["hosts"] and
          re.match(r"dll_[0-9A-Fa-f]{4}_", os.path.basename(rec["hosts"][0]))]
    if rr:
        w("| dll | current | proposed | expansion |\n|---|---|---|---|\n")
        for rec in rr:
            w("| 0x%03X | %s | %s | %s |\n" % (
                rec["dll"], rec["hosts"][0], rec["proposed"], rec["exp"]))
    else:
        w("(none)\n")

    w("\n## Appendix: current `dll_XXXX` files whose id != descriptor id\n\n")
    w("The number embedded in the filename does not match the\n")
    w("gResourceDescriptors index of any dll the unit hosts (drift-era or\n")
    w("mislabeled files — the rename campaign must renumber these):\n\n")
    mm = id_mismatches(unit_dlls)
    if mm:
        w("| unit | file id | actually hosts |\n|---|---|---|\n")
        for u, fid, dset in mm:
            w("| %s | 0x%03X | %s |\n" % (
                u, fid, ", ".join("0x%03X" % d for d in dset)))
    else:
        w("(none)\n")

    w("\n## Appendix: same-stem headers that must move with a rename\n\n")
    w("`include/` headers named after a unit's current stem; a rename of the\n")
    w(".c must move/rename the header (and every `#include` of it) in the\n")
    w("same commit. Counted for rename-ready/canonical-variant dlls only —\n")
    w("blocked units will surface more when carved.\n\n")
    if hdr_moves:
        w("| dll | current unit | header |\n|---|---|---|\n")
        for did, u, h in hdr_moves:
            w("| 0x%03X | %s | %s |\n" % (did, u, h))
    else:
        w("(none)\n")


def main():
    recs, rows, units, unit_for, fn_end, sym_at, unit_dlls = analyze()
    hdr_moves, hdr_global = headers_gate(recs)
    if "--regen" in sys.argv:
        with open(MANIFEST, "w") as f:
            emit_md(recs, unit_dlls, hdr_moves, hdr_global, f)
        print("wrote %s" % os.path.relpath(MANIFEST, REPO))
    elif "--print" in sys.argv:
        emit_md(recs, unit_dlls, hdr_moves, hdr_global, sys.stdout)
        return
    c, named, nodef, conf, conflicts, contras = summarize(recs)
    print("descriptors: %d  named: %d  no-def: %d" % (len(recs), len(named), len(nodef)))
    for k in ("already-canonical", "canonical-variant", "rename-ready",
              "blocked-on-carve", "blocked-on-cut", "blocked-on-extraction",
              "no-text-fns"):
        print("  %-24s %d" % (k, c.get(k, 0)))
    print("  expansion (named): %s" % ", ".join(
        "%s=%d" % (k, v) for k, v in sorted(conf.items())))
    print("  name-conflicts: %d  contradictions: %d  header-moves: %d" % (
        len(conflicts), len(contras), len(hdr_moves)))


if __name__ == "__main__":
    main()
