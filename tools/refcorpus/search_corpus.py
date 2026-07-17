#!/usr/bin/env python3
r"""Search the GC/2.0 reference-asm corpus built by build_corpus.py.

Answers the SFA playbook question "what C produces this asm shape, under our compiler?"
by searching real, SFA-adjacent reference C recompiled with MWCC GC/2.0.

    # find compact, size-ranked function candidates for an asm shape
    python3 tools/refcorpus/search_corpus.py --asm 'rlwinm[^.].*0x7f'
    # find an instruction sequence in order (mnemonics, gaps allowed)
    python3 tools/refcorpus/search_corpus.py --seq 'extsb. rlwimi'
    # inspect the complete assembly and C only after selecting a result
    python3 tools/refcorpus/search_corpus.py --show rc_0123456789ab
    # go the other way: find compiled functions containing matching reference C
    python3 tools/refcorpus/search_corpus.py --csrc 'for *\(.*u8 ' --profile both_on
    # scope / limit
    python3 tools/refcorpus/search_corpus.py --asm 'psq_l' --project dkr --limit 20
    python3 tools/refcorpus/search_corpus.py --stats

Profiles: both_off (SFA default), peep_on, sched_on, both_on, or 'all'. Default: both_off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recipes as R  # noqa: E402

MANIFEST = R.REPO_ROOT / R.OUT_ROOT / "manifest.json"
FUNC_LABEL_RE = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:")
RELOC_RE = re.compile(r"R_PPC\S*\s+(\S+)")


@dataclass
class Func:
    project: str
    profile: str
    src: str          # repo-relative C source
    sym: str          # symbol == C function name (MWCC doesn't mangle C)
    insns: List[str]  # normalized "mnemonic operands" lines
    text: str         # "\n".join(insns), for regex search

    @property
    def result_id(self) -> str:
        identity = "\0".join((self.project, self.profile, self.src, self.sym))
        digest = hashlib.blake2s(identity.encode(), digest_size=6).hexdigest()
        return f"rc_{digest}"


def _normalize_insn(line: str) -> Optional[str]:
    """objdump -drz line -> 'mnemonic operands', or None if not an instruction."""
    parts = line.split("\t")
    if len(parts) >= 3 and re.match(r"^\s*[0-9a-fA-F]+:\s*$", parts[0]):
        insn = re.sub(r"\s+", " ", parts[2].strip())
        return insn or None
    return None


def _reloc_target(line: str) -> Optional[str]:
    m = RELOC_RE.search(line)
    return m.group(1) if m else None


def _parse_s(path: Path, project: str, profile: str, src: str) -> List[Func]:
    funcs: List[Func] = []
    cur_sym: Optional[str] = None
    cur: List[str] = []
    for line in path.read_text(errors="ignore").splitlines():
        lab = FUNC_LABEL_RE.match(line)
        if lab:
            if cur_sym is not None:
                funcs.append(Func(project, profile, src, cur_sym, cur, "\n".join(cur)))
            cur_sym, cur = lab.group(1), []
            continue
        if cur_sym is None:
            continue
        insn = _normalize_insn(line)
        if insn is not None:
            cur.append(insn)
        else:
            tgt = _reloc_target(line)
            if tgt and cur:
                cur[-1] += f"  <{tgt}>"
    if cur_sym is not None:
        funcs.append(Func(project, profile, src, cur_sym, cur, "\n".join(cur)))
    return funcs


def load(projects: Optional[List[str]], profiles: List[str]) -> List[Func]:
    if not MANIFEST.exists():
        raise SystemExit("no corpus; run: python3 tools/refcorpus/build_corpus.py")
    manifest = json.loads(MANIFEST.read_text())
    out: List[Func] = []
    for e in manifest:
        if not e["ok"]:
            continue
        if projects and e["rec"] not in projects:
            continue
        if profiles != ["all"] and e["profile"] not in profiles:
            continue
        out.extend(_parse_s(R.REPO_ROOT / e["out_s"], e["rec"], e["profile"], e["src"]))
    return out


# --- C-source extraction (best-effort; MWCC C symbols == source names) --------

def extract_c_function(src: str, sym: str) -> Optional[str]:
    try:
        lines = (R.REPO_ROOT / src).read_text(errors="ignore").splitlines()
    except OSError:
        return None
    defn = re.compile(r"(^|[^\w])" + re.escape(sym) + r"\s*\(")
    for i, ln in enumerate(lines):
        if not defn.search(ln) or ln.strip().startswith(("//", "*", "/*")):
            continue
        # definition vs prototype/call: after the name, does '{' come before ';'?
        window = "\n".join(lines[i:i + 60])
        brace = window.find("{")
        semi = window.find(";")
        if brace == -1 or (semi != -1 and semi < brace):
            continue  # prototype or call site
        # capture from line i until the body braces balance
        depth = 0
        buf: List[str] = []
        for j in range(i, len(lines)):
            buf.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in "\n".join(buf) and depth <= 0:
                return "\n".join(buf)
    return None


# --- search modes -------------------------------------------------------------

def _seq_mnemonics(seq: str) -> List[str]:
    return [m for m in re.split(r"[\s,;]+", seq.strip()) if m]


def _search_seq_func(f: Func, mnems: List[str], flags: int) -> Optional[tuple]:
    """Earliest in-order match of mnemonics (gaps allowed) over f.insns.

    Linear in len(insns): each instruction advances the sequence at most one step.
    A regex of lazy '[\\s\\S]*?'-joined anchors backtracks exponentially instead.
    """
    rxs = [re.compile(r"^" + re.escape(m) + r"\b", flags) for m in mnems]
    k = 0
    first: Optional[int] = None
    for i, insn in enumerate(f.insns):
        if rxs[k].match(insn):
            if k == 0:
                first = i
            k += 1
            if k == len(rxs):
                return (first, i)
    return None


def _line_span_to_chars(f: Func, lo: int, hi: int) -> tuple:
    start = sum(len(f.insns[j]) + 1 for j in range(lo))
    end = start + sum(len(f.insns[j]) + 1 for j in range(lo, hi + 1)) - 1
    return start, max(start, end)


def search_seq(funcs: List[Func], seq: str, flags: int) -> List[tuple]:
    mnems = _seq_mnemonics(seq)
    hits = []
    for f in funcs:
        span = _search_seq_func(f, mnems, flags)
        if span:
            s, e = _line_span_to_chars(f, span[0], span[1])
            hits.append((f, s, e))
    return hits


def search_asm(funcs: List[Func], pattern: str, flags: int) -> List[tuple]:
    rx = re.compile(pattern, flags)
    hits = []
    for f in funcs:
        m = rx.search(f.text)
        if m:
            hits.append((f, m.start(), m.end()))
    return hits


def _match_instruction_span(f: Func, start: int, end: int) -> int:
    pre = f.text.count("\n", 0, start)
    post = f.text.count("\n", 0, end)
    return max(1, post - pre + 1)


def _hit_sort_key(hit: tuple) -> tuple:
    f, start, end = hit
    return (
        len(f.insns),
        _match_instruction_span(f, start, end),
        f.project,
        f.src,
        f.sym,
        f.profile,
    )


def print_discovery(hits: List[tuple], total: int, profile: str, limit: int) -> None:
    ordered = sorted(hits, key=_hit_sort_key)
    print(f"[{len(ordered)} hit(s) over {total} funcs; profile(s): {profile}; smallest first]")
    print("ID              INSNS  MATCH  PROJECT/PROFILE       FUNCTION  SOURCE")
    for f, start, end in ordered[:limit]:
        span = _match_instruction_span(f, start, end)
        project_profile = f"{f.project}/{f.profile}"
        print(
            f"{f.result_id:15s} {len(f.insns):6d} {span:6d}  "
            f"{project_profile:21s} {f.sym}  {f.src}"
        )
    if len(ordered) > limit:
        print(f"... +{len(ordered)-limit} more (raise --limit)")
    if ordered:
        print("\nInspect one result with: python3 tools/refcorpus/search_corpus.py --show ID")


def show_function(result_id: str) -> None:
    matches = [f for f in load(None, ["all"]) if f.result_id == result_id]
    if not matches:
        raise SystemExit(f"unknown corpus result ID: {result_id}")
    if len(matches) > 1:
        raise SystemExit(f"ambiguous corpus result ID: {result_id}")
    f = matches[0]
    print(f"{f.result_id}  {f.project}/{f.profile}  {f.src} :: {f.sym}")
    print(f"instructions: {len(f.insns)}")
    print("\n--- assembly ---")
    for insn in f.insns:
        print(insn)
    print("\n--- C ---")
    source = extract_c_function(f.src, f.sym)
    if source is None:
        print("[C definition unavailable]")
    else:
        print(source)


def search_csrc(pattern: str, projects, profile: str) -> tuple[List[tuple], int]:
    manifest = json.loads(MANIFEST.read_text())
    srcs = []
    seen = set()
    for e in manifest:
        if e["ok"] and (not projects or e["rec"] in projects) and e["src"] not in seen:
            seen.add(e["src"])
            srcs.append((e["rec"], e["src"]))
    rx = re.compile(pattern)
    # index funcs for the chosen display profile for asm lookup
    funcs = load(projects, [profile])
    by_key = {(f.project, f.src, f.sym): f for f in funcs}
    hits = []
    seen_hits = set()
    for proj, src in srcs:
        try:
            lines = (R.REPO_ROOT / src).read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            if not rx.search(ln):
                continue
            sym = _enclosing_c_symbol(lines, i)
            f = by_key.get((proj, src, sym)) if sym else None
            if f and f.result_id not in seen_hits:
                hits.append((f, 0, 0))
                seen_hits.add(f.result_id)
    return hits, len(funcs)


_C_DEF_RE = re.compile(r"^\w[\w\s\*]*\s\**(\w+)\s*\(")


def _enclosing_c_symbol(lines: List[str], idx: int) -> Optional[str]:
    depth = 0
    for i in range(idx, -1, -1):
        depth += lines[i].count("}") - lines[i].count("{")
        m = _C_DEF_RE.match(lines[i])
        if m and depth <= 0 and not lines[i].rstrip().endswith(";"):
            return m.group(1)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--asm", help="regex over normalized 'mnemonic operands' text")
    mode.add_argument("--seq", help="mnemonics in order, gaps allowed, e.g. 'extsb. rlwimi'")
    mode.add_argument("--csrc", help="regex over reference C source; lists compiled functions")
    mode.add_argument("--show", metavar="ID", help="show complete assembly and C for one result ID")
    mode.add_argument("--stats", action="store_true", help="corpus size summary")
    ap.add_argument("--project", help="comma list to restrict (" + ",".join(R.RECIPES) + ")")
    ap.add_argument("--profile", default="both_off",
                    help="both_off|peep_on|sched_on|both_on|all (default both_off)")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--context", type=int, default=3, help=argparse.SUPPRESS)
    ap.add_argument("--show-c", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("-i", "--ignore-case", action="store_true")
    args = ap.parse_args()

    projects = args.project.split(",") if args.project else None
    profiles = [args.profile]

    if args.show:
        show_function(args.show)
        return

    if args.stats:
        funcs = load(projects, ["all"])
        from collections import Counter
        c = Counter((f.project, f.profile) for f in funcs)
        srcs = len({(f.project, f.src) for f in funcs})
        print(f"corpus: {len(funcs)} function-asm samples, {srcs} source files")
        for (proj, prof), n in sorted(c.items()):
            print(f"  {proj:5s} {prof:9s} {n:6d} funcs")
        return

    if args.csrc:
        display_profile = args.profile if args.profile != "all" else "both_off"
        hits, total = search_csrc(args.csrc, projects, display_profile)
        print_discovery(hits, total, display_profile, args.limit)
        return

    if not (args.asm or args.seq):
        ap.error("one of --asm / --seq / --csrc / --stats is required")

    flags = re.IGNORECASE if args.ignore_case else 0
    funcs = load(projects, profiles)
    if args.seq:
        hits = search_seq(funcs, args.seq, flags)
    else:
        hits = search_asm(funcs, args.asm, flags)
    if args.show_c:
        print("note: --show-c is deprecated; use --show ID after discovery", file=sys.stderr)
    print_discovery(hits, len(funcs), args.profile, args.limit)


if __name__ == "__main__":
    main()
