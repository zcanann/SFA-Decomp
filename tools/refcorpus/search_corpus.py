#!/usr/bin/env python3
r"""Search the GC/2.0 reference-asm corpus built by build_corpus.py.

Answers the SFA playbook question "what C produces this asm shape, under our compiler?"
by searching real, SFA-adjacent reference C recompiled with MWCC GC/2.0.

    # find an asm shape (regex over normalized instructions), show the C that emits it
    python3 tools/refcorpus/search_corpus.py --asm 'rlwinm[^.].*0x7f' --show-c
    # find an instruction sequence in order (mnemonics, gaps allowed)
    python3 tools/refcorpus/search_corpus.py --seq 'extsb. rlwimi'
    # go the other way: grep the reference C, show the asm GC/2.0 gave it
    python3 tools/refcorpus/search_corpus.py --csrc 'for *\(.*u8 ' --profile both_on
    # scope / limit
    python3 tools/refcorpus/search_corpus.py --asm 'psq_l' --project dkr --limit 20
    python3 tools/refcorpus/search_corpus.py --stats

Profiles: both_off (SFA default), peep_on, sched_on, both_on, or 'all'. Default: both_off.
"""

from __future__ import annotations

import argparse
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
        for j in range(i, min(len(lines), i + 400)):
            buf.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in "\n".join(buf) and depth <= 0:
                return "\n".join(buf)
    return None


# --- search modes -------------------------------------------------------------

def _seq_to_regex(seq: str) -> str:
    mnems = [m for m in re.split(r"[\s,;]+", seq.strip()) if m]
    # each mnemonic at a line start, in order, gaps allowed
    return r"[\s\S]*?".join(r"(?m)^" + re.escape(m).replace(r"\.", r"\.") + r"\b"
                            if k == 0 else r"^" + re.escape(m) + r"\b"
                            for k, m in enumerate(mnems))


def search_asm(funcs: List[Func], pattern: str, flags: int) -> List[tuple]:
    rx = re.compile(pattern, flags)
    hits = []
    for f in funcs:
        m = rx.search(f.text)
        if m:
            hits.append((f, m.start(), m.end()))
    return hits


def print_asm_hit(f: Func, start: int, end: int, context: int, show_c: bool):
    # translate char offsets to line indices
    pre = f.text.count("\n", 0, start)
    post = f.text.count("\n", 0, end)
    lo, hi = max(0, pre - context), min(len(f.insns), post + context + 1)
    print(f"\n\033[1m{f.project}/{f.profile}\033[0m  {f.src} :: \033[36m{f.sym}\033[0m")
    for k in range(lo, hi):
        mark = ">" if pre <= k <= post else " "
        print(f"    {mark} {f.insns[k]}")
    if show_c:
        c = extract_c_function(f.src, f.sym)
        if c:
            print("    --- C ---")
            for cl in c.splitlines():
                print(f"      {cl}")


def do_csrc(pattern: str, projects, profile: str, limit: int, context: int):
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
    by_key = {(f.project, f.sym): f for f in funcs}
    shown = 0
    for proj, src in srcs:
        try:
            lines = (R.REPO_ROOT / src).read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            if not rx.search(ln):
                continue
            sym = _enclosing_c_symbol(lines, i)
            print(f"\n\033[1m{proj}\033[0m  {src}:{i+1}  \033[36m{sym or '?'}\033[0m")
            for k in range(max(0, i - context), min(len(lines), i + context + 1)):
                mark = ">" if k == i else " "
                print(f"    {mark} {lines[k]}")
            f = by_key.get((proj, sym)) if sym else None
            if f:
                print(f"    --- asm ({profile}) ---")
                for insn in f.insns[:40]:
                    print(f"      {insn}")
                if len(f.insns) > 40:
                    print(f"      ... (+{len(f.insns)-40} insns)")
            shown += 1
            if shown >= limit:
                return


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
    mode.add_argument("--csrc", help="regex over reference C source; shows resulting asm")
    mode.add_argument("--stats", action="store_true", help="corpus size summary")
    ap.add_argument("--project", help="comma list to restrict (dkr,jfg,mp4)")
    ap.add_argument("--profile", default="both_off",
                    help="both_off|peep_on|sched_on|both_on|all (default both_off)")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--show-c", action="store_true", help="also print the C function")
    ap.add_argument("-i", "--ignore-case", action="store_true")
    args = ap.parse_args()

    projects = args.project.split(",") if args.project else None
    profiles = [args.profile]

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
        do_csrc(args.csrc, projects, args.profile if args.profile != "all" else "both_off",
                args.limit, args.context)
        return

    if not (args.asm or args.seq):
        ap.error("one of --asm / --seq / --csrc / --stats is required")

    flags = re.IGNORECASE if args.ignore_case else 0
    pattern = args.asm if args.asm else _seq_to_regex(args.seq)
    if args.seq:
        flags |= re.MULTILINE
    funcs = load(projects, profiles)
    hits = search_asm(funcs, pattern, flags)
    print(f"[{len(hits)} hit(s) over {len(funcs)} funcs; profile(s): {args.profile}]")
    for f, s, e in hits[:args.limit]:
        print_asm_hit(f, s, e, args.context, args.show_c)
    if len(hits) > args.limit:
        print(f"\n... +{len(hits)-args.limit} more (raise --limit)")


if __name__ == "__main__":
    main()
