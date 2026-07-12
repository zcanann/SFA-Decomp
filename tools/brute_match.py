#!/usr/bin/env python3
"""Brute-force a function's register allocation by permuting its local
declaration ORDER (the #1 source-controllable coloring lever: decl order sets
saved-register homes, per CLAUDE.md) and rebuilding + measuring each variant.

For each candidate ordering it:
  1. rewrites the leading declaration block of the target function,
  2. rebuilds ONLY that unit's src .o (locked_ninja),
  3. measures the function's instruction-match against the retail target .o
     (objdump both, normalize branch labels, SequenceMatcher ratio),
and tracks the best. At the end it applies the best variant if it beats the
baseline, otherwise restores the original file byte-for-byte.

The inner metric is a proxy (exact normalized-instruction match ratio, which is
sensitive to reg-perm diffs); confirm the true objdiff fuzzy% with a report.json
regen afterwards.

Usage:
  python3 tools/brute_match.py <unit> <symbol> [-v GSAE01]
      [--max-variants N] [--time-budget SECONDS] [--strategy swaps|moves|all]
      [--dry-run] [--apply-best]

  --dry-run       parse + print the decl block and the variants it WOULD try,
                  build nothing.
  --apply-best    write the best-scoring variant even if the tool is re-run
                  (default: applies best iff strictly better than baseline).

Notes:
  * SJIS-safe: the file is read/written as latin-1 (byte-transparent).
  * Only the leading declaration block is reordered; each item keeps its exact
    source text (multi-line union/struct decls are moved as one unit).
"""
from __future__ import annotations

import argparse
import itertools
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import (
    load_units,
    resolve_unit,
    objdump_symbol,
    strip_preamble,
)
from ndiff import normalize
import difflib

REPO = Path(__file__).resolve().parent.parent

TYPE_TOKENS = {
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
    "int", "uint", "char", "short", "long", "float", "double",
    "void", "f32", "f64", "f80", "bool", "BOOL", "u128",
    "unsigned", "signed", "const", "static", "volatile", "register",
    "struct", "union", "enum", "undefined4", "undefined2", "undefined1",
    "undefined", "size_t", "vec3", "Vec", "Vec3f", "Mtx", "GXColor",
}


# ------------------------------------------------------------------ scoring
def objdump_paths(unit: dict, version: str):
    tgt = REPO / unit["object"]
    cur = REPO / unit["object"].replace(f"build/{version}/obj/",
                                        f"build/{version}/src/")
    return tgt, cur


def objdump_norm(objdump: Path, obj: Path, symbol: str):
    return normalize(strip_preamble(objdump_symbol(objdump, obj, symbol)))


def match_score(t: list[str], c: list[str]):
    """(pct, regions): exact-normalized-instruction match ratio and #regions."""
    if not t or not c:
        return -1.0, 999
    sm = difflib.SequenceMatcher(None, t, c, autojunk=False)
    matched = sum(b.size for b in sm.get_matching_blocks())
    pct = 200.0 * matched / (len(t) + len(c))
    regions = sum(1 for op in sm.get_opcodes() if op[0] != "equal")
    return pct, regions


# ------------------------------------------------------------- source parse
def find_objdump() -> Path:
    p = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
    if not p.is_file():
        p = REPO / "build" / "binutils" / "powerpc-eabi-objdump.exe"
    return p


def skip_ws_comments(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        ch = s[i]
        if ch in " \t\r\n":
            i += 1
        elif s.startswith("//", i):
            while i < n and s[i] != "\n":
                i += 1
        elif s.startswith("/*", i):
            i += 2
            while i < n and not s.startswith("*/", i):
                i += 1
            i += 2
        else:
            break
    return i


def find_function_body(src: str, name: str):
    """Return (body_open_idx, body_close_idx) for the DEFINITION of `name`."""
    n = len(src)
    start = 0
    while True:
        idx = src.find(name, start)
        if idx < 0:
            return None
        start = idx + len(name)
        # boundary check
        if idx > 0 and (src[idx - 1].isalnum() or src[idx - 1] == "_"):
            continue
        j = skip_ws_comments(src, idx + len(name))
        if j >= n or src[j] != "(":
            continue
        # skip to matching close paren
        depth = 0
        k = j
        while k < n:
            c = src[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        k += 1
        k2 = skip_ws_comments(src, k)
        # allow attribute / trailing tokens up to a '{' or ';'
        if k2 < n and src[k2] == "{":
            # find matching close brace
            depth = 0
            b = k2
            while b < n:
                c = src[b]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return k2, b
                elif c == '"' or c == "'":
                    b = skip_string(src, b)
                    continue
                b += 1
            return None
        # else: it was a declaration/prototype, keep searching


def skip_string(s: str, i: int) -> int:
    q = s[i]
    i += 1
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == q:
            return i + 1
        i += 1
    return i


def next_statement(src: str, i: int, body_end: int):
    """From i (inside body), return (core_start, sep_text, end_after_semi) of the
    next statement, or None. sep_text = ws/comments preceding core."""
    core_start = skip_ws_comments(src, i)
    if core_start >= body_end:
        return None
    sep = src[i:core_start]
    depth = 0
    k = core_start
    while k < body_end:
        c = src[k]
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
        elif c in '"\'':
            k = skip_string(src, k)
            continue
        elif src.startswith("//", k):
            while k < body_end and src[k] != "\n":
                k += 1
            continue
        elif src.startswith("/*", k):
            k += 2
            while k < body_end and not src.startswith("*/", k):
                k += 1
            k += 1
        elif c == ";" and depth == 0:
            end = k + 1
            # absorb a trailing same-line comment
            j = end
            while j < body_end and src[j] in " \t":
                j += 1
            if src.startswith("//", j):
                while j < body_end and src[j] != "\n":
                    j += 1
                end = j
            elif src.startswith("/*", j):
                j += 2
                while j < body_end and not src.startswith("*/", j):
                    j += 1
                end = j + 2
            return core_start, sep, end
        k += 1
    return None


def looks_like_decl(core: str) -> bool:
    s = core.lstrip()
    # first token
    tok = ""
    for ch in s:
        if ch.isalnum() or ch == "_":
            tok += ch
        else:
            break
    if not tok:
        return False
    if tok in TYPE_TOKENS:
        return True
    if tok in {"return", "if", "for", "while", "do", "switch", "goto",
               "case", "default", "break", "continue", "else", "asm"}:
        return False
    # typedef'd type heuristic: `Ident (*|space)+ ident ...` with no '(' before
    # first '=' / ';' / '[' (i.e. not a call/assignment)
    rest = s[len(tok):]
    # position of first terminator among = ; [
    stop = len(rest)
    for term in ("=", ";", "["):
        p = rest.find(term)
        if p != -1:
            stop = min(stop, p)
    head = rest[:stop]
    if "(" in head:
        return False
    # head must contain another identifier (the variable name), possibly via '*'
    import re as _re
    if _re.search(r"[A-Za-z_]\w*", head) or "*" in head:
        # also require the first token be a plausible type (Capitalized or has *)
        if tok[0].isupper() or "*" in head or tok.islower():
            return True
    return False


def parse_decl_block(src: str, body_open: int, body_end: int):
    """Return (block_start, block_end, indent, items[list[str core]])."""
    i = body_open + 1
    items = []
    block_start = None
    block_end = None
    indent = "    "
    while True:
        st = next_statement(src, i, body_end)
        if not st:
            break
        core_start, sep, end = st
        core = src[core_start:end]
        if not looks_like_decl(core):
            break
        if block_start is None:
            block_start = core_start
            # infer indent from sep tail
            nl = sep.rfind("\n")
            if nl != -1:
                indent = sep[nl + 1:]
        items.append(core)
        block_end = end
        i = end
    return block_start, block_end, indent, items


# ------------------------------------------------------------ variant gen
def gen_variants(n: int, strategy: str, cap: int, seed: int = 12345):
    """Yield orderings (as tuples of indices) excluding the identity first."""
    base = tuple(range(n))
    seen = {base}
    out = []

    def add(order):
        t = tuple(order)
        if t not in seen:
            seen.add(t)
            out.append(t)

    if strategy in ("swaps", "all"):
        for a, b in itertools.combinations(range(n), 2):
            o = list(base)
            o[a], o[b] = o[b], o[a]
            add(o)
    if strategy in ("moves", "all"):
        for src_i in range(n):
            for dst in range(n):
                if src_i == dst:
                    continue
                o = list(base)
                x = o.pop(src_i)
                o.insert(dst, x)
                add(o)
    if strategy == "all":
        add(list(reversed(base)))
        rng = random.Random(seed)
        for _ in range(min(40, cap)):
            o = list(base)
            rng.shuffle(o)
            add(o)
    return [base] + out[: max(0, cap - 1)]


# ------------------------------------------------------------------- build
def rebuild(unit_object: str, version: str) -> bool:
    rel = unit_object.replace(f"build/{version}/obj/", f"build/{version}/src/")
    src_o = REPO / rel
    try:
        src_o.unlink()
    except FileNotFoundError:
        pass
    # ninja resolves targets relative to the build root -- pass the repo-relative
    # path, never an absolute path (ninja won't recognise the latter as a target).
    r = subprocess.run(["bash", "tools/locked_ninja.sh", rel],
                       cwd=REPO, capture_output=True, text=True)
    return r.returncode == 0 and src_o.is_file()


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("unit")
    ap.add_argument("symbol")
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--max-variants", type=int, default=60)
    ap.add_argument("--time-budget", type=float, default=900.0)
    ap.add_argument("--strategy", choices=["swaps", "moves", "all"],
                    default="all")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply-best", action="store_true")
    args = ap.parse_args()

    config = REPO / "build" / args.version / "config.json"
    unit = resolve_unit(load_units(config), args.unit)
    src_file = REPO / "src" / unit["name"].replace("\\", "/")
    if not src_file.is_file():
        raise SystemExit(f"source not found: {src_file}")
    objdump = find_objdump()
    tgt_o, cur_o = objdump_paths(unit, args.version)

    original = src_file.read_bytes()
    src = original.decode("latin-1")

    body = find_function_body(src, args.symbol)
    if not body:
        raise SystemExit(f"could not locate definition of {args.symbol}")
    body_open, body_end = body
    bstart, bend, indent, items = parse_decl_block(src, body_open, body_end)
    if not items or len(items) < 2:
        raise SystemExit(
            f"decl block has {len(items) if items else 0} item(s); nothing to permute")

    print(f"# {args.symbol} in {src_file.relative_to(REPO)}")
    print(f"# decl block: {len(items)} items, indent={indent!r}")
    for k, it in enumerate(items):
        one = " ".join(it.split())
        print(f"  [{k}] {one[:90]}")

    def render(order):
        # src[:bstart] already ends with the original leading newline+indent that
        # precedes the first decl, so the first item carries no separator; each
        # subsequent item gets its own "\n"+indent.
        first = items[order[0]].lstrip()
        rest = "".join("\n" + indent + items[k].lstrip() for k in order[1:])
        return src[:bstart] + first + rest + src[bend:], ""

    variants = gen_variants(len(items), args.strategy, args.max_variants)
    print(f"# {len(variants)} variants (strategy={args.strategy}, "
          f"cap={args.max_variants}, budget={args.time_budget}s)")

    if args.dry_run:
        print("# dry-run: baseline decl block would be replaced with, e.g.:")
        newsrc, _ = render(variants[1] if len(variants) > 1 else variants[0])
        seg = newsrc[bstart:bstart + 400]
        print(seg)
        return

    # baseline measure (current tree state as-is; ensure built)
    if not cur_o.is_file():
        rebuild(unit["object"], args.version)
    t_norm = objdump_norm(objdump, tgt_o, args.symbol)

    def measure():
        c = objdump_norm(objdump, cur_o, args.symbol)
        return match_score(t_norm, c)

    base_pct, base_reg = measure()
    print(f"baseline: {base_pct:.3f}%  regions={base_reg}")

    results = []
    best = (base_pct, -base_reg, 0)  # (pct, -regions, variant_idx)
    t0 = time.time()
    try:
        for vi, order in enumerate(variants):
            if vi == 0:
                results.append((base_pct, base_reg, order))
                continue
            if time.time() - t0 > args.time_budget:
                print(f"# time budget hit after {vi} variants")
                break
            newsrc, _ = render(order)
            src_file.write_bytes(newsrc.encode("latin-1"))
            if not rebuild(unit["object"], args.version):
                print(f"[{vi:3d}] BUILD FAIL {order}")
                results.append((-1.0, 999, order))
                continue
            pct, reg = measure()
            results.append((pct, reg, order))
            flag = ""
            if (pct, -reg) > (best[0], best[1]):
                best = (pct, -reg, vi)
                flag = "  <== best"
            print(f"[{vi:3d}] {pct:7.3f}% reg={reg:2d} {list(order)}{flag}")
    finally:
        # restore original before deciding
        src_file.write_bytes(original)

    print("\n# ranked (top 12):")
    for pct, reg, order in sorted(results, key=lambda r: (-r[0], r[1]))[:12]:
        print(f"  {pct:7.3f}% reg={reg:2d} {list(order)}")

    best_pct, neg_reg, best_vi = best
    improved = (best_pct, neg_reg) > (base_pct, -base_reg)
    if improved and (args.apply_best or True):
        newsrc, _ = render(variants[best_vi])
        src_file.write_bytes(newsrc.encode("latin-1"))
        rebuild(unit["object"], args.version)
        print(f"\n# APPLIED best variant #{best_vi}: "
              f"{base_pct:.3f}% -> {best_pct:.3f}%  (proxy metric)")
        print(f"# order = {list(variants[best_vi])}")
        print("# CONFIRM with report.json regen for true objdiff fuzzy%.")
    else:
        rebuild(unit["object"], args.version)
        print(f"\n# no improvement (best {best_pct:.3f}% vs base {base_pct:.3f}%); "
              "restored original.")


if __name__ == "__main__":
    main()
