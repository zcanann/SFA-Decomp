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
    """(pct, regions): exact-normalized-instruction match ratio and #regions.

    This is only a fast pre-filter proxy. The DECIDING metric is the true
    objdiff fuzzy% (fuzzy_measure below); a sibling proved region-count can be
    ANTI-correlated with fuzzy for unroll/schedule-sensitive functions, so never
    rank or commit on this proxy alone.
    """
    if not t or not c:
        return -1.0, 999
    sm = difflib.SequenceMatcher(None, t, c, autojunk=False)
    matched = sum(b.size for b in sm.get_matching_blocks())
    pct = 200.0 * matched / (len(t) + len(c))
    regions = sum(1 for op in sm.get_opcodes() if op[0] != "equal")
    return pct, regions


# --------------------------------------------------- ground-truth fuzzy%
def _rv(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            break
        s += 7
    return r, i


def _fields(b):
    i = 0; o = []
    while i < len(b):
        t, i = _rv(b, i); f = t >> 3; w = t & 7
        if w == 0:
            v, i = _rv(b, i); o.append((f, 0, v))
        elif w == 2:
            l, i = _rv(b, i); o.append((f, 2, b[i:i + l])); i += l
        elif w == 5:
            o.append((f, 5, b[i:i + 4])); i += 4
        elif w == 1:
            o.append((f, 1, b[i:i + 8])); i += 8
    return o


def report_unit_name(unit: dict) -> str:
    """config unit name (e.g. 'main/render.c') -> report/proto name
    ('main/main/render')."""
    name = unit["name"].replace("\\", "/").rsplit(".", 1)[0]
    return "main/" + name


def decode_fuzzy(binpb: bytes, report_unit: str, symbol: str):
    import struct as _st
    for f, w, v in _fields(binpb):
        if f != 2 or w != 2:
            continue
        u = _fields(v); un = None
        for a, b2, c in u:
            if a == 1 and b2 == 2:
                un = c.decode(errors="replace")
        if un != report_unit:
            continue
        for a, b2, c in u:
            if a == 4 and b2 == 2:
                fn = _fields(c); nm = None; fz = None
                for d, e, g in fn:
                    if d == 1 and e == 2:
                        nm = g.decode(errors="replace")
                    if d == 3 and e == 5:
                        fz = _st.unpack("<f", g)[0]
                if nm == symbol:
                    return fz
    return None


def fuzzy_measure(report_unit: str, symbol: str, version: str,
                  retries: int = 8) -> float:
    """True objdiff fuzzy_match_percent for one function. Regenerates the whole
    report (fast: objects are prebuilt) and decodes the proto. `report generate`
    is all-or-nothing, so a concurrent agent mid-rebuild can make it fail -- we
    retry with backoff. Returns -1.0 if it never succeeds."""
    out = Path(f"/tmp/bm_fuzzy_{version}.binpb")
    for attempt in range(retries):
        r = subprocess.run(
            ["build/tools/objdiff-cli", "report", "generate",
             "-o", str(out), "-f", "proto"],
            cwd=REPO, capture_output=True, text=True)
        if r.returncode == 0 and out.is_file():
            fz = decode_fuzzy(out.read_bytes(), report_unit, symbol)
            if fz is not None:
                return fz
        time.sleep(0.4 * (attempt + 1))
    return -1.0


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
    report_unit = report_unit_name(unit)

    def proxy():
        c = objdump_norm(objdump, cur_o, args.symbol)
        return match_score(t_norm, c)

    def fuzzy():
        return fuzzy_measure(report_unit, args.symbol, args.version)

    base_proxy, base_reg = proxy()
    base_fz = fuzzy()
    if base_fz < 0:
        raise SystemExit(
            "could not read baseline fuzzy (report generate failed -- a "
            "concurrent build may be in flight; retry).")
    print(f"baseline: fuzzy={base_fz:.4f}%  proxy={base_proxy:.3f}%  "
          f"regions={base_reg}  (report_unit={report_unit})")

    # DECIDING metric is fuzzy; proxy/regions are informational only. A sibling
    # proved region-count can be anti-correlated with fuzzy, so we never rank on
    # it. results: (fuzzy, proxy, reg, order)
    results = [(base_fz, base_proxy, base_reg, variants[0])]
    best = (base_fz, base_proxy, 0)  # (fuzzy, proxy, variant_idx)
    t0 = time.time()
    try:
        for vi, order in enumerate(variants):
            if vi == 0:
                continue
            if time.time() - t0 > args.time_budget:
                print(f"# time budget hit after {vi} variants")
                break
            newsrc, _ = render(order)
            src_file.write_bytes(newsrc.encode("latin-1"))
            if not rebuild(unit["object"], args.version):
                print(f"[{vi:3d}] BUILD FAIL {order}")
                results.append((-1.0, -1.0, 999, order))
                continue
            px, reg = proxy()
            fz = fuzzy()
            results.append((fz, px, reg, order))
            flag = ""
            # rank strictly by fuzzy; proxy only breaks exact-fuzzy ties
            if (fz, px) > (best[0], best[1]):
                best = (fz, px, vi)
                flag = "  <== best"
            note = " (fuzzy read FAILED)" if fz < 0 else ""
            print(f"[{vi:3d}] fuzzy={fz:8.4f}% proxy={px:7.3f}% reg={reg:2d} "
                  f"{list(order)}{flag}{note}")
    finally:
        # restore original before deciding
        src_file.write_bytes(original)

    print("\n# ranked by FUZZY (top 12):")
    for fz, px, reg, order in sorted(results, key=lambda r: (-r[0], -r[1]))[:12]:
        print(f"  fuzzy={fz:8.4f}% proxy={px:7.3f}% reg={reg:2d} {list(order)}")

    best_fz, best_px, best_vi = best
    # commit gate: true fuzzy must strictly rise
    improved = best_fz > base_fz + 1e-4
    if improved:
        newsrc, _ = render(variants[best_vi])
        src_file.write_bytes(newsrc.encode("latin-1"))
        rebuild(unit["object"], args.version)
        confirm = fuzzy()
        print(f"\n# APPLIED best variant #{best_vi}: "
              f"fuzzy {base_fz:.4f}% -> {confirm:.4f}%")
        print(f"# order = {list(variants[best_vi])}")
        if confirm <= base_fz + 1e-4:
            print("# WARNING: re-measured fuzzy did NOT confirm the gain -- "
                  "restoring original.")
            src_file.write_bytes(original)
            rebuild(unit["object"], args.version)
    else:
        rebuild(unit["object"], args.version)
        print(f"\n# no fuzzy improvement (best {best_fz:.4f}% vs "
              f"base {base_fz:.4f}%); restored original.")


if __name__ == "__main__":
    main()
