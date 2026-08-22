#!/usr/bin/env python3
"""Sweep the OPERAND ORDER of commutative binary expressions.

docs/priced_classes.md Sec 27 measures that the #82 residual is overwhelmingly a
SCRATCH-register class -- 57 of 139 colouring rows have their whole residual in
f0-f13/r0-r13 -- and that declaration order only reaches the callee-saved band.
Scratch registers hold unnamed expression temporaries, so the source key for
them is not any declaration or statement order; it is the shape of the
expression itself.  Measured:

    a * b + c * d   ->  fmuls f0,f3,f4 ; fmadds f1,f1,f2,f0
    b * a + c * d   ->  fmuls f0,f3,f4 ; fmadds f1,f2,f1,f0
    c * d + a * b   ->  fmuls f0,f1,f2 ; fmadds f1,f3,f4,f0

so swapping the two operands of one `*` or `+` moves both the operand columns
and which subexpression is evaluated into the scratch register first.  Neither
brute_match.py (declarations) nor stmt_sweep.py (statements) can reach this.

Only provably safe sites are offered: both operands must be side-effect-free
atoms (an identifier with `->`/`.`/`[]` chains, a numeric literal, or a fully
parenthesised group with no call and no `++`/`--`), and the site must not sit
inside a longer chain of the same precedence class, where a swap would also
re-associate.  Swapping the operands of `*` or `+` is value-identical under
IEEE754 for every non-NaN input.

Usage: operand_sweep.py <unit> <symbol> [-v GSAE01] [--list] [--apply]
                        [--ops "*+"] [--time-budget S]
"""
from __future__ import annotations
import argparse, re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from function_objdump import load_units, resolve_unit
from brute_match import (REPO, TYPE_TOKENS, find_function_body, find_objdump,
                         fuzzy_measure, objdump_paths, rebuild,
                         recover_stale_backup, skip_string)

ATOM_TAIL = re.compile(r"\s*(->\s*[A-Za-z_]\w*|\.\s*[A-Za-z_]\w*|\[)")
IDENT = re.compile(r"[A-Za-z_]\w*")
NUM = re.compile(r"(?:0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][-+]?\d+)?)[fFuUlL]*")
BAD = re.compile(r"\+\+|--|\bsizeof\b")


import semantic_equivalence as _sem


def _candidate_spans(s, lo, hi, ls, re_):
    """Enclosing regions to try, innermost first.

    The proof needs a region that PARSES as an expression on the before side.
    A statement usually does; an `if (...)` condition only does once the
    keyword and its parentheses are stripped, so the enclosing parenthesised
    groups are offered first.
    """
    spans = []
    depth, k = 0, ls - 1
    while k >= lo and len(spans) < 4:
        if s[k] in ")]}":
            depth += 1
        elif s[k] in "([{":
            if depth == 0:
                e = match_paren(s, k)
                if e - 1 >= re_:
                    spans.append((k + 1, e - 1))
            else:
                depth -= 1
        k -= 1
    a = max(s.rfind(ch, lo, ls) for ch in ";{}")
    b = min((p for p in (s.find(ch, re_, hi) for ch in ";{}") if p >= 0),
            default=hi)
    spans.append((lo if a < 0 else a + 1, b))
    return spans


def _prove_statement(src, out, ls, re_, body):
    """Re-parse the enclosing expression on both sides and prove the identity."""
    delta = len(out) - len(src)
    decls = src[body[0]:body[1]]
    ids = frozenset(_sem.TypeOracle(decls).kind)
    last = _sem.Verdict(False, "no enclosing region could be parsed")
    for a, b in _candidate_spans(src, body[0], body[1], ls, re_):
        before, after = src[a:b], out[a:b + delta]
        v = _sem.prove(before, after, decl_text=decls, known_ids=ids)
        if v.ok:
            return v
        if not v.reason.startswith("PARSE"):
            return v
        last = v
    return last


def match_paren(s, i):
    d = 0
    while i < len(s):
        if s[i] in "\"'":
            i = skip_string(s, i); continue
        if s[i] in "([":
            d += 1
        elif s[i] in ")]":
            d -= 1
            if d == 0:
                return i + 1
        i += 1
    return -1


def atom_right(s, i):
    """Longest side-effect-free atom starting at i; -1 if none."""
    while i < len(s) and s[i] in " \t\n":
        i += 1
    if i >= len(s):
        return -1, -1
    st = i
    if s[i] == "(":
        j = match_paren(s, i)
        if j < 0:
            return -1, -1
        inner = s[st:j]
        if BAD.search(inner) or re.search(r"[A-Za-z_]\w*\s*\(", inner[1:]):
            return -1, -1
        k = j
        while k < len(s) and s[k] in " \t":
            k += 1
        # `(u32)x`, `(f32*)p`, `(T)(e)` -- a CAST, whose operand runs past the
        # close paren.  Taking the parenthesised type as the operand splices the
        # expression apart, so refuse the site entirely.
        if k < len(s) and (s[k].isalnum() or s[k] in "_(*&"):
            return -1, -1
        i = j
    else:
        m = NUM.match(s, i)
        if m:
            return st, m.end()
        m = IDENT.match(s, i)
        if not m:
            return -1, -1
        i = m.end()
        # a call is a side effect
        k = i
        while k < len(s) and s[k] in " \t":
            k += 1
        if k < len(s) and s[k] == "(":
            return -1, -1
    while True:
        m = ATOM_TAIL.match(s, i)
        if not m:
            break
        if m.group(1) == "[":
            j = match_paren(s, s.index("[", i))
            if j < 0:
                return -1, -1
            i = j
        else:
            i = m.end()
    return st, i


def atom_left(s, i):
    """Longest side-effect-free atom ENDING at i (exclusive); -1 if none."""
    j = i
    while j > 0 and s[j - 1] in " \t\n":
        j -= 1
    end = j
    if j > 0 and s[j - 1] in ")]":
        # walk back to the matching open
        d = 0; k = j - 1
        while k >= 0:
            if s[k] in ")]":
                d += 1
            elif s[k] in "([":
                d -= 1
                if d == 0:
                    break
            k -= 1
        if k < 0:
            return -1, -1
        j = k
        # a call `f(...)` or an index `a[...]` -- back up over the head too
        h = j
        while h > 0 and (s[h - 1].isalnum() or s[h - 1] in "_.>"):
            h -= 1
        if h < j:
            return -1, -1          # f(...) or a[...] head: not simple enough
        inner = s[j:end]
        if BAD.search(inner) or re.search(r"[A-Za-z_]\w*\s*\(", inner[1:]):
            return -1, -1
        return j, end
    k = j
    while k > 0 and (s[k - 1].isalnum() or s[k - 1] == "_"):
        k -= 1
    if k == j:
        return -1, -1
    # member chains and indices to the left make the atom non-trivial: refuse
    p = k
    while p > 0 and s[p - 1] in " \t":
        p -= 1
    if p >= 2 and (s[p - 2:p] == "->" or s[p - 1] in ".])"):
        return -1, -1
    return k, end


def sites(src, lo, hi, ops, allow_lit=False):
    out = []
    i = lo
    while i < hi:
        c = src[i]
        if c in "\"'":
            i = skip_string(src, i); continue
        if src.startswith("//", i):
            i = src.find("\n", i); i = hi if i < 0 else i; continue
        if src.startswith("/*", i):
            j = src.find("*/", i); i = hi if j < 0 else j + 2; continue
        if c in ops:
            nxt = src[i + 1] if i + 1 < hi else ""
            prv = src[i - 1] if i > lo else ""
            # not ** (deref), not *=, not += / ++, not a pointer decl context
            if nxt in "=*+-/&|" or prv in "=*+-/&|<>!(,;{":
                i += 1; continue
            ls, le = atom_left(src, i)
            rs, re_ = atom_right(src, i + 1)
            if ls < 0 or rs < 0:
                i += 1; continue
            # refuse when the site sits in a longer chain of the same class
            cls = "*/%" if c == "*" else "+-*/%"
            k = ls
            while k > lo and src[k - 1] in " \t\n":
                k -= 1
            if k > lo and src[k - 1] in cls:
                i += 1; continue
            k = re_
            while k < hi and src[k] in " \t\n":
                k += 1
            if k < hi and src[k] in cls:
                i += 1; continue
            # a DECLARATION, not an expression: `MatrixTransform* xf` reads as a
            # multiplication.  Scan back to the statement head and refuse when it
            # opens with a type token.
            h = max(lo, max(src.rfind(ch, lo, ls) for ch in ";{}"))
            head = IDENT.search(src, h, le)
            if head and (head.group(0) in TYPE_TOKENS or
                         head.group(0).endswith("_t") or
                         re.match(r"^[A-Z]\w*$", head.group(0))):
                i += 1; continue
            # `8 * t0` / `0x50 + pos` is legal but nobody wrote it in 2002, so a
            # literal-first rewrite is not a candidate the source could have had.
            if not allow_lit and (NUM.fullmatch(src[ls:le].strip()) or
                                  NUM.fullmatch(src[rs:re_].strip())):
                i = re_; continue
            out.append((ls, le, i, rs, re_, c))
            i = re_; continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unit"); ap.add_argument("symbol")
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--ops", default="*+")
    ap.add_argument("--allow-literal", action="store_true",
                    help="also offer literal-first rewrites (implausible; off)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--show", action="store_true",
                    help="print the exact before -> after rewrite of every site")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--time-budget", type=float, default=900.0)
    a = ap.parse_args()

    unit = resolve_unit(load_units(REPO / "build" / a.version / "config.json"), a.unit)
    src_file = REPO / "src" / unit["name"].replace("\\", "/")
    recover_stale_backup(src_file)
    original = src_file.read_bytes()
    src = original.decode("latin-1")
    body = find_function_body(src, a.symbol)
    if not body:
        raise SystemExit(f"PARSE-ERROR could not locate {a.symbol}")
    ss = sites(src, body[0], body[1], set(a.ops), a.allow_literal)
    print(f"# {a.symbol}: {len(ss)} swappable commutative site(s)")
    for n, (ls, le, oi, rs, re_, c) in enumerate(ss):
        print(f"  [{n}] {' '.join(src[ls:re_].split())[:96]}")
    if a.show:
        for n, (ls, le, oi, rs, re_, c) in enumerate(ss):
            A, B = src[ls:le].strip(), src[rs:re_].strip()
            print(f"  [{n}] {' '.join(src[ls:re_].split())[:70]}"
                  f"   ==>   {' '.join((B + ' ' + c + ' ' + A).split())[:70]}")
    if a.list or a.show or not ss:
        return

    def balanced(t):
        d = 0
        for ch in t:
            if ch in "([":
                d += 1
            elif ch in ")]":
                d -= 1
                if d < 0:
                    return False
        return d == 0

    def render(n):
        ls, le, oi, rs, re_, c = ss[n]
        A, B = src[ls:le].strip(), src[rs:re_].strip()
        if not (balanced(A) and balanced(B)):
            raise SystemExit(f"REFUSED site {n}: unbalanced operand")
        out = src[:ls] + B + " " + c + " " + A + src[re_:]
        # nothing may be added or lost: the rewrite is a permutation of the file
        strip = lambda t: sorted(t.replace(" ", "").replace("\n", "").replace("\t", ""))
        if strip(out) != strip(src):
            raise SystemExit(f"REFUSED site {n}: not a pure transposition")
        # A transposition of the CHARACTERS is not a transposition of the
        # MEANING.  This tool once turned `verts + j * 12` into
        # `(j + verts) * 12` -- a permutation of the file by every check above,
        # and a different computation -- so the enclosing statement is now
        # re-parsed on both sides and the rewrite must be PROVED an identity.
        # The guards in sites() are heuristics; this is the gate.
        v = _prove_statement(src, out, ls, re_, body)
        if not v.ok:
            raise SystemExit(f"REFUSED site {n}: {v}")
        return out

    rebuild(unit["object"], a.version)
    base = fuzzy_measure(unit, a.symbol, a.version)
    print(f"# baseline fuzzy={base:.4f}")
    best = (base, None); t0 = time.time()
    try:
        for n in range(len(ss)):
            if time.time() - t0 > a.time_budget:
                print("# time budget hit"); break
            try:
                candidate_src = render(n)
            except SystemExit as e:
                print(e)
                continue
            src_file.write_bytes(candidate_src.encode("latin-1"))
            if not rebuild(unit["object"], a.version):
                print(f"  [{n}] BUILD FAIL"); continue
            fz = fuzzy_measure(unit, a.symbol, a.version)
            print(f"  [{n}] fuzzy={fz:8.4f}"
                  f"{'  <== BETTER' if fz > base + 1e-4 else ''}")
            if fz > best[0] + 1e-4:
                best = (fz, n)
    finally:
        src_file.write_bytes(original)
    if a.apply and best[1] is not None:
        src_file.write_bytes(render(best[1]).encode("latin-1"))
        rebuild(unit["object"], a.version)
        print(f"# APPLIED site {best[1]}: {base:.4f} -> "
              f"{fuzzy_measure(unit, a.symbol, a.version):.4f}")
    else:
        rebuild(unit["object"], a.version)
    print(f"#BASE={base:.4f} BEST={best[0]:.4f} SITES={len(ss)}")


if __name__ == "__main__":
    main()
