#!/usr/bin/env python3
"""Mechanically enumerate plausible-2002 C spellings of a marked source region
and rank each one by instruction distance from the retail carve.

Humans sample the spelling space around a defect; this covers it.  The tool
composes a small grammar of MEANING-PRESERVING source transformations (the
levers this project has measured by hand: statement split/merge at `=`,
named-temp introduction/removal, declaration moves, independent-statement
reorders, `x = x op y` <-> `x op= y`, if/ternary swaps, duplicate-then-fold of
a pure expression, dead-local reuse, array-of-one <-> scalar) up to a bounded
composition depth, compiles every distinct variant OUT OF TREE with the unit's
exact cflags (sequential wibo, perl-alarm timeout, no ninja, no build-tree
writes), and scores the target function with structscan.fn_diff against the
retail carve object.

Banned constructs (volatile puns, pragmas, goto, pool externs) are never
generated.  The grammar is chosen to preserve semantics; a compile failure or
a missing symbol is recorded as ERROR and never ranked.  The verdict on any
winner is still the standard in-tree gate (report.json + full ninja + DOL
sha1): this tool proposes, the operator judges.

The score is a byte-diff PROXY (see permsweep.py's header for why proxies can
mislead): use it to find candidates, then confirm in-tree.  A score of 0 means
the variant's function is instruction-identical to the retail carve modulo
reloc encoding -- the strongest proxy there is, but still confirm.

Usage:
  python3 tools/spellfuzz.py <src.c> <function> <src_obj> --region A:B
      [--budget N=300] [--depth D=2] [--timeout SEC=120]
      [--list] [--keep K=8] [--workdir DIR]

  src.c     repo-relative source file
  function  target function name
  src_obj   the unit's source object, e.g. build/GSAE01/src/dlls/engine/21/21.o
            (cflags + mw_version are extracted from its build.ninja edge; the
            retail carve is the same path with /src/ -> /obj/)
  --region  1-based inclusive line range of the defect neighbourhood; must lie
            inside the function body
  --list    print the generated variants without compiling anything

Never touches the source file or the build tree.  Ranked results, the best
variant's full source and a unified diff land in --workdir (default: a
spellfuzz/ dir beside the scratch sources).
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import itertools
import os
import re
import shlex
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import structscan

KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default", "return",
    "break", "continue", "sizeof", "struct", "union", "enum", "typedef",
    "static", "const", "extern", "register", "int", "char", "short", "long",
    "float", "double", "void", "signed", "unsigned", "NULL", "offsetof",
}
TYPE_WORDS = {
    "int", "char", "short", "long", "float", "double", "void", "signed",
    "unsigned", "u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "f32",
    "f64", "bool", "size_t",
}
CAST_RE = r"(?:\(\s*(?:s32|u32|int|s16|u16|s8|u8|long)\s*\)\s*)?"


def read_bytes_text(path):
    return path.read_bytes().decode("latin-1")


def norm_ninja_path(path):
    return re.sub(r"/+", "/", path.replace("\\", "/"))


def parse_build_edge(src_obj):
    text = read_bytes_text(ROOT / "build.ninja")
    lines = text.splitlines()
    wanted_obj = norm_ninja_path(src_obj)
    varlines = {}
    found = False

    for i, line in enumerate(lines):
        m = re.match(r"^build\s+(\S+):\s+(\S+)\s", line)
        if not m or norm_ninja_path(m.group(1)) != wanted_obj:
            continue

        found = True
        j = i + 1
        while j < len(lines) and (lines[j].startswith(" ") or not lines[j].strip()):
            m = re.match(r"^\s+(\w+) = (.*)$", lines[j])
            if not m:
                j += 1
                continue

            name, value = m.group(1), m.group(2)
            while value.rstrip().endswith("$") and j + 1 < len(lines):
                value = value.rstrip()[:-1] + " " + lines[j + 1].strip()
                j += 1
            varlines[name] = re.sub(r"\s+", " ", value).strip()
            j += 1
        break

    if not found or "cflags" not in varlines:
        raise SystemExit("build edge for %s not found in build.ninja" % src_obj)
    cflags = shlex.split(varlines["cflags"])
    cflags = [f for f in cflags if f != "-MMD"]
    return varlines.get("mw_version", "GC/2.0"), cflags


def find_function(text, name):
    m = re.search(r"^[A-Za-z_][^;{}=]*\b%s\s*\([^;{]*\)\s*\{" % re.escape(name),
                  text, re.M)
    if not m:
        raise SystemExit("function %s not found" % name)
    start = m.start()
    i = text.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return start, j + 1
    raise SystemExit("unbalanced braces in %s" % name)


IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def idents(text):
    return [w for w in IDENT_RE.findall(text) if w not in KEYWORDS]


def is_pure(expr):
    if re.search(r"\b[A-Za-z_]\w*\s*\(", expr):
        return False
    if "++" in expr or "--" in expr:
        return False
    if re.search(r"(?<![=!<>+\-*/&|^])=(?!=)", expr):
        return False
    return True


class Stmt:
    __slots__ = ("text", "start", "end", "kind", "depth")

    def __init__(self, text, start, end, kind, depth):
        self.text = text
        self.start = start
        self.end = end
        self.kind = kind
        self.depth = depth


def split_stmts(region):
    out = []
    depth_p = 0
    depth_b = 0
    i = 0
    start = 0
    n = len(region)
    while i < n:
        c = region[i]
        if c == "(":
            depth_p += 1
        elif c == ")":
            depth_p -= 1
        elif c == "{":
            out.append(Stmt(region[start:i + 1], start, i + 1, "open", depth_b))
            depth_b += 1
            start = i + 1
        elif c == "}":
            chunk = region[start:i]
            if chunk.strip():
                out.append(Stmt(chunk, start, i, "frag", depth_b))
            depth_b -= 1
            out.append(Stmt(region[i:i + 1], i, i + 1, "close", depth_b))
            start = i + 1
        elif c == ";" and depth_p == 0:
            out.append(Stmt(region[start:i + 1], start, i + 1, "stmt", depth_b))
            start = i + 1
        i += 1
    if region[start:].strip():
        out.append(Stmt(region[start:], start, len(region), "frag", depth_b))
    return out


ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][\w\.\[\]]*(?:->[\w\.\[\]]+)*)\s*"
    r"(\+|-|\*|/|\||&|\^|<<|>>)?=(?![=])\s*(.+?);\s*$", re.S)


def parse_assign(stmt):
    if stmt.kind != "stmt":
        return None
    m = ASSIGN_RE.match(stmt.text)
    if not m:
        return None
    lhs, op, rhs = m.group(1), m.group(2), m.group(3)
    if "(" in lhs:
        return None
    first = IDENT_RE.match(lhs.strip())
    if not first or first.group(0) in KEYWORDS or first.group(0) in TYPE_WORDS:
        return None
    return lhs.strip(), op, rhs.strip()


DECL_RE = re.compile(
    r"^\s*((?:static\s+|const\s+)*[A-Za-z_]\w*(?:\s*\*+\s*|\s+))"
    r"([A-Za-z_]\w*)\s*((?:\[\w*\])*)\s*;\s*$")


def parse_decls(head):
    decls = []
    for m in re.finditer(r"[^;{}]*;", head):
        dm = DECL_RE.match(m.group(0))
        if not dm:
            continue
        base = IDENT_RE.match(dm.group(1).strip())
        if base and base.group(0) not in ("return",):
            decls.append({
                "text": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "type": dm.group(1).strip(),
                "name": dm.group(2),
                "arr": dm.group(3),
            })
    return decls


def brace_depth_at(text, pos):
    return text[:pos].count("{") - text[:pos].count("}")


def in_loop(region, pos):
    depth = 0
    stack = []
    for m in re.finditer(r"\b(for|while|do)\b|[{}]", region[:pos]):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            stack = [d for d in stack if d < depth]
        else:
            stack.append(depth)
    return bool(stack)


def local_dead_at(var, region, pos, tail):
    after = region[pos:] + tail
    m = re.search(r"\b%s\b" % re.escape(var), after)
    if not m:
        return True
    prefix = after[:m.start()]
    rest = re.sub(r"^(\s*\[[^\]]*\])*", "", after[m.end():])
    if not re.match(r"\s*=(?!=)", rest):
        return False
    if re.search(r"\bgoto\b", prefix):
        return False
    depth = 0
    neg = False
    for c in prefix:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                neg = True
    if depth == 0 and not neg and not re.search(
            r"\b(break|continue|return)\b", prefix):
        return "strict"
    return "lax"


def repl_ident(text, name, new):
    return re.sub(r"\b%s\b" % re.escape(name), new, text)


class Variant:
    __slots__ = ("head", "region", "tail", "labels")

    def __init__(self, head, region, tail, labels):
        self.head = head
        self.region = region
        self.tail = tail
        self.labels = labels

    def key(self):
        return hashlib.sha1(
            (self.head + "\x00" + self.region + "\x00" + self.tail)
            .encode("latin-1")).hexdigest()

    def child(self, label, head=None, region=None, tail=None):
        return Variant(self.head if head is None else head,
                       self.region if region is None else region,
                       self.tail if tail is None else tail,
                       self.labels + (label,))


def replace_span(text, start, end, new):
    return text[:start] + new + text[end:]


def gen_swap(v):
    stmts = split_stmts(v.region)
    for a, b in zip(stmts, stmts[1:]):
        if a.kind != "stmt" or b.kind != "stmt" or a.depth != b.depth:
            continue
        pa, pb = parse_assign(a), parse_assign(b)
        if not pa or not pb:
            continue
        if not is_pure(pa[2]) or not is_pure(pb[2]):
            continue
        wa = IDENT_RE.match(pa[0]).group(0)
        wb = IDENT_RE.match(pb[0]).group(0)
        if wa in idents(b.text) or wb in idents(a.text):
            continue
        if pa[0] == pb[0]:
            continue
        new = replace_span(v.region, a.start, b.end, b.text + a.text)
        yield v.child("swap(%s,%s)" % (wa, wb), region=new)


def gen_opassign(v):
    stmts = split_stmts(v.region)
    for s in stmts:
        p = parse_assign(s)
        if not p:
            continue
        lhs, op, rhs = p
        if op:
            new_stmt = re.sub(r"%s=" % re.escape(op),
                              "= " + lhs + " " + op, s.text, count=1)
            yield v.child("deop(%s)" % lhs,
                          region=replace_span(v.region, s.start, s.end, new_stmt))
        else:
            m = re.match(r"^\s*%s\s*(\+|-|\*|/|\||&|\^)\s*(.+)$"
                         % re.escape(lhs), rhs)
            if m:
                new_stmt = s.text.replace(rhs, m.group(2), 1)
                new_stmt = re.sub(r"=(?!=)", m.group(1) + "=", new_stmt, count=1)
                yield v.child("opeq(%s)" % lhs,
                              region=replace_span(v.region, s.start, s.end,
                                                  new_stmt))


def window_pairs(stmts, span=4):
    for i, a in enumerate(stmts):
        for b in stmts[i + 1:i + 1 + span]:
            yield a, b, stmts[stmts.index(a) + 1:stmts.index(b)]


def clean_between(between, ids_guard):
    for s in between:
        if s.kind != "stmt":
            return False
        p = parse_assign(s)
        if not p or not is_pure(p[2]):
            return False
        w = IDENT_RE.match(p[0]).group(0)
        if w in ids_guard:
            return False
    return True


def gen_chain(v):
    stmts = [s for s in split_stmts(v.region)]
    for a, b, between in window_pairs(stmts, 3):
        if a.kind != "stmt" or b.kind != "stmt" or a.depth != b.depth:
            continue
        pa, pb = parse_assign(a), parse_assign(b)
        if not pa or not pb or pa[1] or pb[1]:
            continue
        la, ra = pa[0], pa[2]
        lb, rb = pb[0], pb[2]
        m = re.match(r"^%s%s$" % (CAST_RE, re.escape(la)), rb)
        if m:
            if not between:
                pad = a.text[:len(a.text) - len(a.text.lstrip())]
                merged = "%s = %s = %s;" % (lb, la, ra)
                yield v.child("chain(%s<=%s)" % (lb, la),
                              region=replace_span(v.region, a.start, b.end,
                                                  pad + merged))
                cast = rb[:len(rb) - len(la)]
                if cast.strip():
                    merged2 = "%s = %s(%s = %s);" % (lb, cast.strip(), la, ra)
                    yield v.child("chaincast(%s<=%s)" % (lb, la),
                                  region=replace_span(v.region, a.start, b.end,
                                                      pad + merged2))
            if is_pure(ra):
                guard = (set(idents(la + " " + ra))
                         | {IDENT_RE.match(lb).group(0)})
                if clean_between(between, guard):
                    dup = b.text.replace(rb, ra, 1)
                    yield v.child("dup(%s)" % lb,
                                  region=replace_span(v.region, b.start, b.end,
                                                      dup))
        if is_pure(ra) and is_pure(rb) and ra == rb and la != lb:
            fold = b.text.replace(rb, la, 1)
            guard = set(idents(la))
            if clean_between(between, guard):
                yield v.child("fold(%s=%s)" % (lb, la),
                              region=replace_span(v.region, b.start, b.end,
                                                  fold))


def gen_unchain(v):
    stmts = split_stmts(v.region)
    for s in stmts:
        m = re.match(r"^(\s*)([A-Za-z_][\w\.\[\]>-]*)\s*=\s*"
                     r"([A-Za-z_][\w\.\[\]>-]*)\s*=\s*([^=].*?);\s*$", s.text)
        if not m:
            continue
        pad, lb, la, ra = m.groups()
        split = "%s%s = %s;%s%s = %s;" % (pad, la, ra, pad or " ", lb, la)
        yield v.child("unchain(%s)" % lb,
                      region=replace_span(v.region, s.start, s.end, split))


def gen_temp_park(v, decls):
    stmts = split_stmts(v.region)
    for s in stmts:
        p = parse_assign(s)
        if not p or p[1]:
            continue
        lhs, _, rhs = p
        if not is_pure(rhs):
            continue
        lbase = IDENT_RE.match(lhs).group(0)
        for d in decls:
            name = d["name"]
            if name == lbase or name in idents(rhs):
                continue
            if d["arr"] not in ("", "[1]"):
                continue
            if "*" in d["type"] and "*" not in rhs and not re.match(
                    r"^(0|NULL)$", rhs.strip()):
                continue
            dead = local_dead_at(name, v.region, s.end, v.tail)
            if not dead:
                continue
            if in_loop(v.region, s.start):
                if re.search(r"\b%s\b" % re.escape(name), v.region[:s.start]):
                    continue
            use = name + ("[0]" if d["arr"] == "[1]" else "")
            pad = s.text[:len(s.text) - len(s.text.lstrip())]
            parked = "%s%s = %s;%s%s = %s;" % (pad, use, rhs, pad or " ",
                                               lhs, use)
            tag = "park" if dead == "strict" else "park?"
            yield v.child("%s(%s->%s)" % (tag, lhs, name),
                          region=replace_span(v.region, s.start, s.end, parked))


def gen_fresh_temp(v, decls):
    stmts = split_stmts(v.region)
    if "spf_t" in v.head:
        return
    for s in stmts:
        p = parse_assign(s)
        if not p or p[1]:
            continue
        lhs, _, rhs = p
        if not is_pure(rhs):
            continue
        lbase = IDENT_RE.match(lhs).group(0)
        d = next((d for d in decls if d["name"] == lbase), None)
        if d is not None and "*" in d["type"]:
            continue
        if d is not None:
            types = [d["type"]]
        else:
            cm = re.match(r"^\(\s*(\w+)\s*\)", rhs)
            types = ["int"] if not cm else [cm.group(1), "int"]
        pad = s.text[:len(s.text) - len(s.text.lstrip())]
        parked = "%sspf_t = %s;%s%s = spf_t;" % (pad, rhs, pad or " ", lhs)
        last = decls[-1]
        for ty in dict.fromkeys(types):
            for where, dpos in (("top", decls[0]["start"]),
                                ("bot", last["end"])):
                if where == "top":
                    head = replace_span(v.head, dpos, dpos,
                                        "%s spf_t;\n    " % ty)
                else:
                    head = replace_span(v.head, dpos, dpos,
                                        "\n    %s spf_t;" % ty)
                yield v.child("fresh(%s,%s,%s)" % (lhs, ty, where), head=head,
                              region=replace_span(v.region, s.start, s.end,
                                                  parked))


def gen_array1(v, decls):
    touched = set(idents(v.region))
    for d in decls:
        name = d["name"]
        if name not in touched:
            continue
        if d["arr"] == "":
            if re.search(r"&\s*%s\b" % re.escape(name), v.head + v.region + v.tail):
                continue
            new_decl = re.sub(r"\b%s\b" % re.escape(name), name + "[1]",
                              d["text"], count=1)
            head = replace_span(v.head, d["start"], d["end"], new_decl)
            cut = d["start"] + len(new_decl)
            head = head[:cut] + repl_ident(head[cut:], name, name + "[0]")
            region = repl_ident(v.region, name, name + "[0]")
            tail = repl_ident(v.tail, name, name + "[0]")
            yield v.child("arr1(%s)" % name, head=head, region=region,
                          tail=tail)
        elif d["arr"] == "[1]":
            body = v.head[d["end"]:] + "\x00" + v.region + "\x00" + v.tail
            uses = re.findall(r"\b%s\b(?!\s*\[0\])" % re.escape(name), body)
            if uses:
                continue
            new_decl = d["text"].replace(name + "[1]", name, 1)
            head = replace_span(v.head, d["start"], d["end"], new_decl)
            pre, post = head[:d["start"] + len(new_decl)], head[d["start"] + len(new_decl):]

            def unarr(t):
                return re.sub(r"\b%s\s*\[0\]" % re.escape(name), name, t)

            yield v.child("scal(%s)" % name, head=pre + unarr(post),
                          region=unarr(v.region), tail=unarr(v.tail))


def gen_decl_move(v, decls):
    touched = set(idents(v.region))
    for d in decls:
        if d["name"] not in touched:
            continue
        for target, label in ((decls[0], "first"), (decls[-1], "last")):
            if target is d:
                continue
            head = v.head
            if label == "first":
                stripped = replace_span(head, d["start"], d["end"], "")
                head2 = replace_span(stripped, target["start"], target["start"],
                                     d["text"].strip() + "\n    ")
            else:
                if d["start"] < target["start"]:
                    head2 = replace_span(head, target["end"], target["end"],
                                         "\n    " + d["text"].strip())
                    head2 = replace_span(head2, d["start"], d["end"], "")
                else:
                    continue
            yield v.child("mv(%s,%s)" % (d["name"], label), head=head2)


def gen_scope_push(v, decls):
    stack = []
    for i, c in enumerate(v.head):
        if c == "{":
            stack.append(i)
        elif c == "}":
            if stack:
                stack.pop()
    if len(stack) < 2:
        return
    ins = stack[-1] + 1
    touched = set(idents(v.region))
    for d in decls:
        if d["name"] not in touched or d["end"] >= ins:
            continue
        between = v.head[d["end"]:ins]
        if re.search(r"\b%s\b" % re.escape(d["name"]), between):
            continue
        head = replace_span(v.head, ins, ins,
                            "\n        " + d["text"].strip())
        head = replace_span(head, d["start"], d["end"], "")
        yield v.child("push(%s)" % d["name"], head=head)


def gen_ternary(v):
    pat = re.compile(
        r"(\s*)if\s*\(([^{};]+)\)\s*\{\s*([A-Za-z_][\w\.\[\]>-]*)\s*=\s*"
        r"([^;{}]+);\s*\}\s*else\s*\{\s*\3\s*=\s*([^;{}]+);\s*\}", re.S)
    for m in pat.finditer(v.region):
        pad, cond, lhs, a, b = m.groups()
        if not (is_pure(a) and is_pure(b) and is_pure(cond)):
            continue
        rep = "%s%s = %s ? %s : %s;" % (pad, lhs, cond.strip(), a.strip(),
                                        b.strip())
        yield v.child("tern(%s)" % lhs,
                      region=replace_span(v.region, m.start(), m.end(), rep))
    tpat = re.compile(r"(\s*)([A-Za-z_][\w\.\[\]>-]*)\s*=\s*([^;?]+)\?"
                      r"([^;:]+):([^;]+);")
    for m in tpat.finditer(v.region):
        pad, lhs, cond, a, b = m.groups()
        rep = ("%sif (%s) {%s    %s = %s;%s} else {%s    %s = %s;%s}"
               % (pad, cond.strip(), pad, lhs, a.strip(), pad, pad, lhs,
                  b.strip(), pad))
        yield v.child("ifelse(%s)" % lhs,
                      region=replace_span(v.region, m.start(), m.end(), rep))


def match_brace(text, open_pos):
    depth = 0
    for j in range(open_pos, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return -1


def gen_loopform(v):
    for m in re.finditer(r"\bwhile\s*\(", v.region):
        par = v.region.index("(", m.start())
        depth = 1
        j = par + 1
        while j < len(v.region) and depth:
            if v.region[j] == "(":
                depth += 1
            elif v.region[j] == ")":
                depth -= 1
            j += 1
        cond = v.region[par + 1:j - 1]
        ob = v.region.find("{", j)
        if ob < 0 or v.region[j:ob].strip():
            continue
        cb = match_brace(v.region, ob)
        if cb < 0:
            continue
        body = v.region[ob + 1:cb]
        stmts = [s for s in split_stmts(body) if s.kind == "stmt"]
        if not stmts:
            continue
        last = stmts[-1]
        if last.end < len(body) and body[last.end:].strip():
            continue
        if last.depth != 0 or re.search(r"\bcontinue\b", body):
            continue
        core = last.text.strip().rstrip(";")
        simple_upd = (parse_assign(last) is not None
                      or re.match(r"^[A-Za-z_][\w\.\[\]>-]*\s*(\+\+|--)$",
                                  core))
        if not simple_upd or re.search(r"\b\w+\s*\(", core):
            continue
        upd = core
        new_body = body[:last.start]
        rep = "for (; %s; %s) {%s}" % (cond.strip(), upd, new_body)
        yield v.child("for(%s)" % upd[:20],
                      region=replace_span(v.region, m.start(), cb + 1, rep))
    for m in re.finditer(r"\bfor\s*\(([^;()]*);([^;()]*);([^()]*)\)\s*\{",
                         v.region):
        init, cond, upd = (x.strip() for x in m.groups())
        ob = v.region.index("{", m.end() - 1)
        cb = match_brace(v.region, ob)
        if cb < 0:
            continue
        body = v.region[ob + 1:cb]
        pre = (init + ";\n    ") if init else ""
        post = ("    " + upd + ";\n") if upd else ""
        rep = "%swhile (%s) {%s%s}" % (pre, cond, body, post)
        yield v.child("while(%s)" % (cond[:20]),
                      region=replace_span(v.region, m.start(), cb + 1, rep))


GENERATORS = ("swap", "opassign", "chain", "unchain", "park", "fresh",
              "arr1", "mv", "ternary", "loopform")


def expand(v):
    decls = parse_decls(v.head)
    gens = [gen_swap(v), gen_opassign(v), gen_chain(v), gen_unchain(v),
            gen_ternary(v), gen_loopform(v)]
    if decls:
        gens += [gen_temp_park(v, decls), gen_fresh_temp(v, decls),
                 gen_array1(v, decls), gen_decl_move(v, decls),
                 gen_scope_push(v, decls)]
    for g in gens:
        try:
            for child in g:
                yield child
        except Exception:
            continue


class Compiler:
    def __init__(self, mw_version, cflags, workdir, timeout):
        self.mw = str(ROOT / "build" / "compilers" / mw_version / "mwcceppc.exe")
        self.cflags = cflags
        self.workdir = workdir
        self.timeout = timeout

    def compile(self, src_path, out_dir):
        sjiswrap = ROOT / "build/tools/sjiswrap.exe"
        wibo = ROOT / "build/tools/wibo"
        base_cmd = [str(sjiswrap), self.mw] + self.cflags + [
            "-c", str(src_path), "-o", str(out_dir)
        ]
        if wibo.exists() and shutil.which("perl"):
            cmd = ["perl", "-e", "alarm shift; exec @ARGV", str(self.timeout),
                   str(wibo)] + base_cmd
        else:
            cmd = base_cmd
        try:
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                               timeout=self.timeout + 30,
                               start_new_session=True)
        except subprocess.TimeoutExpired:
            if shutil.which("pkill"):
                subprocess.run(["pkill", "-f", "mwcceppc.exe"],
                               capture_output=True)
            return None, "TIMEOUT"
        obj = out_dir / (src_path.stem + ".o")
        if r.returncode != 0 or not obj.exists():
            return None, (r.stdout + r.stderr)[-400:]
        return obj, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("function")
    ap.add_argument("src_obj")
    ap.add_argument("--region", required=True)
    ap.add_argument("--budget", type=int, default=300)
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--keep", type=int, default=8)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--workdir")
    args = ap.parse_args()

    src_path = ROOT / args.src
    text = read_bytes_text(src_path)
    fstart, fend = find_function(text, args.function)
    fn_text = text[fstart:fend]

    a, b = (int(x) for x in args.region.split(":"))
    line_offsets = [0]
    for line in text.split("\n"):
        line_offsets.append(line_offsets[-1] + len(line) + 1)
    rstart = line_offsets[a - 1]
    rend = min(line_offsets[b], len(text))
    if not (fstart < rstart and rend <= fend):
        raise SystemExit("region %s outside function body (%d..%d)"
                         % (args.region, fstart, fend))
    head = text[fstart:rstart]
    region = text[rstart:rend]
    tail = text[rend:fend]
    pre, post = text[:fstart], text[fend:]

    mw_version, cflags = parse_build_edge(args.src_obj)
    retail = ROOT / args.src_obj.replace("\\", "/").replace("/src/", "/obj/", 1)
    if not retail.exists():
        raise SystemExit("retail carve %s missing" % retail)

    workdir = Path(args.workdir) if args.workdir else \
        Path(os.environ.get("TMPDIR", "/tmp")) / "spellfuzz" / Path(args.src).stem
    workdir.mkdir(parents=True, exist_ok=True)

    base = Variant(head, region, tail, ())
    seen = {base.key()}
    frontier = [base]
    variants = []
    for depth in range(1, args.depth + 1):
        nxt = []
        for v in frontier:
            for child in expand(v):
                k = child.key()
                if k in seen:
                    continue
                seen.add(k)
                nxt.append(child)
                variants.append(child)
                if len(variants) >= args.budget:
                    break
            if len(variants) >= args.budget:
                break
        frontier = nxt
        if len(variants) >= args.budget:
            break

    print("generated %d distinct variants (depth<=%d, budget %d)"
          % (len(variants), args.depth, args.budget))
    if args.list:
        for v in variants:
            print("  " + " | ".join(v.labels))
        return

    comp = Compiler(mw_version, cflags, workdir, args.timeout)
    base_src = workdir / "base.c"
    base_src.write_bytes((pre + head + region + tail + post).encode("latin-1"))
    obj, err = comp.compile(base_src, workdir)
    if obj is None:
        raise SystemExit("baseline compile failed: %s" % err)
    base_score = structscan.fn_diff(str(retail), str(obj), args.function)
    if base_score is None:
        raise SystemExit("baseline: %s not found in object" % args.function)
    print("baseline score: ndiff=%d struc=%d len %d/%d"
          % (base_score[0], base_score[1], base_score[2], base_score[3]))

    results = []
    t0 = time.time()
    for i, v in enumerate(variants):
        vsrc = workdir / ("v%s.c" % v.key()[:12])
        vsrc.write_bytes((pre + v.head + v.region + v.tail + post)
                         .encode("latin-1"))
        obj, err = comp.compile(vsrc, workdir)
        if obj is None:
            tailmsg = (err or "").strip().splitlines()
            results.append((None, v, "ERROR: %s" % (tailmsg[-1] if tailmsg else "")))
            vsrc.unlink(missing_ok=True)
            continue
        score = structscan.fn_diff(str(retail), str(obj), args.function)
        vobj = obj.read_bytes()
        sha = hashlib.sha1(vobj).hexdigest()[:10]
        if score is None:
            results.append((None, v, "NOSYM"))
        else:
            results.append((score, v, sha))
        obj.rename(workdir / ("v%s.o" % v.key()[:12]))
        if score is not None and score[0] == 0:
            print("[%d/%d] ZERO  %s" % (i + 1, len(variants),
                                        " | ".join(v.labels)))
            break
        if (i + 1) % 20 == 0:
            best = min((r for r in results if r[0]), default=None,
                       key=lambda r: r[0])
            print("[%d/%d] %.0fs best-so-far=%s" %
                  (i + 1, len(variants), time.time() - t0,
                   best[0] if best else "none"))

    scored = sorted((r for r in results if r[0] is not None),
                    key=lambda r: (r[0][0], r[0][1]))
    errors = [r for r in results if r[0] is None]
    print("\ncompiled %d ok, %d errors" % (len(scored), len(errors)))
    for _, v, msg in errors[:15]:
        print("  ERR %s :: %s" % (" | ".join(v.labels), msg))
    print("== ranking (ndiff, struc, lenT, lenC) vs baseline %s ==" %
          (base_score,))
    for score, v, sha in scored[:max(args.keep, 20)]:
        marker = "<<<" if score[0] < base_score[0] else "   "
        print(" %s %s sha=%s  %s" % (marker, score, sha,
                                     " | ".join(v.labels)))

    with open(workdir / "ranking.txt", "w") as fh:
        fh.write("baseline %s\n" % (base_score,))
        for score, v, sha in scored:
            fh.write("%s sha=%s  %s\n" % (score, sha, " | ".join(v.labels)))
        for _, v, msg in errors:
            fh.write("ERR %s :: %s\n" % (" | ".join(v.labels), msg))
    for j, (score, v, sha) in enumerate(scored[:args.keep]):
        keep_src = workdir / ("best%d_%s.c" % (j, v.key()[:12]))
        full = pre + v.head + v.region + v.tail + post
        keep_src.write_bytes(full.encode("latin-1"))
        if j == 0:
            diff = difflib.unified_diff(
                text.splitlines(True), full.splitlines(True),
                fromfile=args.src, tofile=args.src + " (best)", n=6)
            (workdir / "best.patch").write_text("".join(diff))
    kept = {("v%s.c" % v.key()[:12]) for _, v, _ in scored[:args.keep]}
    kept |= {("v%s.o" % v.key()[:12]) for _, v, _ in scored[:args.keep]}
    for f in workdir.glob("v*.c"):
        if f.name not in kept:
            f.unlink(missing_ok=True)
    for f in workdir.glob("v*.o"):
        if f.name not in kept:
            f.unlink(missing_ok=True)
    if scored and scored[0][0][0] == 0:
        print("\nZERO-DIFF variant found; best.patch written to %s" % workdir)
    else:
        print("\nno zero; best %s (baseline %s); best.patch in %s"
              % (scored[0][0] if scored else None, base_score, workdir))


if __name__ == "__main__":
    main()
