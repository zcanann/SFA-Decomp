#!/usr/bin/env python3
"""Screen for un-modelled incoming parameters.

A register the TARGET function reads but never writes is an incoming value.
That alone is NOT a finding -- it is true of every correctly declared
parameter, which is why the unguarded form of this screen reported 19 hits and
19 false positives.  The screen is only meaningful against OUR OWN declared
signature: a hit is a register that arrives as an incoming value in the target
and is NOT accounted for by the parameter list we wrote.

So the pipeline is:

  target object  -> registers read-but-never-written  (incoming set)
  our .c source  -> declared signature -> PPC EABI register assignment
  hit            = incoming - assigned

Blind spot, stated explicitly because a prior wave mistook it for this
tool's headline result: a parameter that the body never touches at all --
forwarded to a callee in the register it arrived in -- appears in NO
instruction operand, so it is in neither the read nor the write set and this
screen cannot see it.  `dll_CB_moveHandler0`'s f32 is exactly that shape.
Finding those needs the CALLEE's signature, not this def/use scan.

  --selftest   fault-inject each path (strip a declared parameter from a copy
               of the real source and confirm the register is flagged) and
               assert it fires.
"""

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")

# instructions whose FIRST operand is a source, not a destination
SRC_FIRST = re.compile(
    r"^(st|b|cmp|cr|mt|tw|dcb|icb|sync|isync|eieio|nop|psq_st|fcmp)"
)
REG = re.compile(r"\b([rf])(\d+)\b")
CALLS = ("bl", "bla", "bctrl", "blrl")

GPR_ARGS = ["r%d" % i for i in range(3, 11)]
FPR_ARGS = ["f%d" % i for i in range(1, 9)]
ARGS = set(GPR_ARGS) | set(FPR_ARGS)

FLOAT_T = re.compile(r"\b(float|double|f32|f64)\b")
LONGLONG_T = re.compile(r"\b(long\s+long|s64|u64|int64|s64_t|u64_t)\b")
INT_T = re.compile(
    r"\b(void|char|short|int|long|signed|unsigned|bool|BOOL|"
    r"[su](?:8|16|32)|size_t|enum)\b")


# --------------------------------------------------------------------------
# target side: which argument registers arrive as incoming values
# --------------------------------------------------------------------------

def disasm(obj, symbol):
    out = subprocess.run(
        [OBJDUMP, "-M", "gekko", "-drz", obj], capture_output=True, text=True
    ).stdout
    lines, on = [], False
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:$", line.strip())
        if m:
            on = m.group(1) == symbol
            continue
        if on and re.match(r"^\s+[0-9a-f]+:\s", line):
            lines.append(line)
    return lines


# MWCC prologue/epilogue helpers.  These are `bl`s but they are ABI-special:
# they touch only r11 and the saved bank, so they do NOT clobber the argument
# registers.  Treating them as ordinary calls silences the screen on every
# function large enough to spill (walkGroupFn, debugPrintfxy).
PRESERVING = re.compile(r"^(_{1,2}(save|rest(ore)?)(gpr|fpr|f|g)\w*)$")


def _decode(lines):
    """-> [(mnemonic, dst_or_None, [srcs], reloc_sym), ...] in program order."""
    out = []
    for line in lines:
        m = re.match(r"^\s+[0-9a-f]+:\s+(R_PPC_\S+)\s+(\S+)", line)
        if m:
            if out:
                out[-1][3] = m.group(2)
            continue
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].split():
            continue
        mnem = parts[2].split()[0]
        ops = parts[2][len(mnem):].strip()
        ops = ops.split("#")[0]
        # a branch operand is a target ADDRESS, not a register: "b f10 <sym>"
        # would otherwise read as fpr f10
        ops = ops.split("<")[0]
        # `bl`/`bla` are CALLS and clobber the whole volatile bank exactly as
        # `bctrl` does.  Treating them as plain branches made every function
        # that stores a callee's return value read as taking that register as
        # an incoming parameter (hwInitIrq storing OSDisableInterrupts()).
        if mnem.startswith("b") and mnem not in CALLS:
            continue
        if mnem in CALLS:
            # A call's operand is a TARGET ADDRESS, never a register. Hex
            # addresses like `bl f4 <sym+0x48>` otherwise decode as fpr f4 and
            # manufacture an incoming float parameter out of thin air.
            out.append([mnem, None, [], None])
            continue
        regs = [(k + n) for k, n in REG.findall(ops)]
        srcs, dst = regs, None
        if regs and not SRC_FIRST.match(mnem):
            dst, srcs = regs[0], regs[1:]
        out.append([mnem, dst, srcs, None])
    return out


def analyze(lines):
    """-> (registers written anywhere, registers that arrive as incoming).

    Two different notions of "written", because one alone gets it wrong in
    opposite directions:

      * an EXPLICIT write is taken flat over the whole body, so a register
        defined on a loop back edge is never mistaken for an incoming value;
      * a CALL clobber is POSITIONAL -- it only kills uses that follow it.
        Flat call-clobbering wipes out the entire signal (every function with
        a `bl` reports no incoming registers at all); ignoring calls entirely
        makes every stored return value look like a parameter.
    """
    insns = _decode(lines)
    written = {d for m, d, _, _ in insns if d and m not in CALLS}
    incoming, clobbered = set(), set()
    for mnem, dst, srcs, sym in insns:
        for r in srcs:
            if r not in written and r not in clobbered:
                incoming.add(r)
        if mnem in CALLS and not (sym and PRESERVING.match(sym)):
            clobbered.update("r%d" % i for i in range(3, 13))
            clobbered.update("f%d" % i for i in range(1, 14))
    return written, incoming


def incoming_regs(obj, symbol):
    lines = disasm(obj, symbol)
    if not lines:
        return None
    _, incoming = analyze(lines)
    return {r for r in incoming if r in ARGS}


# --------------------------------------------------------------------------
# our side: declared signature -> PPC EABI register assignment
# --------------------------------------------------------------------------

def typedef_map():
    """name -> underlying type text, for `typedef X name;` across the tree."""
    out = {}
    pat = re.compile(r"\btypedef\s+([^;{}()]+?)\s*\**\s*(\w+)\s*;")
    ptr = re.compile(r"\btypedef\s+([^;{}()]+?\*+)\s*(\w+)\s*;")
    struct = re.compile(r"\btypedef\s+(struct|union)\b[^;]*?\}\s*(\w+)\s*;",
                        re.S)
    for base in ("include", "src"):
        for r, _, fs in os.walk(os.path.join(ROOT, base)):
            for f in fs:
                if not f.endswith((".h", ".c")):
                    continue
                try:
                    t = open(os.path.join(r, f), errors="replace").read()
                except OSError:
                    continue
                for m in struct.finditer(t):
                    out.setdefault(m.group(2), "struct{}")
                for m in ptr.finditer(t):
                    out.setdefault(m.group(2), m.group(1))
                for m in pat.finditer(t):
                    out.setdefault(m.group(2), m.group(1))
    return out


def split_params(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def extract_signature(text, name):
    """-> (return_type, [param_texts], variadic, (pstart, pend)) for a
    DEFINITION, else None.  The span is the parameter-list text, so callers
    (notably --selftest) can splice a parameter out of the DEFINITION rather
    than out of whatever prototype happens to appear first in the file."""
    for m in re.finditer(r"\b%s\s*\(" % re.escape(name), text):
        i, depth = m.end() - 1, 0
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        params = text[m.end():i]
        j = i + 1
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        knr = {}
        if j < len(text) and text[j] != "{":
            # K&R definition: `int f(a, b) int a; float b; { ... }`.  The
            # parameter list is bare names and the types follow.
            k, decls = j, []
            while k < len(text) and text[k] != "{":
                sc = text.find(";", k)
                if sc < 0 or text.find("{", k) < sc:
                    break
                decls.append(text[k:sc])
                k = sc + 1
                while k < len(text) and text[k] in " \t\r\n":
                    k += 1
            if k >= len(text) or text[k] != "{" or not decls:
                continue
            for d in decls:
                d = d.strip()
                nm = re.findall(r"(\w+)\s*(?:\[[^\]]*\])?\s*$", d)
                for one in split_params(d):
                    nm = re.findall(r"(\w+)\s*(?:\[[^\]]*\])?\s*$", one.strip())
                    if nm:
                        knr[nm[0]] = one.strip()
                base = d.split(",")[0]
                for extra in d.split(",")[1:]:
                    e = extra.strip().rstrip()
                    n2 = re.findall(r"(\w+)\s*$", e)
                    if n2:
                        knr[n2[0]] = re.sub(r"\w+\s*$", "", base) + e
            j = k
        if j >= len(text) or text[j] != "{":
            continue  # a call or a prototype, not a definition
        ls = text.rfind("\n", 0, m.start()) + 1
        ret = text[ls:m.start()].strip()
        if not ret or "=" in ret or ret.endswith(("&&", "||", ",")):
            continue
        ps = split_params(params)
        if knr:
            ps = [knr.get(p.strip(), "int " + p.strip()) for p in ps]
        variadic = any(p == "..." for p in ps)
        ps = [p for p in ps if p != "..."]
        if len(ps) == 1 and re.fullmatch(r"void", ps[0]):
            ps = []
        return ret, ps, variadic, (m.end(), i)
    return None


def resolve(t, tds, depth=0):
    if depth > 8:
        return t
    base = re.sub(r"\b(const|volatile|static|register|struct|union)\b", " ", t)
    base = base.strip()
    if "*" in base or "[" in base:
        return base
    if base in tds:
        return resolve(tds[base], tds, depth + 1)
    return base


def kind(param, tds):
    """-> 'FPR' | 'GPR' | 'GPR2' | 'UNKNOWN'"""
    t = re.sub(r"\[[^\]]*\]", "*", param)
    t = resolve(t, tds)
    if "*" in t or "(" in t:
        return "GPR"
    if FLOAT_T.search(t):
        return "FPR"
    if LONGLONG_T.search(t):
        return "GPR2"
    if "struct{}" in t or re.search(r"\bstruct\b", t):
        return "UNKNOWN"
    if INT_T.search(t):
        return "GPR"
    return "UNKNOWN"


def assigned_regs(ret, params, tds, variadic=False):
    """-> (set of registers the declared signature accounts for, unresolved).

    A variadic function accounts for EVERY remaining argument register: MWCC
    spills the whole tail of the ABI into the va_list save area, so r7-r10 and
    f1-f8 all read as incoming.  Without this, every printf-alike is a hit.
    """
    g, f, regs, unresolved = 0, 0, set(), []
    if kind(ret, tds) == "UNKNOWN" and "*" not in ret:
        # a struct returned BY VALUE consumes r3 as a hidden result pointer
        g += 1
    for p in params:
        k = kind(p, tds)
        if k == "FPR":
            if f < len(FPR_ARGS):
                regs.add(FPR_ARGS[f])
            f += 1
        elif k == "GPR2":
            if g % 2:
                g += 1
            for _ in range(2):
                if g < len(GPR_ARGS):
                    regs.add(GPR_ARGS[g])
                g += 1
        else:
            if k == "UNKNOWN":
                unresolved.append(p)
            if g < len(GPR_ARGS):
                regs.add(GPR_ARGS[g])
            g += 1
    if variadic:
        regs.update(GPR_ARGS[g:])
        regs.update(FPR_ARGS[f:])
    return regs, unresolved


# --------------------------------------------------------------------------

def build_index(version="GSAE01"):
    build = os.path.join(ROOT, "build", version)
    report = json.load(open(os.path.join(build, "report.json")))
    idx = {}
    for unit in report["units"]:
        src = unit["metadata"].get("source_path")
        if not src:
            continue
        rel = src[4:] if src.startswith("src/") else src
        tgt = os.path.join(build, "obj", rel[:-2] + ".o")
        if not os.path.isfile(tgt):
            continue
        for fn in unit.get("functions", []):
            idx[fn["name"]] = {
                "unit": unit["name"], "src": os.path.join(ROOT, src),
                "obj": tgt, "size": int(fn["size"]),
                "pct": fn.get("fuzzy_match_percent", 0.0),
                "unit_pct": unit["measures"]["fuzzy_match_percent"],
            }
    return idx


def _source_chain(path):
    """The file itself, then every .c it #includes (group-file pattern)."""
    out = [path]
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return out
    for m in re.finditer(r'#\s*include\s+"([^"]+\.c)"', text):
        cand = os.path.normpath(os.path.join(os.path.dirname(path), m.group(1)))
        if os.path.isfile(cand):
            out.append(cand)
            continue
        cand = os.path.normpath(os.path.join(ROOT, "src", m.group(1)))
        if os.path.isfile(cand):
            out.append(cand)
    return out


def check(entry, tds, src_override=None):
    """-> dict describing the verdict for one function."""
    inc = incoming_regs(entry["obj"], entry["sym"])
    if inc is None:
        return {"status": "no target body"}
    path = src_override or entry["src"]
    sig = None
    # A unit's source_path is often a GROUP file that only #includes the real
    # translation units, so the definition is one level down.
    for p in _source_chain(path):
        try:
            text = open(p, errors="replace").read()
        except OSError:
            continue
        sig = extract_signature(text, entry["sym"])
        if sig:
            break
    if sig is None:
        return {"status": "no definition found", "incoming": sorted(inc)}
    ret, params, variadic, _ = sig
    regs, unresolved = assigned_regs(ret, params, tds, variadic)
    missing = inc - regs
    return {
        "status": "hit" if missing else "ok",
        "incoming": sorted(inc, key=_rk), "assigned": sorted(regs, key=_rk),
        "missing": sorted(missing, key=_rk), "variadic": variadic,
        "unresolved": unresolved, "ret": ret, "params": params,
    }


def _rk(r):
    return (r[0], int(r[1:]))


def selftest():
    """Fault-inject: strip a DECLARED parameter and require the hit to appear.

    Each case is run twice -- unmodified (must be clean) and with the
    parameter deleted (must flag exactly the register the EABI would have
    assigned to it).  A screen that only ever passes has not been tested.
    """
    ok = True

    def expect(label, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print("  [%s] %-52s got %-16s want %s"
              % ("PASS" if good else "FAIL", label, got, want))

    tds = typedef_map()
    idx = build_index()

    # (symbol, param text to delete, register that should then be missing)
    cases = [
        ("walkGroupFn_800db3e4", "u32 currentWalkGroupIndex", ["r5"]),
        ("MoonSeedBush_init", "int data", ["r4"]),
        ("dll_CB_moveHandler0", "u8* obj", ["r4"]),
        # variadic tail: dropping `...` must resurrect the whole ABI tail
        ("debugPrintfxy", "...",
         ["f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8",
          "r7", "r8", "r9", "r10"]),
    ]
    scratch = os.environ.get("TMPDIR", "/tmp")
    for sym, param, want_missing in cases:
        if sym not in idx:
            print("  [SKIP] %s not in report index" % sym)
            continue
        e = dict(idx[sym], sym=sym)
        base = check(e, tds)
        expect("%s as declared" % sym, base["status"], "ok")
        expect("  ...covers its incoming regs",
               set(base["incoming"]) - set(base["assigned"]), set())

        defsrc = next((p for p in _source_chain(e["src"])
                       if extract_signature(
                           open(p, errors="replace").read(), sym)), e["src"])
        text = open(defsrc, errors="replace").read()
        sig = extract_signature(text, sym)
        ps, pe = sig[3]
        raw = split_params(text[ps:pe])
        kept = [p for p in raw if p != param]
        if len(kept) == len(raw):
            expect("  ...FAULT INJECTED (param %r removed)" % param,
                   "not-injected", "injected")
            continue
        broken = text[:ps] + ", ".join(kept) + text[pe:]
        p = os.path.join(scratch, "mpc_selftest_%s.c" % sym)
        open(p, "w").write(broken)
        hit = check(e, tds, src_override=p)
        os.unlink(p)
        expect("  ...without %r -> flagged" % param,
               (hit["status"], hit["missing"]), ("hit", want_missing))

    # Definition-shape coverage.  Both of these were silently "no definition
    # found" -- a K&R-style definition, and a symbol whose unit source_path is
    # a GROUP file that only #includes the real translation unit.
    for sym, why in (("mapLoadBlocksFn_800685cc", "K&R definition"),
                     ("NW_mammoth_init", "definition behind a group #include")):
        if sym in idx:
            r = check(dict(idx[sym], sym=sym), tds)
            expect("%s (%s) is screened" % (sym, why),
                   r["status"] in ("ok", "hit"), True)

    # A branch TARGET ADDRESS that spells a register name must not decode as
    # one.  Fault-inject the exact objdump line shape that caused it.
    call_line = "      f0:\t48 00 00 01 \tbl      f4 <sym+0x48>"
    expect("`bl f4 <sym>` decodes no register operand",
           _decode([call_line])[0][2], [])
    expect("  ...while a real fpr operand still decodes",
           _decode(["      f0:\t00 \tfadds   f4,f8,f9"])[0][2], ["f8", "f9"])

    # `bl` must clobber the volatile bank.  Fault-inject by demoting `bl` back
    # to a plain branch and confirming the false positive returns.
    if "hwInitIrq" in idx:
        e = dict(idx["hwInitIrq"], sym="hwInitIrq")
        expect("hwInitIrq (void, stores a bl result) -> ok",
               check(e, tds)["status"], "ok")
        global CALLS
        saved, CALLS = CALLS, ("bctrl", "blrl")
        try:
            expect("  ...with `bl` demoted to a branch -> false positive",
                   check(e, tds)["missing"], ["r3"])
        finally:
            CALLS = saved

    # the un-guarded form of this screen (compare against NOTHING) must light
    # up on the very same functions -- that is the over-report being fixed.
    over = 0
    for sym, _, _ in cases:
        if sym in idx:
            e = dict(idx[sym], sym=sym)
            if incoming_regs(e["obj"], sym):
                over += 1
    expect("unguarded screen would over-report all controls", over, len(cases))

    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("symbol", nargs="?")
    ap.add_argument("-v", "--version", default="GSAE01")
    ap.add_argument("--all", action="store_true",
                    help="sweep every function in a sub-100 unit")
    ap.add_argument("--unit", help="restrict --all to units matching this")
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    tds = typedef_map()
    idx = build_index(args.version)

    if args.symbol:
        if args.symbol not in idx:
            sys.exit("unknown symbol: %s" % args.symbol)
        e = dict(idx[args.symbol], sym=args.symbol)
        r = check(e, tds)
        print(json.dumps(r, indent=2))
        return

    if not args.all:
        sys.exit("give a symbol, or --all")

    hits, stats, unscreened = [], {}, {}
    for sym, e in sorted(idx.items()):
        if e["unit_pct"] >= 100.0 or e["pct"] >= 100.0:
            continue
        if args.unit and args.unit not in e["unit"]:
            continue
        if e["size"] < args.min_size:
            continue
        r = check(dict(e, sym=sym), tds)
        stats[r["status"]] = stats.get(r["status"], 0) + 1
        if r["status"] == "hit":
            hits.append((sym, e, r))
        elif r["status"] != "ok":
            unscreened.setdefault(r["status"], []).append(sym)

    print("SCREENED: %d functions" % sum(stats.values()))
    for k, v in sorted(stats.items(), key=lambda kv: -kv[1]):
        print("  %-22s %4d" % (k, v))
    for k, syms in sorted(unscreened.items()):
        print("  NOT SCREENED (%s): %s" % (k, ", ".join(sorted(syms))))
    print()
    hits.sort(key=lambda h: -(100.0 - h[1]["pct"]) / 100.0 * h[1]["size"])
    for sym, e, r in hits:
        print("%-34s %-38s %6d %8.4f  missing=%s  incoming=%s assigned=%s%s"
              % (e["unit"], sym, e["size"], e["pct"], r["missing"],
                 r["incoming"], r["assigned"],
                 "  UNRESOLVED=%s" % r["unresolved"] if r["unresolved"] else ""))


if __name__ == "__main__":
    main()
