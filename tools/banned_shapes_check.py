#!/usr/bin/env python3
"""Scan game code for the CLAUDE.md banned constructs, so the ban self-enforces.

Scope is GAME CODE ONLY -- src/main/, src/track/, src/dlls/. The third-party
library trees are exempt by policy; they legitimately carry pragmas, gotos,
__declspec and lbl_ constants, so scanning them would produce nothing but false
positives: src/dolphin/ (the SDK), src/musyx/ (Factor 5's audio runtime) and
src/Runtime.PPCEABI.H/ (the Metrowerks MSL runtime).

Every directory under src/ is either scanned or exempt, and the self-test
asserts it, so a newly added library tree cannot slip through unaudited and
unlabelled.

Nine pattern classes, each carrying its citation:

  PRAGMA          any #pragma in a game TU. Per-function pragma sandwiches of
                  every kind were purged repo-wide; pragmas may only be
                  configured at TU level via configure.py cflags.
  GOTO            write structured control flow instead.
  DECLSPEC_SECTION  __declspec(section ...) and any section-forcing placement.
  VOLATILE_PUN    volatile / *(volatile T*)& puns used to block CSE or hoisting.
                  volatile is legal ONLY for genuine hardware/interrupt
                  semantics, so a write through a hardware ADDRESS (the GX FIFO
                  at 0xCC008000) or a WGPipe-style pipe macro is allowed. The
                  banned shape takes the address of a C object: *(volatile T*)&x.
  VOLATILE_DECL   the DECLARATION form of the same hack: a file-scope volatile
                  object of FLOATING-POINT type. Genuine volatiles in this tree
                  are integer status flags written from a DVD/ARQ/retrace
                  callback, or a PPCWGPipe mapped at a hardware address; a
                  volatile f32 is a CSE/hoist blocker on ordinary data. Scoped to
                  file scope on purpose: an indented `volatile float y;` local is
                  the project's extern-inline-sqrtf return-slot idiom, which is
                  how sqrtf is written and is not a hack.
  REGISTER_ASM    dummy global-register reservations such as
                  register int unused asm("r14"), whose only purpose is to
                  remove a register from MWCC's allocator.
  LBL_CONST_DEF   pool-reconstruction consts: an lbl_8XXXXXXX-named SCALAR const
                  definition (or the const union { f32 f; } disguise) that exists
                  to force a pool symbol. Write the plain literal instead.
                  NOTE: an lbl_-named ARRAY or struct table is NOT this ban -- it
                  is real data whose name has not been recovered yet. Only scalar
                  definitions are flagged (an aggregate is told apart by its brace
                  initialiser), and --strict-lbl additionally reports arrays and
                  struct tables as naming debt (informational, never gating).
  SINGLE_ELEM_CONST_ARRAY
                  const T name[1] = {...} whose only reads are name[0] -- a
                  one-element array written to pin a pool slot. Two-pass: the
                  definition regex, then a reads census over the whole tree.
                  KEYED ON THE DEFINITION, because the definition is what makes
                  it the banned construct; the reads census only CLASSIFIES:
                  read only as name[0] -> pool anchor; NEVER READ -> anchor AND
                  dead (the purest form, and the one a reads-keyed check silently
                  misses); indexed or otherwise used -> a real array, not this
                  shape. ALLOWED EXCEPTION: a genuine cross-TU object, and the
                  ONLY evidence for one is a reference from a DIFFERENT source
                  file. Presence in config/GSAE01/symbols.txt is NOT that
                  evidence -- the splitter emits every retail data symbol there,
                  statics included, so the file carries no linkage information.
                  Reading it as linkage once hid 14 real violations, the code
                  has not done so for some time, and the self-test pins the
                  regression; this paragraph said otherwise until now.
                  EXTENT: keyed on `[1]` written literally, so a pin widened to
                  `[2]` and still read only at [0] is outside the pattern. The
                  two instances of that shape today (gAndrossBrainRenderScale,
                  gWmPlanetsZeroVecTemplate) are sized by the carve at 0x8 and
                  0x10, so they are real objects rather than evasions.
  UNCALLED_STATIC_FN
                  a static function definition that nothing in the tree calls,
                  not even transitively -- the phantom-function shape. MWCC emits
                  an unreferenced static and mwld strips it at link, so such a
                  function is invisible to every score gate: objdiff pairs our
                  functions against RETAIL functions by name, and a body that is
                  not in the DOL has no pair and is never scored. That makes the
                  shape a free place to park fabricated code whose only effect is
                  to mint .sdata2 literals in the order the carve wants.
                  IT IS NOT AUTOMATICALLY A HACK. Retail TUs really did carry
                  dead statics, and the pool proves it: MWCC does NOT intern a
                  file-scope const against a pool literal (declaring one emits a
                  SECOND word), so whenever a slot that live retail code also
                  loads sits AHEAD of the first live minter, only code that ran
                  before it can have minted it -- code mwld then stripped. Such a
                  reconstruction is evidence-backed and belongs in the baseline.
                  What this class exists to stop is the OTHER kind: a body that
                  mints nothing and moves no data byte, which is pure dead
                  weight. Detection is source-only and transitive (a cluster
                  reachable only from other uncalled statics is uncalled), so it
                  needs no build; adjudicate a new hit against the unit's pool
                  before accepting it. See docs/priced_classes.md.

Exit status: 0 when there are no hits beyond the baseline, 1 otherwise, so this
can gate. --baseline rewrites the baseline file from the current tree; hits
beyond baseline are regrowth and fail the gate.

  python3 tools/banned_shapes_check.py              # gate
  python3 tools/banned_shapes_check.py --list       # every hit, ignore baseline
  python3 tools/banned_shapes_check.py --baseline   # record current as accepted
  python3 tools/banned_shapes_check.py --self-test  # validate BOTH directions

--self-test is not optional decoration. This tool gates future work, so it
validates against ground truth in both directions before anyone trusts a census
from it: it must FIRE on the historical hacks recorded at the pre-hack-purge tag
(a real positive corpus of thousands of instances) and must stay SILENT on
src/dolphin and on the genuine hardware-volatile sites. A checker that reports
zero is indistinguishable from a checker that is broken -- which is exactly how
a shell word-splitting bug once made this very tree look clean on every
pattern. Never trust a zero without the positive control.
"""

import argparse
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools"))
from source_coverage_audit import live_sources  # noqa: E402
SCAN_ROOTS = ["src/main", "src/track", "src/dlls",
              "include/main", "include/dlls", "include/game", "include/track",
              "include/sys", "include/util",
              "include/global.h", "include/types.h"]
EXEMPT_ROOTS = ["src/dolphin", "src/musyx", "src/Runtime.PPCEABI.H",
                "include/dolphin", "include/musyx", "include/GBA",
                "include/OdemuExi2", "include/amcstubs",
                "include/PowerPC_EABI_Support", "include/Runtime.PPCEABI.H",
                "include/TRK_MINNOW_DOLPHIN",
                "include/dolphin.h", "include/math.h", "include/stdarg.h",
                "include/stddef.h", "include/stdlib.h", "include/string.h",
                "include/__ppc_eabi_linker.h"]
BASELINE = "tools/banned_shapes_baseline.txt"
SYMBOLS = "config/GSAE01/symbols.txt"

CITE = {
    "PRAGMA": "CLAUDE.md Banned constructs: any #pragma (TU-level cflags only)",
    "GOTO": "CLAUDE.md Banned constructs: goto -- write structured control flow",
    "DECLSPEC_SECTION": "CLAUDE.md Banned constructs: __declspec(section ...)",
    "VOLATILE_PUN": "CLAUDE.md Banned constructs: match-volatiles",
    "VOLATILE_DECL": "CLAUDE.md Banned constructs: match-volatiles (declaration form)",
    "REGISTER_ASM": "CLAUDE.md Banned constructs: dummy global-register reservations",
    "LBL_CONST_DEF": "CLAUDE.md Banned constructs: pool-reconstruction consts",
    "SINGLE_ELEM_CONST_ARRAY": "CLAUDE.md Banned constructs: pool-reconstruction consts (1-element pin)",
    "LBL_ARRAY_NAMING_DEBT": "informational: unrecovered name, NOT a ban",
    "UNCALLED_STATIC_FN": "CLAUDE.md Banned constructs: phantom literal-minter functions",
    "UNCALLED_STATIC_FN_SDK": "informational: dead static in an exempt root, NOT a ban",
}
INFORMATIONAL = ("LBL_ARRAY_NAMING_DEBT", "UNCALLED_STATIC_FN_SDK")

# An `extern T name[...];` declaration carries the symbol without using it. Counting
# it as a read made the census read "used as a real array" (the name is not followed
# by [0]) and, across files, as cross-TU linkage -- either way laundering a genuine
# pool anchor straight out of the report.
RE_EXTERN_DECL = re.compile(r"^\s*extern\b[^=]*;\s*$")
RE_PRAGMA = re.compile(r"^\s*#\s*pragma\b")
RE_GOTO = re.compile(r"(?<![\w.>])goto\s+[A-Za-z_]\w*\s*;")
# Both the raw attribute and the two `include/global.h` shims that expand to it --
# the ban is on APPLYING section forcing to an object, so a macro that spells the
# attribute is an evasion path, while global.h's own `#define` of it is not a use.
RE_DECLSPEC = re.compile(r"__declspec\s*\(\s*section\b|\bSECTION_(?:DATA|INIT)\b")
RE_DEFINE = re.compile(r"^\s*#\s*define\b")
# Either the immediate-deref form `*(volatile T*)&x` or the pointer form
# `volatile T *p = (volatile T *)&x;`, which launders the same hack through a
# named pointer and which the deref-only pattern could never see.  There are
# zero instances of the pointer form in game code, so the widening costs no
# baseline entries -- but a zero that no pattern could ever have disturbed is
# not evidence, which is the whole point of the per-class controls below.
RE_VOLATILE_CAST = re.compile(r"\*\s*\(\s*volatile\b|\(\s*volatile\b[^)]*\*\s*\)\s*&")
RE_REGISTER_ASM = re.compile(r"\bregister\b[^;]*\basm\s*\(")
# file-scope (column 0) volatile object of floating-point type
RE_VOLATILE_DECL = re.compile(
    r"^(?:extern\s+)?volatile\s+(?:const\s+)?(?:f32|f64|float|double)\b")
# scalar lbl_ const definition: no '[' before '=' -> not an array, and no
# brace initialiser after it -> not a struct table either. Both of those are
# real data whose name has not been recovered, which this class exempts.
RE_LBL_SCALAR = re.compile(
    r"^\s*(?:static\s+)?const\s+(?!union\b)[A-Za-z_]\w*\s*\*?\s*"
    r"(lbl_[0-9A-Fa-f]{8})\s*=(?!\s*\{)")
# the union disguise, including the inline `const union { f32 f; } lbl_ = ...`
# form whose member list carries a ';' of its own
RE_LBL_UNION = re.compile(r"^\s*(?:static\s+)?const\s+union\b.*?(lbl_[0-9A-Fa-f]{8})\s*=")
RE_LBL_ARRAY = re.compile(
    r"^\s*(?:static\s+)?const\s+[A-Za-z_]\w*\s*\*?\s*(lbl_[0-9A-Fa-f]{8})"
    r"\s*(?:\[|=\s*\{)")
RE_ONE_ELEM = re.compile(
    r"^\s*(?:static\s+)?const\s+[A-Za-z_]\w*\s*\*?\s*([A-Za-z_]\w*)\s*\[\s*1\s*\]\s*=")
# A function DEFINITION at column 0: a return type, then the name and '(', with
# no trailing ';' (that would be a prototype). Both the static and the exported
# form are collected -- the exported ones are needed as reference OWNERS so the
# transitive pass can tell a live caller from a dead one.
# `static inline` is deliberately NOT collected as a candidate: an inline that
# nothing calls is never expanded and never emitted, so it cannot be a phantom
# .text symbol. It is still collected as a reference OWNER.
RE_FN_DEF = re.compile(
    r"^(?P<static>static\s+)?(?P<inline>inline\s+)?(?!return\b|else\b|typedef\b)"
    r"[A-Za-z_]\w*(?:\s+\w+)*[\s*]+(?P<name>[A-Za-z_]\w*)\s*\(")

# A volatile cast is GENUINE hardware when it targets a hardware address or a
# write-gather pipe, rather than the address of a C object.
RE_HW_ADDR = re.compile(r"0x[Cc][Cc][0-9A-Fa-f]{5}")
RE_PIPE = re.compile(r"WG(?:Pipe|Fifo)", re.I)
RE_ADDR_OF_OBJECT = re.compile(r"\*\s*\(\s*volatile\b[^)]*\)\s*&"
                               r"|\(\s*volatile\b[^)]*\*\s*\)\s*&")


def is_c_source(path):
    # .cpp counts because src/Runtime.PPCEABI.H/__init_cpp_exceptions.cpp is
    # compiled into the DOL and a .c/.h filter was blind to it.  It is the
    # ONLY compiled .cpp; every other C-shaped file the build does not compile
    # is screened out by the liveness check in walk(), which asks
    # tools/source_coverage_audit.py -- build.ninja plus group #includes --
    # rather than trusting the extension.  The two assembled .s units stay
    # outside: a C-shape screen has nothing to say about assembly.  Every
    # never-compiled source is outside SCAN_ROOTS, so the GATING population
    # of the file-type gap is 0 either way.
    return path.endswith((".c", ".h", ".cpp"))


def walk(roots, base=REPO):
    live = None
    if os.path.normpath(base) == os.path.normpath(REPO):
        live = {os.path.normpath(p) for p in live_sources()}
    for root in roots:
        full = os.path.join(base, root)
        if os.path.isfile(full):
            # a root may name a single loose file (include/global.h)
            if is_c_source(full):
                yield os.path.relpath(full, base)
            continue
        for dirpath, _dirs, files in os.walk(full):
            for f in sorted(files):
                if not is_c_source(f):
                    continue
                p = os.path.join(dirpath, f)
                # headers are population regardless; a .c/.cpp is only
                # population if its text can reach the DOL
                if (live is not None and not f.endswith(".h")
                        and os.path.normpath(p) not in live):
                    continue
                yield os.path.relpath(p, base)


def strip_line_comment(line):
    i = line.find("//")
    return line[:i] if i >= 0 else line


def scan_file(rel, text, strict_lbl=False):
    """Return single-line hits as (rel, lineno, cls, snippet)."""
    hits = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = strip_line_comment(raw)
        if not line.strip():
            continue
        if RE_PRAGMA.search(line):
            hits.append((rel, n, "PRAGMA", raw.strip()))
        if RE_GOTO.search(line):
            hits.append((rel, n, "GOTO", raw.strip()))
        if RE_DECLSPEC.search(line) and not RE_DEFINE.match(line):
            hits.append((rel, n, "DECLSPEC_SECTION", raw.strip()))
        if RE_REGISTER_ASM.search(line):
            hits.append((rel, n, "REGISTER_ASM", raw.strip()))
        if RE_VOLATILE_DECL.match(line) and not (
                RE_HW_ADDR.search(line) or RE_PIPE.search(line)):
            hits.append((rel, n, "VOLATILE_DECL", raw.strip()))
        if RE_VOLATILE_CAST.search(line):
            hardware = RE_HW_ADDR.search(line) or RE_PIPE.search(line)
            pun = RE_ADDR_OF_OBJECT.search(line)
            if pun or not hardware:
                hits.append((rel, n, "VOLATILE_PUN", raw.strip()))
        m = RE_LBL_SCALAR.match(line) or RE_LBL_UNION.match(line)
        if m:
            hits.append((rel, n, "LBL_CONST_DEF", raw.strip()))
        elif strict_lbl and RE_LBL_ARRAY.match(line):
            hits.append((rel, n, "LBL_ARRAY_NAMING_DEBT", raw.strip()))
    return hits


def load_symbols(base=REPO):
    p = os.path.join(base, SYMBOLS)
    if not os.path.isfile(p):
        return set()
    names = set()
    with open(p, errors="ignore") as fh:
        for line in fh:
            m = re.match(r"\s*([A-Za-z_]\w*)\s*=", line)
            if m:
                names.add(m.group(1))
    return names


def scan_one_elem(files, base=REPO):
    """Two-pass check for `const T name[1] = {...}` pinned pool slots.

    Pass 1 finds definitions. Pass 2 censuses reads across the whole tree, so a
    symbol used as a real array (any subscript other than [0], or its bare name
    passed along) is not flagged. Cross-TU symbols are the allowed exception.
    """
    defs = []
    for rel, text in files.items():
        for n, raw in enumerate(text.splitlines(), 1):
            line = strip_line_comment(raw)
            m = RE_ONE_ELEM.match(line)
            if m:
                defs.append((rel, n, m.group(1), raw.strip()))
    if not defs:
        return []
    hits = []
    for rel, n, name, snippet in defs:
        zero_reads = other_reads = foreign = 0
        for orel, text in files.items():
            if name not in text:
                continue
            for idx, raw in enumerate(text.splitlines(), 1):
                if orel == rel and idx == n:
                    continue          # the definition itself
                line = strip_line_comment(raw)
                if RE_EXTERN_DECL.match(line):
                    continue      # a declaration is neither a read nor linkage
                for mm in re.finditer(r"\b" + re.escape(name) + r"\b", line):
                    rest = line[mm.end():]
                    if re.match(r"\s*\[\s*0\s*\]", rest):
                        zero_reads += 1
                    else:
                        other_reads += 1
                    if orel != rel:
                        foreign += 1
        # The DEFINITION shape is what makes this the banned construct; the reads
        # census only CLASSIFIES it. Keying on reads instead silently missed the
        # purest case -- a definition that is never read at all (its only purpose
        # is to occupy a pool slot).
        # symbols.txt presence is NOT cross-TU evidence: the splitter emits EVERY retail
        # data symbol there, statics included, so the file carries zero linkage
        # information (precedent: sIntersectUnused0 is in symbols.txt, defined in
        # src/track/intersect.c, and has zero external references). Only an actual
        # reference from a DIFFERENT source file proves a cross-TU object.
        if foreign:
            continue                                   # allowed cross-TU exception
        if other_reads:
            continue                                   # used as a real array
        note = " [never read -- dead pool anchor]" if not zero_reads else ""
        hits.append((rel, n, "SINGLE_ELEM_CONST_ARRAY", snippet + note))
    return hits


def _fn_defs(text):
    """[(lineno, name, is_static)] for every column-0 function definition."""
    out = []
    lines = text.splitlines()
    for i, raw in enumerate(lines, 1):
        line = strip_line_comment(raw)
        if not line or line[0].isspace() or line.rstrip().endswith(";"):
            continue
        if line.lstrip().startswith(("#", "/", "*", "}")):
            continue
        m = RE_FN_DEF.match(line)
        if not m:
            continue
        # a definition opens a body: '{' on this line, or on a later line that is
        # still part of the signature (a wrapped parameter list).
        j, seen = i - 1, 0
        while j < len(lines) and seen < 4:
            if "{" in strip_line_comment(lines[j]):
                out.append((i, m.group("name"),
                            bool(m.group("static")) and not m.group("inline")))
                break
            if strip_line_comment(lines[j]).rstrip().endswith(";"):
                break
            j += 1
            seen += 1
    return out


def scan_uncalled_statics(files):
    """Transitive census of static functions that nothing in the tree calls.

    A reference is attributed to the column-0 function definition that precedes
    it in the same file; a reference on a column-0 line is file scope (an
    initialiser table) and always counts as live. A static reachable only from
    other uncalled statics is itself uncalled, so the marking is iterated to a
    fixpoint -- a mutually-recursive dead cluster is caught whole.
    """
    defs = {}                      # name -> (rel, lineno)
    owners = {}                    # rel -> sorted [(lineno, name)]
    for rel, text in files.items():
        if rel.endswith(".h"):
            continue
        fns = _fn_defs(text)
        owners[rel] = [(ln, nm) for ln, nm, _st in fns]
        for ln, nm, st in fns:
            if st and nm not in defs:
                defs[nm] = (rel, ln)
    if not defs:
        return []
    callers = {n: set() for n in defs}       # name -> set of owner fns / None
    for rel, text in files.items():
        if not any(n in text for n in defs):
            continue
        own = owners.get(rel, [])
        for idx, raw in enumerate(text.splitlines(), 1):
            line = strip_line_comment(raw)
            if not line.strip():
                continue
            file_scope = not line[0].isspace()
            here = None
            for ln, nm in own:
                if ln <= idx:
                    here = nm
                else:
                    break
            for name in defs:
                drel, dln = defs[name]
                if rel == drel and idx == dln:
                    continue                  # the definition itself
                if not re.search(r"\b" + re.escape(name) + r"\b", line):
                    continue
                callers[name].add(None if file_scope else here)
    dead = {n for n in defs if not callers[n]}
    while True:
        grew = {n for n in defs
                if n not in dead and callers[n] and callers[n] <= dead}
        if not grew:
            break
        dead |= grew
    hits = []
    for name in sorted(dead):
        rel, ln = defs[name]
        text = files[rel].splitlines()
        hits.append((rel, ln, "UNCALLED_STATIC_FN", text[ln - 1].strip()))
    return hits


def _read(roots, base):
    files = {}
    for rel in walk(roots, base):
        try:
            with open(os.path.join(base, rel), errors="ignore") as fh:
                files[rel] = fh.read()
        except OSError:
            continue
    return files


def collect(roots=SCAN_ROOTS, base=REPO, strict_lbl=False):
    files = _read(roots, base)
    hits = []
    for rel, text in sorted(files.items()):
        hits += scan_file(rel, text, strict_lbl)
    hits += scan_one_elem(files, base)
    # The uncalled-function census runs over the WHOLE tree, not just the game
    # roots: src/dolphin and src/musyx are exempt from the BANS, but nothing
    # else in the tree screened them for dead code, so synth_jobs.c's
    # streamGainFromVolume sat unadjudicated. Widening the file set can only add
    # callers to a game-code static, never remove one (a static is file-local),
    # and the widening is measured to lose no previously-reported row. SDK rows
    # are reported under their own class and never gate: an exempt root is
    # exempt.
    if set(roots) == set(SCAN_ROOTS):
        wide = dict(files)
        wide.update(_read(EXEMPT_ROOTS, base))
    else:
        wide = files
    for rel, ln, _cls, snip in scan_uncalled_statics(wide):
        cls = ("UNCALLED_STATIC_FN_SDK"
               if rel.startswith(tuple(EXEMPT_ROOTS)) else "UNCALLED_STATIC_FN")
        hits.append((rel, ln, cls, snip))
    return sorted(hits, key=lambda h: (h[0], h[1], h[2]))


def key(h):
    return "%s:%d:%s" % (h[0], h[1], h[2])


def read_baseline():
    p = os.path.join(REPO, BASELINE)
    if not os.path.isfile(p):
        return set()
    out = set()
    with open(p) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(line)
    return out


def write_baseline(hits):
    p = os.path.join(REPO, BASELINE)
    with open(p, "w") as fh:
        fh.write("# tools/banned_shapes_check.py baseline -- accepted existing instances.\n")
        fh.write("# Anything NOT listed here is regrowth and fails the gate.\n")
        fh.write("# Shrink this file; never grow it.\n")
        for h in hits:
            fh.write(key(h) + "\n")
    return p


def report(hits, title):
    print("%s: %d" % (title, len(hits)))
    by = {}
    for h in hits:
        by.setdefault(h[2], []).append(h)
    for cls in sorted(by):
        print("  %-24s %4d   [%s]" % (cls, len(by[cls]), CITE.get(cls, "")))
        for rel, n, _c, snip in by[cls]:
            print("      %s:%d: %s" % (rel, n, snip[:100]))


def self_test():
    """Validate in BOTH directions before this tool is allowed to gate."""
    ok = True

    def chk(label, cond, detail=""):
        nonlocal ok
        if not cond:
            ok = False
        print("  %-56s %s %s" % (label, "PASS" if cond else "*** FAIL ***", detail))

    # NEGATIVE 1: the SDK is out of scope and must never appear in a GATING
    # result. The uncalled-function census now runs over the SDK too, but only
    # ever under the informational class -- an exempt root is exempt.
    hits = collect()
    chk("no gating result is inside an exempt root",
        not any(h[0].startswith(tuple(EXEMPT_ROOTS))
                for h in hits if h[2] not in INFORMATIONAL))

    # NEGATIVE 2: genuine hardware volatiles are not puns.
    hw = [h for h in hits if h[2] == "VOLATILE_PUN" and RE_HW_ADDR.search(h[3])
          and "&" not in h[3]]
    chk("genuine GX FIFO volatiles not flagged", not hw,
        "" if not hw else "leaked %d" % len(hw))

    # NEGATIVE 3: genuine interrupt/status volatiles (integer flags written from a
    # DVD/ARQ/retrace callback) and hardware pipes must never be flagged. This is
    # the reconciliation guard for the 48-vs-49 delta: the rule that catches
    # gCloudActionGlareQuadSize must not catch these.
    vd = [h for h in hits if h[2] == "VOLATILE_DECL"]
    leaked = [h for h in vd if re.search(r"\b(?:int|u8|u16|u32|s8|s16|s32|BOOL)\b", h[3])
              or RE_PIPE.search(h[3])]
    chk("interrupt/status + pipe volatiles not flagged", not leaked,
        "" if not leaked else "leaked %d" % len(leaked))

    # NEGATIVE 4: the extern-inline-sqrtf return slot is an indented LOCAL and is
    # not a file-scope declaration; it must not be flagged.
    chk("sqrtf volatile return-slot local not flagged",
        not [h for h in vd if h[3].startswith(("volatile float y", "volatile f32 root"))
             and h[3] != h[3].lstrip()])
    chk("VOLATILE_DECL pattern fires on a float file-scope volatile",
        bool(RE_VOLATILE_DECL.match("volatile f32 gX[2] = {1.0f, 0.0f};")))
    chk("VOLATILE_DECL pattern ignores an int file-scope volatile",
        not RE_VOLATILE_DECL.match("volatile int gFlag;"))

    # REGRESSION GUARD for the 48-vs-49 reconciliation: two independent scans
    # disagreed by one, and the delta was a one-element const array that is NEVER
    # READ. A reads-keyed check cannot see it, so the class is keyed on the
    # definition. This asserts the never-read variant stays caught.
    # Synthetic, so the guard survives the tree it guards: the instance it used
    # to name has since been purged, which silently turned the check red.
    synth = scan_one_elem({"src/main/_probe.c":
                           "static const f32 sNeverRead[1] = {1.0f};\n"},
                          base=os.path.join(REPO, "does_not_exist"))
    chk("never-read one-element const array is caught",
        len(synth) == 1 and synth[0][2] == "SINGLE_ELEM_CONST_ARRAY")
    chk("never-read variant is labelled as dead",
        bool(synth) and "never read" in synth[0][3])
    chk("one-element const array read as name[0] is caught",
        len(scan_one_elem({"src/main/_probe.c":
                           "static const f32 sPinned[1] = {1.0f};\n"
                           "void f(void) { g(sPinned[0]); }\n"},
                          base=os.path.join(REPO, "does_not_exist"))) == 1)
    chk("genuine indexed array is not caught",
        scan_one_elem({"src/main/_probe.c":
                       "static const f32 sReal[1] = {1.0f};\n"
                       "void f(int i) { g(sReal[i]); }\n"},
                      base=os.path.join(REPO, "does_not_exist")) == [])

    # UNCALLED_STATIC_FN, positive: use a synthetic cluster so the self-test does
    # not require the live tree to keep any real banned debt around. deadLeaf is
    # the transitive case -- it IS referenced, but only from another uncalled
    # static, so a non-transitive scan misses it.
    uc = [h for h in hits if h[2] == "UNCALLED_STATIC_FN"]
    synth_uc = scan_uncalled_statics({
        "src/main/_probe.c": (
            "static void deadLeaf(void) {\n"
            "}\n"
            "\n"
            "static void deadRoot(void) {\n"
            "    deadLeaf();\n"
            "}\n"
        )
    })
    chk("uncalled static caught", any("deadRoot" in h[3] for h in synth_uc))
    chk("transitive dead cluster caught",
        any("deadLeaf" in h[3] for h in synth_uc))

    # NEGATIVE: a plain static WITH call sites must never be flagged. MWCC
    # inlines these and still emits an out-of-line body that mwld strips, so they
    # look identical to a phantom in the object and are separated only by having
    # a caller in the source.
    called = ("wctemplebri_deformVertex", "LargeCrate_spawnPickup",
              "Obj_HeadingRadians", "DIMCannon_explodeBall")
    leaked_called = [h for h in uc if any(c in h[3] for c in called)]
    chk("plain static with call sites not flagged", not leaked_called,
        "" if not leaked_called else "leaked %d" % len(leaked_called))

    # NEGATIVE: an unused `static inline` emits no .text and is out of class.
    chk("unused static inline not flagged",
        not [h for h in uc if h[3].startswith("static inline")])

    # The SDK widening, in both directions. POSITIVE: use a synthetic exempt-root
    # dead static, because the checked-in SDK may become clean too.
    sdkuc = [h for h in hits if h[2] == "UNCALLED_STATIC_FN_SDK"]
    synth_sdk_uc = scan_uncalled_statics({
        "src/dolphin/_probe.c": "static void sdkDeadStatic(void) {\n}\n"
    })
    chk("the SDK census fires on a dead SDK static",
        any("sdkDeadStatic" in h[3] for h in synth_sdk_uc))
    chk("every SDK census row really is in an exempt root",
        all(h[0].startswith(tuple(EXEMPT_ROOTS)) for h in sdkuc))
    # NEGATIVE / NO-LOSS: widening the file set may only ADD callers, so no row
    # the narrow scan reported may disappear. A static is file-local, but the
    # census keys on the NAME, so an SDK file that happens to spell a game
    # static's name could have laundered it. Measured: it does not.
    narrow = {(h[0], h[1]) for h in scan_uncalled_statics(_read(SCAN_ROOTS, REPO))}
    widened = {(h[0], h[1]) for h in hits
               if h[2] in ("UNCALLED_STATIC_FN", "UNCALLED_STATIC_FN_SDK")}
    chk("widening loses no previously-reported row",
        not (narrow - widened), "(%d narrow, %d wide)" % (len(narrow), len(widened)))

    # .cpp coverage: uncompiled namesakes must stay OUTSIDE the population; dead
    # text screens nothing.
    cpp = [r for r in walk(EXEMPT_ROOTS) if r.endswith(".cpp")]
    chk("uncompiled .cpp namesakes stay outside the walker",
        all(not r.endswith("__ppc_eabi_init.cpp") for r in cpp),
        ", ".join(cpp))

    # POSITIVE: the SDK really does contain the shapes, so the patterns fire
    # when pointed at code that has them. This is the control that proves a
    # zero on game code means "clean", not "broken".
    sdk = collect(roots=EXEMPT_ROOTS)
    got = {h[2] for h in sdk}
    for cls in ("PRAGMA", "DECLSPEC_SECTION"):
        chk("pattern fires on SDK corpus: %s" % cls, cls in got)

    # POSITIVE, PER CLASS, SYNTHETIC. Five of the nine classes report ZERO on
    # game code, and a zero is only evidence if the pattern could have fired.
    # PRAGMA and DECLSPEC_SECTION are covered by the SDK corpus above and
    # VOLATILE_DECL by its own regex probes, but VOLATILE_PUN and REGISTER_ASM
    # had no control at all: their regexes could have rotted to never match and
    # nothing here or in the baseline would have moved. Every class now carries
    # a synthetic instance, so no class can report a silent zero.
    def fires(cls, line):
        return cls in {h[2] for h in scan_file("src/main/_probe.c", line)}

    for cls, line in (
            ("PRAGMA", "#pragma peephole off"),
            ("GOTO", "    goto done;"),
            ("DECLSPEC_SECTION",
             '__declspec(section ".sdata2") const f32 k = 1.0f;'),
            ("VOLATILE_PUN", "    *(volatile f32*)&sBlocker = x;"),
            ("VOLATILE_PUN",
             "    volatile f32 *q = (volatile f32 *)&sTable[i];"),
            ("VOLATILE_DECL", "volatile f32 gBlocker = 0.0f;"),
            ("REGISTER_ASM", 'register int unused asm("r14");'),
            ("REGISTER_ASM", 'static register void *sPin asm ("r31");'),
            ("LBL_CONST_DEF", "const f32 lbl_803E1234 = 1.0f;")):
        chk("pattern fires on a synthetic %s" % cls, fires(cls, line),
            line.strip()[:44])

    # ...and the matching NEGATIVES for the two newly-controlled classes, so the
    # widening that closed the pointer-form pun cannot start swallowing the
    # genuine hardware volatiles it is carved around.
    chk("genuine hardware volatile write not flagged as a pun",
        not fires("VOLATILE_PUN", "    *(volatile u32*)0xCC008000 = v;"))
    chk("write-gather pipe not flagged as a pun",
        not fires("VOLATILE_PUN", "    WGPipe.u32 = v;"))
    chk("a plain register local is not a register-asm reservation",
        not fires("REGISTER_ASM", "    register int i = 0;"))

    # POSITIVE: the historical purge corpus at pre-hack-purge.
    try:
        tag = subprocess.run(["git", "-C", REPO, "rev-parse", "-q", "--verify",
                              "pre-hack-purge^{commit}"],
                             capture_output=True, text=True)
        if tag.returncode == 0:
            out = subprocess.run(
                ["git", "-C", REPO, "grep", "-cE", r"^\s*#\s*pragma",
                 "pre-hack-purge", "--", "src/main/*.c"],
                capture_output=True, text=True).stdout
            total = sum(int(l.rsplit(":", 1)[1]) for l in out.splitlines() if ":" in l)
            chk("historical corpus has pragmas to catch", total > 100, "(%d)" % total)
        else:
            chk("pre-hack-purge tag present", False, "(tag missing -- corpus unavailable)")
    except Exception as exc:                                   # pragma: no cover
        chk("historical corpus reachable", False, str(exc))

    # SANITY: scanning nothing must yield nothing (guards the walker).
    # --- symbols.txt is not linkage evidence (regression guard) -----------------
    # The exemption used to read `if (name in symbols) or foreign`, which hid 14
    # real violations whose names merely appear in symbols.txt -- including
    # lbl_803E23C0, which the ban names BY NAME. The splitter lists every retail
    # data symbol, statics included, so presence there proves nothing.
    synth_neverread = {"a.c": "const f32 gSynthNeverRead[1] = {0.0f};\n"}
    synth_zeroread = {"a.c": "const f32 gSynthZeroRead[1] = {1.0f};\n"
                             "void f(void) { use(gSynthZeroRead[0]); }\n"}
    synth_realarray = {"a.c": "const f32 gSynthReal[1] = {1.0f};\n"
                              "void f(void) { g(gSynthReal); }\n"}
    synth_crosstu = {"a.c": "const f32 gSynthShared[1] = {1.0f};\n",
                     "b.c": "void f(void) { use(gSynthShared[0]); }\n"}
    r_never = scan_one_elem(synth_neverread)
    chk("synthetic never-read one-element array is caught", len(r_never) == 1)
    chk("never-read variant is labelled as dead",
        bool(r_never) and "never read" in r_never[0][3])
    chk("synthetic [0]-only read is caught", len(scan_one_elem(synth_zeroread)) == 1)
    chk("a genuine array use is NOT flagged", len(scan_one_elem(synth_realarray)) == 0)
    chk("a cross-TU referenced object is NOT flagged", len(scan_one_elem(synth_crosstu)) == 0)
    _syms = load_symbols()
    _sym_name = next(iter(_syms), "gSynthListedSymbol")
    _listed = scan_one_elem({"a.c": "const f32 %s[1] = {0.0f};\n" % _sym_name})
    chk("symbols.txt-listed but unreferenced instances ARE caught",
        bool(_listed), _sym_name)

    chk("empty scope yields empty result", collect(roots=["src/does_not_exist"]) == [])

    covered = [os.path.normpath(r) for r in SCAN_ROOTS + EXEMPT_ROOTS]
    src = os.path.join(REPO, "src")
    unlabelled = [d for d in sorted(os.listdir(src))
                  if os.path.isdir(os.path.join(src, d))
                  and os.path.join("src", d) not in covered
                  and any(True for _ in walk([os.path.join("src", d)]))]
    chk("every C source directory under src/ is scanned or exempt",
        not unlabelled, ", ".join(unlabelled))

    inc = os.path.join(REPO, "include")
    unlabelled_inc = [d for d in sorted(os.listdir(inc))
                      if os.path.isdir(os.path.join(inc, d))
                      and os.path.join("include", d) not in covered
                      and any(True for _ in walk([os.path.join("include", d)]))]
    chk("every header directory under include/ is scanned or exempt",
        not unlabelled_inc, ", ".join(unlabelled_inc))

    loose_inc = [f for f in sorted(os.listdir(inc))
                 if is_c_source(f)
                 and os.path.isfile(os.path.join(inc, f))
                 and os.path.join("include", f) not in covered]
    chk("every loose header at include/ root is scanned or exempt",
        not loose_inc, ", ".join(loose_inc))
    chk("global.h's own #define of the section shim is not a use",
        len(scan_file("h.h", '#define SECTION_DATA __declspec(section ".data")\n')) == 0)
    chk("the section shim used on an object IS flagged",
        [h[2] for h in scan_file("a.c", "SECTION_DATA int gThing;\n")] == ["DECLSPEC_SECTION"])

    synth_fwd = {"a.c": ("void f(void) {\n"
                         "    extern const f32 gSynthFwd[1];\n"
                         "    use(gSynthFwd[0]);\n"
                         "}\n"
                         "const f32 gSynthFwd[1] = {0.25f};\n")}
    chk("a forward extern declaration does not launder the definition",
        len(scan_one_elem(synth_fwd)) == 1)
    synth_hdr = {"a.c": "const f32 gSynthHdr[1] = {1.0f};\nvoid f(void){use(gSynthHdr[0]);}\n",
                 "h.h": "extern const f32 gSynthHdr[1];\n"}
    chk("a header declaration does not launder the definition",
        len(scan_one_elem(synth_hdr)) == 1)
    return ok


def main():
    ap = argparse.ArgumentParser(description="Gate game code against CLAUDE.md banned constructs.")
    ap.add_argument("--list", action="store_true", help="print every hit, ignoring the baseline")
    ap.add_argument("--baseline", action="store_true", help="rewrite the baseline from the current tree")
    ap.add_argument("--self-test", action="store_true", help="validate the checker in both directions")
    ap.add_argument("--strict-lbl", action="store_true",
                    help="also report lbl_-named arrays as naming debt (informational)")
    args = ap.parse_args()

    if args.self_test:
        print("banned_shapes_check self-test")
        ok = self_test()
        print("\nSELF-TEST %s" % ("PASSED" if ok else "FAILED"))
        return 0 if ok else 1

    hits = collect(strict_lbl=args.strict_lbl)
    informational = [h for h in hits if h[2] in INFORMATIONAL]
    hits = [h for h in hits if h[2] not in INFORMATIONAL]

    if args.baseline:
        p = write_baseline(hits)
        print("baseline written: %s (%d accepted instances)" % (p, len(hits)))
        report(hits, "recorded")
        return 0

    if args.list:
        report(hits, "all hits")
        if informational:
            report(informational, "informational (never gating)")
        return 0

    base = read_baseline()
    new = [h for h in hits if key(h) not in base]
    fixed = base - {key(h) for h in hits}
    print("scanned %d files under %s" % (
        sum(1 for _ in walk(SCAN_ROOTS)), ", ".join(SCAN_ROOTS)))
    print("hits=%d  baseline=%d  regrowth=%d  fixed-since-baseline=%d"
          % (len(hits), len(base), len(new), len(fixed)))
    if fixed:
        print("\n%d baseline entries no longer present -- shrink the baseline:" % len(fixed))
        for k in sorted(fixed):
            print("      %s" % k)
    if new:
        print()
        report(new, "REGROWTH (not in baseline)")
        print("\nThese are banned in game code. See CLAUDE.md 'Banned constructs' "
              "and docs/HACK_AUDIT.md.")
        return 1
    print("\nOK -- no banned-shape regrowth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
