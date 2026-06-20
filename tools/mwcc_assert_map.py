#!/usr/bin/env python3
"""Map mwcceppc.exe functions to source files via embedded assert(file,line) strings.

Strategy:
  - The compiler retains `Assertion (%s) failed in "%s" on line %d` style asserts.
  - Each assert call site does `push <line>; push offset <FILE.c>; push offset <cond>; call`.
  - We find every code reference to a source-filename string, attribute it to the
    enclosing function (nearest preceding call-target / prologue), and recover the
    line number from a nearby `push imm`.

Output: a function->source-file map with VAs you can feed to a debugger / Ghidra.
"""
import sys, re, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

PATH = sys.argv[1] if len(sys.argv) > 1 else "build/compilers/GC/2.0p1/mwcceppc.exe"

pe = pefile.PE(PATH, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase

# --- gather sections ---
sections = []
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode("latin1")
    va = base + s.VirtualAddress
    data = s.get_data()
    sections.append((name, va, data, s.Characteristics))

def va_to_section(va):
    for name, sva, data, _ in sections:
        if sva <= va < sva + len(data):
            return name, sva, data
    return None

# --- extract all null-terminated ASCII strings (>=2 chars) with their VA ---
str_at_va = {}            # va -> string
ascii_re = re.compile(rb"[\x20-\x7e]{2,}")
for name, sva, data, _ in sections:
    for m in ascii_re.finditer(data):
        s = m.group()
        # only count if null-terminated (real C string)
        end = m.end()
        if end < len(data) and data[end] == 0:
            str_at_va[sva + m.start()] = s.decode("latin1")

# source-file strings of interest
SRC_RE = re.compile(r"^[\w./\\-]+\.(c|cpp|h)$", re.I)
srcfile_vas = {va: s for va, s in str_at_va.items() if SRC_RE.match(s)}

# --- find executable section(s) and disassemble ---
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

IMAGE_SCN_MEM_EXECUTE = 0x20000000
text_secs = [(n, v, d) for (n, v, d, c) in sections if c & IMAGE_SCN_MEM_EXECUTE]

# Pass 1: linear sweep -> collect call rel32 targets (function starts) + all insns
# capstone's disasm() stops at the first undecodable byte; resync by +1 and continue.
call_targets = set()
insns = []   # (addr, size, mnemonic, op_str, imm_list)
for name, va, data in text_secs:
    off = 0
    n = len(data)
    while off < n:
        progressed = False
        for ins in md.disasm(data[off:], va + off):
            imms = [o.imm for o in ins.operands if o.type == CS_OP_IMM]
            insns.append((ins.address, ins.size, ins.mnemonic, ins.op_str, imms))
            if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == CS_OP_IMM:
                call_targets.add(ins.operands[0].imm)
            off = ins.address - va + ins.size
            progressed = True
        if not progressed:
            off += 1   # skip undecodable byte and resync

# prologue-based function starts: push ebp; mov ebp,esp  (55 8B EC)
prologue_starts = set()
for name, va, data in text_secs:
    i = 0
    while True:
        j = data.find(b"\x55\x8b\xec", i)
        if j < 0:
            break
        prologue_starts.add(va + j)
        i = j + 1

func_starts = sorted(call_targets | prologue_starts)

import bisect
def enclosing_func(addr):
    k = bisect.bisect_right(func_starts, addr) - 1
    if k >= 0:
        return func_starts[k]
    return None

# index insns by address for line-number recovery
insn_by_addr = {a: (a, sz, mn, ops, imms) for (a, sz, mn, ops, imms) in insns}
insn_addrs = [a for (a, *_ ) in insns]

# Pass 2: find references to source-file strings
# func_start -> {srcfile: set(lines)}
func_files = collections.defaultdict(lambda: collections.defaultdict(set))
file_funcs = collections.defaultdict(set)

for idx, (addr, sz, mn, ops, imms) in enumerate(insns):
    for imm in imms:
        if imm in srcfile_vas:
            srcfile = srcfile_vas[imm]
            fn = enclosing_func(addr)
            if fn is None:
                continue
            file_funcs[srcfile].add(fn)
            # recover line number: look at the immediately preceding push imm
            line = None
            for back in range(1, 4):
                if idx - back < 0:
                    break
                paddr, psz, pmn, pops, pimms = insns[idx - back]
                if pmn == "push" and pimms:
                    cand = pimms[0]
                    # plausible source line: small positive, not a string/code VA
                    if 0 < cand < 200000 and cand not in str_at_va:
                        line = cand
                        break
            func_files[fn][srcfile].add(line)

# --- report ---
BACKEND = ["Coloring.c", "InterferenceGraph.c", "SpillCode.c", "RegisterInfo.c",
           "Scheduler.c", "ValueNumbering.c", "PCodeListing.c",
           "IroCSE.c", "IroPropagate.c", "IroUnrollLoop.c",
           "LoopOptimization.c", "LoopDetection.c", "CodeGen.c", "ObjGen_PPC_EABI.c",
           "COptimizer.c", "IrOptimizer.c", "CIRTransform.c", "IroFlowgraph.c",
           "IroLinearForm.c", "IROUseDef.c", "IroRangePropagation.c", "VectorArraysToRegs.c"]

print(f"# mwcceppc assert-string function map")
print(f"# binary: {PATH}  image base: {base:#x}")
print(f"# {len(srcfile_vas)} source-file strings, {len(func_starts)} candidate function starts")
print(f"# {sum(len(v) for v in file_funcs.values())} (file,function) attributions\n")

def dump_file(srcfile):
    funcs = sorted(file_funcs.get(srcfile, []))
    if not funcs:
        print(f"## {srcfile}: (no code references found)\n")
        return
    print(f"## {srcfile}: {len(funcs)} functions")
    for fn in funcs:
        lines = sorted(l for l in func_files[fn][srcfile] if l is not None)
        lspan = f"  lines {min(lines)}-{max(lines)}" if lines else ""
        print(f"   func @ {fn:#010x}{lspan}")
    print()

# --- TU address-band inference -------------------------------------------
# MWCC lays out each .c's functions contiguously. The assert anchors bound the
# band; every call-target inside the band is (very likely) a function of that TU.
file_anchor_addrs = {f: sorted(s) for f, s in file_funcs.items()}
# Build global ordering of anchors to detect band overlaps.
anchor_list = sorted((a, f) for f, addrs in file_anchor_addrs.items() for a in addrs)

def tu_band(srcfile):
    a = file_anchor_addrs.get(srcfile)
    if not a:
        return None
    lo, hi = a[0], a[-1]
    # extend hi to the next function start after the last anchor (band end)
    k = bisect.bisect_right(func_starts, hi)
    band_hi = func_starts[k] if k < len(func_starts) else hi + 0x400
    return lo, band_hi

def funcs_in_band(lo, hi):
    i = bisect.bisect_left(func_starts, lo)
    j = bisect.bisect_left(func_starts, hi)
    return func_starts[i:j]

def dump_file_full(srcfile):
    band = tu_band(srcfile)
    anchors = set(file_anchor_addrs.get(srcfile, []))
    if band is None:
        print(f"## {srcfile}: (no assert anchors found)\n")
        return
    lo, hi = band
    allf = funcs_in_band(lo, hi)
    # cross-contamination check: anchors from OTHER files inside this band
    foreign = sorted({(a, f) for (a, f) in anchor_list if lo <= a < hi and f != srcfile})
    print(f"## {srcfile}: band {lo:#010x}-{hi:#010x}  "
          f"({len(anchors)} assert-anchored, {len(allf)} total funcs in band)")
    for fn in allf:
        tag = " <-- assert anchor" if fn in anchors else ""
        print(f"   func @ {fn:#010x}{tag}")
    if foreign:
        print(f"   !! WARNING: band also contains anchors from: "
              f"{sorted({f for _, f in foreign})}")
    print()

print("=" * 60)
print("BACKEND TUs (the matching-relevant passes)")
print("=" * 60)
print("# 'band' = inferred TU address range from assert anchors.")
print("# Functions without an anchor tag are inferred-same-TU (call-targets in band).\n")
for f in BACKEND:
    dump_file_full(f)

# --- Whole-.text TU partition --------------------------------------------
# Functions are emitted in source order, contiguous per TU. Using only .c anchors
# (drop .h header-inline noise), partition .text: each TU spans from its first
# anchor to the next TU's first anchor, absorbing its un-asserted trailing funcs.
c_files = {f: sorted(a) for f, a in file_anchor_addrs.items() if f.lower().endswith(".c")}
tu_min = sorted(((a[0], a[-1], f) for f, a in c_files.items()))  # (min,max,file)

# detect interleave (TU max crosses into the next TU's min) -> ambiguous boundary
partition = []   # (lo, hi, file, interleaved_bool)
for i, (lo, hi, f) in enumerate(tu_min):
    nxt = tu_min[i + 1][0] if i + 1 < len(tu_min) else (func_starts[-1] + 0x400)
    interleaved = hi >= nxt
    partition.append((lo, min(hi if interleaved else nxt, nxt), f, interleaved))

part_band = {f: (lo, hi, il) for (lo, hi, f, il) in partition}

print("=" * 60)
print("BACKEND TUs — EXTENDED bands (whole-.text partition)")
print("=" * 60)
print("# Band runs to the next TU's first anchor (absorbs un-asserted funcs).")
print("# '~' = inferred (no assert); interleaved bands flagged as AMBIGUOUS.\n")
for srcfile in BACKEND:
    pb = part_band.get(srcfile)
    if not pb:
        print(f"## {srcfile}: (no .c assert anchors)\n"); continue
    lo, hi, il = pb
    allf = funcs_in_band(lo, hi)
    anchors = set(file_anchor_addrs.get(srcfile, []))
    flag = "  *** AMBIGUOUS (interleaved with neighbour) ***" if il else ""
    print(f"## {srcfile}: band {lo:#010x}-{hi:#010x}  "
          f"({len(anchors)} anchored / {len(allf)} total){flag}")
    for fn in allf:
        print(f"   {'A' if fn in anchors else '~'} {fn:#010x}")
    print()

# global TU layout (address order) — useful for spotting where each pass lives
print("=" * 60)
print("FULL TU LAYOUT (.c files, address order)")
print("=" * 60)
for lo, hi, f, il in partition:
    n = len(funcs_in_band(lo, hi))
    flag = " AMBIG" if il else ""
    print(f"  {lo:#010x}-{hi:#010x}  {n:4d} funcs  {f}{flag}")

# summary table: every source file by #functions referencing it
print("\n" + "=" * 60)
print("ALL source files by assert-reference count")
print("=" * 60)
for srcfile, funcs in sorted(file_funcs.items(), key=lambda kv: -len(kv[1])):
    print(f"  {len(funcs):4d} funcs   {srcfile}")
