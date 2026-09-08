#!/usr/bin/env python3
"""Rank non-matching functions by how few instruction words actually differ.

bandscreen.py answers "is the saved band steerable"; this answers "how close is
this function to byte-exact, and is the residual a shape change or a recolour".
For each non-matching function it disassembles the target and our object,
compares instruction words positionally, and reports:

    ndiff   words that differ at all
    struc   of those, how many changed MNEMONIC, plus any length difference

A low ndiff with struc == 0 is an operand-level difference; inspect data bases
and relocation targets as well as register allocation. A low ndiff with
struc > 0 is a real shape difference, which is where the source levers apply.
#nm is how many functions in the unit still differ, so #nm == 1 means matching
this one function flips the whole unit.

Relocation normalisation: a word carrying a relocation is compared with the
reloc-affected bitfield masked out and the reloc target reduced to a canonical
token (anonymous @N constants, lbl_* labels and section symbols all become
POOL), so an @N-vs-lbl_ pool naming difference or a baked-vs-relocated field
(carved target objects bake the final bits, ours carry the reloc) no longer
counts as a differing word. Non-data named targets still differ. Data-target
identity is deliberately outside this coarse shape comparison; objdiff and
resolved relocation audits remain necessary. Big-endian 16-bit relocations
may identify the immediate at instruction+2 rather than the instruction word.
--raw restores the old raw-byte comparison.
"""
import argparse
import difflib
import json
import re
import subprocess
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OD = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")

INSN_RE = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){4})\s*(\S+)')
RELOC_RE = re.compile(r'^\s*([0-9a-f]+):\s+(R_PPC\S+)\s+(\S+)')

# Bits the linker rewrites for each relocation type; everything else in the
# word (opcode, registers) still has to match.
RELOC_MASKS = {
    "R_PPC_EMB_SDA21": 0x001FFFFF,
    "R_PPC_REL24": 0x03FFFFFC,
    "R_PPC_ADDR24": 0x03FFFFFC,
    "R_PPC_REL14": 0x0000FFFC,
    "R_PPC_ADDR14": 0x0000FFFC,
    "R_PPC_ADDR16": 0x0000FFFF,
    "R_PPC_ADDR16_LO": 0x0000FFFF,
    "R_PPC_ADDR16_HI": 0x0000FFFF,
    "R_PPC_ADDR16_HA": 0x0000FFFF,
    "R_PPC_EMB_SDA2REL": 0x0000FFFF,
    "R_PPC_SDAREL16": 0x0000FFFF,
}

POOL_SYM_RE = re.compile(r'^(@\d+|lbl_[0-9A-Fa-f]{8}|\.[A-Za-z0-9_.]+)$')
SDA_RELOCS = {"R_PPC_EMB_SDA21", "R_PPC_EMB_SDA2REL", "R_PPC_SDAREL16"}
DATA_SECTIONS = {".data", ".sdata", ".sdata2", ".rodata", ".bss", ".sbss", ".sbss2",
                 ".ctors", ".dtors"}

_symsec_cache = {}


def relocation_belongs_to_instruction(instruction_address, relocation_address, relocation_type):
    """Match either a word relocation or a big-endian immediate-halfword relocation."""
    if relocation_address == instruction_address:
        return True
    return (relocation_address == instruction_address + 2
            and RELOC_MASKS.get(relocation_type) == 0xFFFF)


def sym_sections(obj):
    """symbol name -> section, from the object's symbol table."""
    if obj in _symsec_cache:
        return _symsec_cache[obj]
    out = subprocess.run([OD, "-t", obj], capture_output=True, text=True).stdout
    secs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and re.match(r'^[0-9a-f]{8}$', parts[0]):
            secs[parts[-1]] = parts[-3]
    _symsec_cache[obj] = secs
    return secs


def canon_sym(sym, rtype, secs):
    base = sym.split("+")[0]
    if rtype in SDA_RELOCS or POOL_SYM_RE.match(base) or secs.get(base) in DATA_SECTIONS:
        return "POOL"
    return sym


def words(obj, sym, raw=False):
    """[(diff key, mnemonic, hex, reloc type, canonical reloc target), ...]."""
    out = subprocess.run([OD, "-M", "gekko", "-drz", "--disassemble=" + sym, obj],
                         capture_output=True, text=True).stdout
    got = []
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if m and len(m.group(2)) == 12:
            got.append([m.group(2), m.group(3), None, None, int(m.group(1), 16)])
            continue
        m = RELOC_RE.match(line)
        if m and got and relocation_belongs_to_instruction(
                got[-1][4], int(m.group(1), 16), m.group(2)):
            got[-1][2] = m.group(2)
            got[-1][3] = m.group(3)
    secs = None
    res = []
    for hexs, mnem, rtype, rsym, _ in got:
        if raw or rtype is None:
            key = hexs
            tok = None
        else:
            if secs is None:
                secs = sym_sections(obj)
            word = int(hexs.replace(" ", ""), 16)
            mask = RELOC_MASKS.get(rtype, 0xFFFFFFFF)
            tok = canon_sym(rsym, rtype, secs)
            key = "%08x %s" % (word & ~mask, tok)
        res.append((key, mnem, hexs, rtype, tok))
    return res


def reloc_equal(wa, wb):
    """True when two words differ only in reloc-rewritten bits: one side baked
    the final field (carved object), the other left it zeroed under a reloc."""
    ra, rb = wa[3], wb[3]
    if ra is None and rb is None:
        return False
    mask = 0
    if ra is not None:
        mask |= RELOC_MASKS.get(ra, 0xFFFFFFFF)
    if rb is not None:
        mask |= RELOC_MASKS.get(rb, 0xFFFFFFFF)
    va = int(wa[2].replace(" ", ""), 16) & ~mask
    vb = int(wb[2].replace(" ", ""), 16) & ~mask
    if va != vb:
        return False
    if ra is not None and rb is not None:
        return wa[4] == wb[4]
    return True


def fn_diff(target_obj, base_obj, sym, raw=False):
    """(ndiff, struc, len_a, len_b) or None when either side is missing."""
    a = words(target_obj, sym, raw)
    b = words(base_obj, sym, raw)
    if not a or not b:
        return None
    sm = difflib.SequenceMatcher(None, [w[0] for w in a], [w[0] for w in b],
                                 autojunk=False)
    diff = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if not raw and tag == "replace" and i2 - i1 == j2 - j1:
            for k in range(i2 - i1):
                if not reloc_equal(a[i1 + k], b[j1 + k]):
                    diff.append(i1 + k)
        else:
            diff.extend(range(i1, i2 if i2 > i1 else i1 + 1))
    n = min(len(a), len(b))
    struc = sum(1 for i in diff if i < n and a[i][1] != b[i][1]) + abs(len(a) - len(b))
    return len(diff), struc, len(a), len(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-size", type=int, default=500,
                    help="ignore functions smaller than this many bytes")
    ap.add_argument("--max-ndiff", type=int, default=0,
                    help="only show functions with at most this many differing words (0 = no limit)")
    ap.add_argument("--sole", action="store_true",
                    help="only functions that are the last straggler in their unit")
    ap.add_argument("--raw", action="store_true",
                    help="old behaviour: diff raw word bytes with no relocation normalisation")
    args = ap.parse_args()

    report = json.load(open(os.path.join(ROOT, "build/GSAE01/report.json")))
    cfg = json.load(open(os.path.join(ROOT, "objdiff.json")))
    by_name = {u["name"].replace("\\", "/"): u for u in cfg["units"]}

    rows = []
    for unit in report["units"]:
        if unit.get("metadata", {}).get("auto_generated"):
            continue
        cu = by_name.get(unit["name"].replace("\\", "/"))
        if not cu or not cu.get("base_path"):
            continue
        fns = [f for f in (unit.get("functions") or []) if f]
        remaining = sum(1 for f in fns if f.get("fuzzy_match_percent", 0.0) < 100)
        if args.sole and remaining != 1:
            continue
        for f in fns:
            fuzzy = f.get("fuzzy_match_percent", 0.0)
            size = int(f.get("size", 0))
            if fuzzy >= 100.0 or size < args.min_size:
                continue
            got = fn_diff(os.path.join(ROOT, cu["target_path"]),
                          os.path.join(ROOT, cu["base_path"]), f["name"], args.raw)
            if got is None:
                continue
            ndiff, struc, _, _ = got
            if args.max_ndiff and ndiff > args.max_ndiff:
                continue
            rows.append((size, fuzzy, ndiff, struc, unit["name"], f["name"], remaining))

    rows.sort(reverse=True)
    print("%6s %9s %5s %5s %4s  %s" % ("size", "fuzzy", "ndiff", "struc", "#nm", "fn"))
    for size, fuzzy, ndiff, struc, unit, fn, remaining in rows:
        print("%6d %9.5f %5d %5d %4d  %-42s %s" % (size, fuzzy, ndiff, struc, remaining, fn, unit))


if __name__ == "__main__":
    main()
