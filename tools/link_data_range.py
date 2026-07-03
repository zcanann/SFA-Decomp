#!/usr/bin/env python3
"""Derive the DOL address range of a unit's own data section, for reattributing
it in splits.txt so the unit can link (see docs/linking.md).

A 100%-matched unit often can't link because its built object emits a
.data/.sdata2/.rodata section the retail split never gave it. To fix, add the
range to the unit's splits.txt entry. This tool finds the range by correlating
relocations: for each symbol the built object defines in the target section, it
locates the retail object's .text relocation at the same instruction offset,
reads the real symbol name it points at, and looks up that symbol's address in
symbols.txt. base = symbol_address - built_symbol_offset.

Usage:
    python3 tools/link_data_range.py <src-obj> <retail-obj> <section>
    python3 tools/link_data_range.py build/GSAE01/src/main/dll/DIM/dll_01E0_dimboss.o \
            build/GSAE01/obj/main/dll/DIM/dll_01E0_dimboss.o .data

Caveats: shared .sdata2 constant pools and layout mismatches will produce a range
that overlaps another split or fails the link — the DOL SHA1 is the only proof.
"""
import re
import subprocess
import sys
from collections import Counter

OBJDUMP = "build/binutils/powerpc-eabi-objdump"
SYMBOLS = "config/GSAE01/symbols.txt"


def symbol_addresses():
    addr = {}
    for line in open(SYMBOLS):
        m = re.match(r"(\S+) = \.\w+:0x([0-9A-Fa-f]+);", line)
        if m:
            addr[m.group(1)] = int(m.group(2), 16)
    return addr


def section_defs(obj, section):
    """symbols defined in `section` of `obj` -> their offset"""
    out = subprocess.run([OBJDUMP, "-t", obj], capture_output=True, text=True).stdout
    defs = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5 and section in p:
            name = p[-1]
            if name != section:
                try:
                    defs[name] = int(p[0], 16)
                except ValueError:
                    pass
    return defs


def relocs(obj):
    out = subprocess.run([OBJDUMP, "-dr", obj], capture_output=True, text=True).stdout
    r = {}
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\s+(R_PPC\S+)\s+(\S+?)(?:\+0x([0-9a-f]+))?$", line)
        if m:
            r[(int(m.group(1), 16), m.group(2))] = (
                m.group(3),
                int(m.group(4), 16) if m.group(4) else 0,
            )
    return r


def derive_base(src_obj, retail_obj, section):
    defs = section_defs(src_obj, section)
    if not defs:
        return None
    addr = symbol_addresses()
    B, O = relocs(src_obj), relocs(retail_obj)
    bases = []
    for key, (btarget, baddend) in B.items():
        if btarget in defs and key in O:
            name, oaddend = O[key]
            if name in addr:
                symaddr = addr[name] + oaddend - baddend
                bases.append(symaddr - defs[btarget])
    return Counter(bases).most_common(1)[0][0] if bases else None


def section_size(obj, section):
    out = subprocess.run([OBJDUMP, "-h", obj], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 7 and p[0].isdigit() and p[1] == section:
            return int(p[2], 16)
    return None


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    src, retail, section = sys.argv[1:4]
    base = derive_base(src, retail, section)
    size = section_size(src, section)
    if base is None or size is None:
        sys.exit(f"could not derive {section} range (no correlatable relocation)")
    print(f"\t{section:11s} start:0x{base:08X} end:0x{base + size:08X}")


if __name__ == "__main__":
    main()
