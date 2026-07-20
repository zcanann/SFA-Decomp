#!/usr/bin/env python3
"""Screen for objdiff name-pairing losses.

objdiff pairs symbols BY NAME. If our source object defines a symbol name that the
retail (carved) object does not define at the same address -- e.g. the source was
renamed but config/GSAE01/symbols.txt was never updated -- objdiff silently drops
that function from the comparison and the unit loses the score for it, with no
diff and no warning anywhere.

This compares, per unit, the .text symbols our source object defines against the
.text symbols the retail object defines, and reports names present on only one side.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = os.path.join(ROOT, "build/binutils/powerpc-eabi-objdump")
SRC_ROOT = os.path.join(ROOT, "build/GSAE01/src")
OBJ_ROOT = os.path.join(ROOT, "build/GSAE01/obj")

SYM_RE = re.compile(
    r"^([0-9a-f]{8})\s+(l|g|w|\s)\s*([a-zA-Z ]*?)\s+(\S+)\s+([0-9a-f]{8})\s+(\S+)\s*$"
)


def text_syms(path, section=".text"):
    """Return {name: (offset, size)} for FUNC symbols in `section`."""
    out = subprocess.run(
        [OBJDUMP, "-t", path], capture_output=True, text=True
    ).stdout
    syms = {}
    for line in out.splitlines():
        m = SYM_RE.match(line)
        if not m:
            continue
        off, _bind, flags, sec, size, name = m.groups()
        if sec != section:
            continue
        if "F" not in flags.split():
            continue
        syms[name] = (int(off, 16), int(size, 16))
    return syms


def units():
    for dirpath, _dirs, files in os.walk(SRC_ROOT):
        for f in files:
            if not f.endswith(".o"):
                continue
            src = os.path.join(dirpath, f)
            rel = os.path.relpath(src, SRC_ROOT)
            obj = os.path.join(OBJ_ROOT, rel)
            if os.path.exists(obj):
                yield rel, src, obj


def check(rel, src, obj, section=".text"):
    ours = text_syms(src, section)
    theirs = text_syms(obj, section)
    only_ours = set(ours) - set(theirs)
    only_theirs = set(theirs) - set(ours)
    if not only_ours and not only_theirs:
        return None
    # match up unpaired names by identical (offset,size) -- that is a rename
    renames = []
    for a in sorted(only_ours):
        for b in sorted(only_theirs):
            if ours[a] == theirs[b]:
                renames.append((a, b, ours[a]))
    return {
        "unit": rel,
        "ours": ours,
        "theirs": theirs,
        "only_ours": sorted(only_ours),
        "only_theirs": sorted(only_theirs),
        "renames": renames,
    }


def main():
    argv = sys.argv[1:]
    section = ".text"
    if argv and argv[0].startswith("--section="):
        section = argv.pop(0).split("=", 1)[1]
    if argv:
        # explicit src-object paths (used for the positive control)
        pairs = []
        for p in argv:
            rel = os.path.relpath(os.path.abspath(p), SRC_ROOT)
            pairs.append((rel, p, os.path.join(OBJ_ROOT, rel)))
    else:
        pairs = list(units())

    hits = []
    for rel, src, obj in sorted(pairs):
        if not os.path.exists(obj):
            print("NO RETAIL OBJ: %s" % rel)
            continue
        r = check(rel, src, obj, section)
        if r:
            hits.append(r)

    for h in hits:
        print("=== %s" % h["unit"])
        for a, b, (off, size) in h["renames"]:
            print("  RENAME  ours=%-40s retail=%-40s @+0x%X size 0x%X" % (a, b, off, size))
        rn_ours = {a for a, _b, _s in h["renames"]}
        rn_theirs = {b for _a, b, _s in h["renames"]}
        for a in h["only_ours"]:
            if a not in rn_ours:
                off, size = h["ours"][a]
                print("  ONLY-OURS   %-40s @+0x%X size 0x%X" % (a, off, size))
        for b in h["only_theirs"]:
            if b not in rn_theirs:
                off, size = h["theirs"][b]
                print("  ONLY-RETAIL %-40s @+0x%X size 0x%X" % (b, off, size))
    print("\n%d units scanned, %d with unpaired %s symbols" % (len(pairs), len(hits), section))


if __name__ == "__main__":
    main()
