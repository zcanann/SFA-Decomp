#!/usr/bin/env python3
"""Compare section alignment (sh_addralign) of our objects against retail's.

Section ALIGNMENT is invisible to every existing gate: objdiff's fuzzy score
and matched_data both read section CONTENT, and section_size_check reads
section SIZE.  An object whose .data is 8-aligned where retail's is 4-aligned
is byte-identical by all three, yet linking it pads the DOL and shifts every
following section -- so a unit can be at fuzzy 100.0, pass every screen, and
still be unpromotable.

MWCC emits .data with sh_addralign 8 unconditionally (verified against
jumptable-only, array-only and struct-only translation units), so a retail
object carved at 4 always needs the fix.  The remedy already exists in the
tree: pass section_alignments={".data": 4} to the Object in configure.py,
which post-processes the object with objcopy --set-section-alignment.

Usage:
    tools/section_align_check.py [--all]

Default output lists only mismatches on units that are, or could become,
source-linked.  --all also prints matching units.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
READELF = ROOT / "build" / "binutils" / "powerpc-eabi-readelf"
SRC_DIR = ROOT / "build" / "GSAE01" / "src"
OBJ_DIR = ROOT / "build" / "GSAE01" / "obj"

# Sections whose alignment affects DOL layout.
INTERESTING = {".text", ".data", ".rodata", ".sdata", ".sdata2", ".bss", ".sbss", ".sbss2"}


def alignments(path):
    try:
        out = subprocess.run(
            [str(READELF), "-S", "-W", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    result = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            body = line.split("]", 1)[1].split()
        except IndexError:
            continue
        if not body:
            continue
        name = body[0]
        if name in INTERESTING:
            try:
                result[name] = int(body[-1])
            except ValueError:
                pass
    return result


def main():
    show_all = "--all" in sys.argv
    if not READELF.exists():
        print("missing %s" % READELF)
        return 2

    mismatches = []
    checked = 0
    for src in sorted(SRC_DIR.rglob("*.o")):
        rel = src.relative_to(SRC_DIR)
        retail = OBJ_DIR / rel
        if not retail.exists():
            continue
        ours = alignments(src)
        theirs = alignments(retail)
        if ours is None or theirs is None:
            continue
        checked += 1
        bad = {
            sec: (ours[sec], theirs[sec])
            for sec in sorted(set(ours) & set(theirs))
            if ours[sec] != theirs[sec]
        }
        if bad:
            mismatches.append((rel, bad))
        elif show_all:
            print("ok       %s" % rel)

    for rel, bad in mismatches:
        detail = ", ".join(
            "%s ours=%d retail=%d" % (sec, o, t) for sec, (o, t) in bad.items()
        )
        print("MISMATCH %s: %s" % (rel, detail))

    print("\nchecked=%d mismatched=%d" % (checked, len(mismatches)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
