#!/usr/bin/env python3
"""One-shot rename of v1.1 -> v1.0 names in track/intersect.{c,h}.

Sequential mapping built from `build/GSAE01/asm/track/intersect.s` and the
order of function definitions in `src/track/intersect.c`. Also remaps the
known cross-file externs and data labels we've identified by reading the
corresponding v1.0 asm bodies.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/track/intersect.c"
HDR = ROOT / "include/track/intersect.h"

# Function name renames (v1.1 -> v1.0). For empty FUN_xxx stubs and the
# decoded fn_xxx, all become fn_<v1.0_addr>. OSReport stays. The duplicate
# FUN_800723a0 is dropped at a later step (separate edit).
FN_RENAMES = {
    # internal sequential (positions 0..94, OSReport at pos 80, dup at 81)
    "FUN_8006ef38": "fn_8006EF38",
    "fn_8006F504":  "fn_8006F388",
    "fn_8006F57C":  "fn_8006F400",
    "FUN_8006f09c": "fn_8006F500",
    "FUN_8006f0a0": "fn_8006F950",
    "fn_8006FD7C":  "fn_8006FC00",
    "fn_8006FE48":  "fn_8006FCCC",
    "FUN_8006f690": "fn_8006FDF8",
    "fn_80070050":  "fn_8006FED4",
    "fn_80070074":  "fn_8006FEF8",
    "fn_8007007C":  "fn_8006FF00",
    "FUN_8006f79c": "fn_8006FF0C",
    "fn_80070320":  "fn_800701A4",
    "fn_800703B0":  "fn_80070234",
    "fn_80070434":  "fn_800702B8",
    "fn_8007048C":  "fn_80070310",
    "fn_80070528":  "fn_800703AC",
    "fn_80070538":  "fn_800703BC",
    "fn_80070540":  "fn_800703C4",
    "fn_80070580":  "fn_80070404",
    "fn_80070658":  "fn_800704DC",
    "fn_80070678":  "fn_800704FC",
    "FUN_8006fb00": "fn_80070510",
    "FUN_8006fb04": "fn_80070ED4",
    "FUN_8006fb08": "fn_800717FC",
    "FUN_8006fb0c": "fn_80071D54",
    "FUN_8006fb10": "fn_800722B0",
    "FUN_8006fb14": "fn_80072DFC",
    "FUN_8006fb18": "fn_8007366C",
    "fn_80073C28":  "fn_80073AAC",
    "FUN_8006fd74": "fn_80073D04",
    "FUN_8006fd7c": "fn_80074110",
    "FUN_8006fd84": "fn_80074518",
    "FUN_8006fd88": "fn_80074D04",
    "fn_80075534":  "fn_800753B8",
    "fn_80075800":  "fn_80075684",
    "fn_80075B98":  "fn_80075A1C",
    "fn_80075ED8":  "fn_80075D5C",
    "fn_80076008":  "fn_80075E8C",
    "FUN_800709d8": "fn_80075FC8",
    "FUN_800709dc": "fn_80076510",
    "FUN_800709e0": "fn_8007681C",
    "FUN_800709e4": "fn_80076D78",
    "FUN_800709e8": "fn_8007719C",
    "fn_80077780":  "fn_80077604",
    "fn_80077A08":  "fn_8007788C",
    "FUN_80070ec0": "fn_80077AD8",
    "FUN_80070ec4": "fn_80077EF8",
    "fn_800788BC":  "fn_80078740",
    "fn_80078988":  "fn_8007880C",
    "fn_80078A58":  "fn_800788DC",
    "fn_80078B28":  "fn_800789AC",
    "fn_80078BF8":  "fn_80078A7C",
    "fn_80078CC8":  "fn_80078B4C",
    "fn_80078D98":  "fn_80078C1C",
    "fn_80078F78":  "fn_80078DFC",
    "fn_8007904C":  "fn_80078ED0",
    "fn_80079120":  "fn_80078FA4",
    "fn_80079228":  "fn_800790AC",
    "fn_800792FC":  "fn_80079180",
    "fn_800793D0":  "fn_80079254",
    "fn_800794A4":  "fn_80079328",
    "fn_8007965C":  "fn_800794E0",
    "fn_80079764":  "fn_800795E8",
    "fn_8007986C":  "fn_800796F0",
    "FUN_80071f8c": "fn_80079804",
    "fn_80079B3C":  "fn_800799C0",
    "fn_80079B60":  "fn_800799E4",
    "fn_80079BA0":  "fn_80079A24",
    "FUN_80072034": "fn_80079A64",
    "FUN_80072038": "fn_80079E64",
    "FUN_8007203c": "fn_8007A71C",
    "FUN_80072040": "fn_8007AD10",
    "FUN_80072044": "fn_8007B01C",
    "FUN_80072048": "fn_8007BD8C",
    "fn_8007C54C":  "fn_8007C3D0",
    "FUN_800722e0": "fn_8007C664",
    "FUN_800722e4": "fn_8007CAF4",
    "FUN_800722e8": "fn_8007CF7C",
    "fn_8007D7EC":  "fn_8007D670",
    # OSReport stays the same name; it's at v1.0 0x8007D6DC per symbols.txt
    # FUN_800723a0 is a duplicate of OSReport — handled by a separate Edit
    "FUN_800723a4": "fn_8007D72C",
    "fn_8007DADC":  "fn_8007D960",
    "fn_8007DB04":  "fn_8007D988",
    "fn_8007DB10":  "fn_8007D994",
    "fn_8007DB18":  "fn_8007D99C",
    "fn_8007DCA0":  "fn_8007DB24",
    "fn_8007DD3C":  "fn_8007DBC0",
    "fn_8007DDD8":  "fn_8007DC5C",
    "fn_8007DE80":  "fn_8007DD04",
    "fn_8007DF88":  "fn_8007DE0C",
    "fn_8007E06C":  "fn_8007DEF0",
    "fn_8007E08C":  "fn_8007DF10",
    "FUN_80072be8": "fn_8007E1AC",

    # cross-file externs and intersect-internal trailing fns recovered from
    # bl-targets in the v1.0 asm.
    "fn_8007E7A0":  "fn_8007E54C",
    "fn_8007E328":  "fn_8007E1AC",
    "fn_8007ED98":  "fn_8007EB44",
    "fn_8007E928":  "fn_8007E6D4",
    "fn_8007E99C":  "fn_8007E748",
    "fn_8007E9D0":  "fn_8007E77C",
    "fn_8007FAC8":  "fn_8007F83C",
    "fn_800238C4":  "fn_80023800",
    "fn_8006C86C":  "fn_8006C6F0",
}

# Data label renames recovered from the v1.0 asm.
LBL_RENAMES = {
    "lbl_8030F470": "lbl_8030E8B0",  # fn_8006F388 base table
    "lbl_803DDCC0": "lbl_803DD040",
    "lbl_803DDCDA": "lbl_803DD05A",
    "lbl_803DDCD8": "lbl_803DD058",
    "lbl_803DC360": "lbl_803DB700",
    "lbl_80397560": "lbl_80396900",  # CARDClose handle
}


def rename_tokens(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """Replace whole-word identifier tokens in *text* using *mapping*."""
    if not mapping:
        return text, 0
    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in mapping) + r")\b")
    n = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal n
        n += 1
        return mapping[m.group(1)]

    return pattern.sub(sub, text), n


def main() -> None:
    for path in (SRC, HDR):
        original = path.read_text(encoding="utf-8")
        updated, fn_count = rename_tokens(original, FN_RENAMES)
        updated, lbl_count = rename_tokens(updated, LBL_RENAMES)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            print(f"{path.relative_to(ROOT)}: fn_renames={fn_count} lbl_renames={lbl_count}")
        else:
            print(f"{path.relative_to(ROOT)}: no changes")


if __name__ == "__main__":
    main()
