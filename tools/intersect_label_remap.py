#!/usr/bin/env python3
"""Translate v1.1 DAT_/lbl_ references in track/intersect.c to v1.0.

Strategy: for each (DAT|lbl)_<addr> referenced in the C source, try the
known per-section deltas (.data ~ -0xBC0, .bss/.sdata ~ -0xC60, .sbss ~
-0xC80). If the candidate v1.0 address exists in `config/GSAE01/symbols.txt`
or in the v1.0 asm for intersect.c (`build/GSAE01/asm/track/intersect.s`),
emit a rename. Anything ambiguous or not found is reported and left alone.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/track/intersect.c"
SYMS = ROOT / "config/GSAE01/symbols.txt"
ASM = ROOT / "build/GSAE01/asm/track/intersect.s"

REF_RE = re.compile(r"\b(?:DAT|lbl|jumptable)_[0-9A-Fa-f]{8}\b")


def load_v10_addresses() -> dict[int, str]:
    out: dict[int, str] = {}
    sym_re = re.compile(r"^(\w+)\s*=\s*\.\w+:0x([0-9A-Fa-f]+);")
    for line in SYMS.read_text().splitlines():
        m = sym_re.match(line)
        if m:
            name = m.group(1)
            if name.startswith(("lbl_", "jumptable_")):
                out[int(m.group(2), 16)] = name
    # also harvest any local labels referenced inside our intersect asm
    asm_re = re.compile(r"\b(lbl|jumptable)_([0-9A-Fa-f]{8})\b")
    for token in asm_re.finditer(ASM.read_text()):
        addr = int(token.group(2), 16)
        out.setdefault(addr, f"{token.group(1)}_{token.group(2).upper()}")
    return out


# Per-section v1.1 -> v1.0 deltas, derived empirically from labels we've
# already mapped by inspecting v1.0 bodies. The keys are inclusive lower
# bounds; the rightmost key whose lower bound is ≤ addr applies.
SECTION_DELTAS = [
    (0x80000000, -0x000),   # .text region — function names handled separately
    (0x80300000, -0xBC0),   # .data
    (0x80335000, -0xC60),   # .bss / .sdata2 / .sdata
    (0x803DC000, -0xC80),   # .sbss
]


def candidate_v10(addr: int) -> int:
    delta = 0
    for lo, d in SECTION_DELTAS:
        if addr >= lo:
            delta = d
    return addr + delta


def main() -> None:
    v10_addrs = load_v10_addresses()
    text = SRC.read_text(encoding="utf-8")

    seen: dict[str, str] = {}
    misses: list[str] = []

    for token in sorted(set(REF_RE.findall(text))):
        addr = int(token.split("_")[1], 16)
        if addr in v10_addrs and v10_addrs[addr] == token:
            # already a v1.0 name, nothing to do
            continue
        cand = candidate_v10(addr)
        if cand in v10_addrs:
            seen[token] = v10_addrs[cand]
        else:
            # also accept any token whose addr already exists in v10_addrs
            # (e.g. an existing lbl_xxx that's already correct)
            if addr in v10_addrs:
                continue
            misses.append(f"{token} addr=0x{addr:08X} cand=0x{cand:08X}")

    if not seen:
        print("no renames")
    else:
        pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in seen) + r")\b")
        n = 0

        def sub(m: re.Match[str]) -> str:
            nonlocal n
            n += 1
            return seen[m.group(1)]

        new_text = pattern.sub(sub, text)
        SRC.write_text(new_text, encoding="utf-8")
        print(f"renames={len(seen)} replacements={n}")
        for old, new in sorted(seen.items()):
            print(f"  {old} -> {new}")

    if misses:
        print(f"unresolved={len(misses)}:")
        for m in misses:
            print(f"  {m}")


if __name__ == "__main__":
    main()
