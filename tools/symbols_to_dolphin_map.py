#!/usr/bin/env python3
"""Convert config/<GAMEID>/symbols.txt into a Dolphin-loadable .map file.

The decomp build byte-matches the retail DOL, so the addresses in symbols.txt
are the live RAM addresses while the game runs. Loading the emitted .map in
Dolphin (Symbols -> Load Map File, or drop it at User/Maps/<GAMEID>.map) makes
the Code view and the call stack show real names instead of bare addresses --
which is what makes breakpoint/watchpoint spelunking practical.

Output is the CodeWarrior "section layout" format. Dolphin switches sections on
a line ending in "section layout" and reads each symbol as:
    <section-relative offset> <size> <virtual address> <align> <name>
using the 3rd column (virtual address) as the real address.
"""
import argparse
import re
import sys
from pathlib import Path

LINE_RE = re.compile(
    r"^(?P<name>\S+)\s*=\s*\.(?P<section>\w+):0x(?P<addr>[0-9A-Fa-f]+);(?P<rest>.*)$"
)
SIZE_RE = re.compile(r"size:0x(?P<size>[0-9A-Fa-f]+)")


def parse(symbols_path: Path, functions_only: bool):
    sections = {}
    for line in symbols_path.read_text().splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        rest = m.group("rest")
        if functions_only and "type:function" not in rest:
            continue
        size_m = SIZE_RE.search(rest)
        size = int(size_m.group("size"), 16) if size_m else 0
        sym = (int(m.group("addr"), 16), size, m.group("name"))
        sections.setdefault(m.group("section"), []).append(sym)
    return sections


def emit(sections, out_path: Path):
    out = []
    total = 0
    for section in sorted(sections, key=lambda s: min(a for a, _, _ in sections[s])):
        syms = sorted(sections[section])
        base = syms[0][0]
        out.append(f".{section} section layout")
        out.append("  Starting        Virtual")
        out.append("  address  Size   address")
        out.append("  -----------------------")
        for addr, size, name in syms:
            out.append(f"  {addr - base:08x} {size:06x} {addr:08x}  4 {name}")
            total += 1
        out.append("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(out))
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gameid", default="GSAE01")
    ap.add_argument("--input", type=Path,
                    help="symbols.txt (default: config/<gameid>/symbols.txt)")
    ap.add_argument("--output", type=Path,
                    help="output .map (default: build/<gameid>.map)")
    ap.add_argument("--functions-only", action="store_true",
                    help="emit only type:function symbols")
    args = ap.parse_args()

    inp = args.input or Path("config") / args.gameid / "symbols.txt"
    out = args.output or Path("build") / f"{args.gameid}.map"
    if not inp.exists():
        sys.exit(f"not found: {inp}")

    sections = parse(inp, args.functions_only)
    total = emit(sections, out)
    print(f"wrote {total} symbols across {len(sections)} sections -> {out}")


if __name__ == "__main__":
    main()
