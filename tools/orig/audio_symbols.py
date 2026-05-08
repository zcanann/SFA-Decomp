#!/usr/bin/env python3
"""Query the preserved MusyX symbol header without committing it into source."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HEADER = ROOT / "orig" / "GSAE01" / "files" / "audio" / "starfox.h.bak"
DEFINE_RE = re.compile(r"^#define\s+((GRP|SNG|SFX)\S+)\s+(\d+)\s*$")


def parse_int(value: str) -> int:
    return int(value, 0)


def load_symbols(path: Path) -> list[tuple[str, str, int]]:
    symbols: list[tuple[str, str, int]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = DEFINE_RE.match(line)
        if match:
            name, kind, value = match.groups()
            symbols.append((kind, name, int(value)))
    return symbols


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search orig/GSAE01/files/audio/starfox.h.bak MusyX IDs."
    )
    parser.add_argument("terms", nargs="*", help="Name fragments or numeric IDs such as 0x7e.")
    parser.add_argument("--kind", choices=("GRP", "SNG", "SFX"), help="Limit to one symbol kind.")
    parser.add_argument("--header", type=Path, default=DEFAULT_HEADER, help="Header to parse.")
    args = parser.parse_args()

    symbols = load_symbols(args.header)
    if args.kind:
        symbols = [symbol for symbol in symbols if symbol[0] == args.kind]

    if not args.terms:
        counts = {kind: sum(1 for symbol in symbols if symbol[0] == kind) for kind in ("GRP", "SNG", "SFX")}
        print(f"header: {args.header}")
        print(f"GRP={counts['GRP']} SNG={counts['SNG']} SFX={counts['SFX']}")
        return

    for term in args.terms:
        needle = term.lower()
        numeric = None
        try:
            numeric = parse_int(term)
        except ValueError:
            pass

        matches = [
            symbol
            for symbol in symbols
            if (numeric is not None and symbol[2] == numeric) or needle in symbol[1].lower()
        ]
        print(f"# {term}")
        if not matches:
            print("  no matches")
            continue
        for kind, name, value in matches:
            print(f"  {kind} {value:4d} 0x{value:03X} {name}")


if __name__ == "__main__":
    main()
