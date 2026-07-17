#!/usr/bin/env python3
"""Rank matching objects whose compiled .text exceeds their retail split.

An overage often means the source emits a helper that the retail compiler only
inlined.  The report cannot expose those target-absent functions because they
have no retail symbol, so this provides a cheap complementary worklist.  Every
candidate still needs a final-link checksum gate: object-local section scores
can hide relocation or layout dependencies.
"""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def matching_sources(version: str) -> set[str]:
    configure = (ROOT / "configure.py").read_text(encoding="utf-8")
    pattern = re.compile(
        rf'Object\(MatchingFor\("{re.escape(version)}"\),\s*"([^"]+\.c)"'
    )
    return set(pattern.findall(configure))


def retail_text_sizes(version: str) -> dict[str, int]:
    splits = ROOT / "config" / version / "splits.txt"
    result: dict[str, int] = {}
    current: str | None = None

    for line in splits.read_text(encoding="utf-8").splitlines():
        unit = re.match(r"([^\s].*\.c):$", line)
        if unit:
            current = unit.group(1)
            continue
        if current is None:
            continue
        text = re.match(
            r"\s+\.text\s+start:0x([0-9A-Fa-f]+)\s+end:0x([0-9A-Fa-f]+)",
            line,
        )
        if text:
            start, end = (int(value, 16) for value in text.groups())
            result[current] = end - start

    return result


def elf_section_size(path: Path, section: str) -> int | None:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise ValueError(f"{path}: expected an ELF32 object")

    endian = ">" if data[5] == 2 else "<"
    section_offset = struct.unpack_from(endian + "I", data, 0x20)[0]
    entry_size = struct.unpack_from(endian + "H", data, 0x2E)[0]
    entry_count = struct.unpack_from(endian + "H", data, 0x30)[0]
    names_index = struct.unpack_from(endian + "H", data, 0x32)[0]

    def header(index: int) -> tuple[int, ...]:
        offset = section_offset + index * entry_size
        return struct.unpack_from(endian + "IIIIIIIIII", data, offset)

    names_header = header(names_index)
    names = data[names_header[4] : names_header[4] + names_header[5]]
    for index in range(entry_count):
        item = header(index)
        name_start = item[0]
        name_end = names.find(b"\0", name_start)
        name = names[name_start:name_end].decode("ascii", errors="replace")
        if name == section:
            return item[5]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument(
        "--include-nonpositive",
        action="store_true",
        help="also show objects at or below their retail .text size",
    )
    args = parser.parse_args()

    targets = retail_text_sizes(args.version)
    rows: list[tuple[int, int, int, str]] = []
    missing = 0
    for source in matching_sources(args.version):
        target_size = targets.get(source)
        obj = ROOT / "build" / args.version / "src" / Path(source).with_suffix(".o")
        if target_size is None or not obj.exists():
            missing += 1
            continue
        source_size = elf_section_size(obj, ".text") or 0
        overage = source_size - target_size
        if overage > 0 or args.include_nonpositive:
            rows.append((overage, source_size, target_size, source))

    rows.sort(reverse=True)
    print(f"{'over':>8} {'source':>8} {'target':>8}  unit")
    for overage, source_size, target_size, source in rows:
        print(f"{overage:8d} {source_size:8d} {target_size:8d}  {source}")
    if missing:
        print(f"\nSkipped {missing} units without both a built object and .text split.")


if __name__ == "__main__":
    main()
