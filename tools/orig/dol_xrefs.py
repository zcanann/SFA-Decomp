from __future__ import annotations

import argparse
import csv
import io
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
SOURCE_TAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_./-]*\.(?:c|h)\b")
FILE_TOKEN_RE = re.compile(r"(?:/?[A-Za-z0-9_%./-]+)\.(?:bin|tab|romlist(?:\.zlb)?|thp)\b", re.IGNORECASE)
SYMBOL_FUNCTION_RE = re.compile(
    r"^(\S+)\s*=\s*\.(\S+):0x([0-9A-Fa-f]+); // type:function size:0x([0-9A-Fa-f]+)"
)


@dataclass(frozen=True)
class DolSection:
    index: int
    offset: int
    address: int
    size: int


@dataclass(frozen=True)
class FunctionSymbol:
    name: str
    section: str
    address: int
    size: int

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.size


@dataclass(frozen=True)
class DolString:
    address: int
    section_index: int
    text: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class StringXref:
    xref_address: int
    pair_address: int
    target_address: int
    target_text: str
    pair_kind: str
    function_name: str | None
    function_start: int | None


class DolFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        section_offsets = [struct.unpack_from(">I", self.data, index * 4)[0] for index in range(18)]
        section_addrs = [struct.unpack_from(">I", self.data, 0x48 + index * 4)[0] for index in range(18)]
        section_sizes = [struct.unpack_from(">I", self.data, 0x90 + index * 4)[0] for index in range(18)]
        self.sections = [
            DolSection(
                index=index,
                offset=section_offsets[index],
                address=section_addrs[index],
                size=section_sizes[index],
            )
            for index in range(18)
            if section_sizes[index]
        ]
        self.text_sections = [section for section in self.sections if section.index <= 6]

    def offset_to_section(self, offset: int) -> DolSection | None:
        for section in self.sections:
            if section.offset <= offset < section.offset + section.size:
                return section
        return None

    def offset_to_addr(self, offset: int) -> int | None:
        section = self.offset_to_section(offset)
        if section is None:
            return None
        return section.address + (offset - section.offset)


def classify_string(text: str) -> tuple[str, ...]:
    tags: list[str] = []
    if SOURCE_TAG_RE.search(text):
        tags.append("source")
    if FILE_TOKEN_RE.search(text):
        tags.append("file")
    if any(token in text for token in ("WARNING", "failed", "overflow", "No Longer supported")):
        tags.append("warning")
    return tuple(tags)


def scan_strings(dol: DolFile) -> list[DolString]:
    strings: list[DolString] = []
    for match in PRINTABLE_RE.finditer(dol.data):
        section = dol.offset_to_section(match.start())
        if section is None:
            continue
        text = match.group().decode("ascii", "ignore")
        tags = classify_string(text)
        if not tags:
            continue
        if "file" in tags and "source" not in tags and "warning" not in tags:
            file_match = FILE_TOKEN_RE.search(text)
            if file_match is not None:
                text = file_match.group(0)
        strings.append(
            DolString(
                address=section.address + (match.start() - section.offset),
                section_index=section.index,
                text=text,
                tags=tags,
            )
        )
    return strings


def load_function_symbols(path: Path | None) -> list[FunctionSymbol]:
    if path is None or not path.is_file():
        return []
    return parse_function_symbols(path.read_text(encoding="utf-8", errors="replace"))


def parse_function_symbols(text: str) -> list[FunctionSymbol]:
    functions: list[FunctionSymbol] = []
    for line in text.splitlines():
        match = SYMBOL_FUNCTION_RE.match(line)
        if match is None:
            continue
        functions.append(
            FunctionSymbol(
                name=match.group(1),
                section=match.group(2),
                address=int(match.group(3), 16),
                size=int(match.group(4), 16),
            )
        )
    functions.sort(key=lambda item: item.address)
    return functions


def function_for_address(functions: list[FunctionSymbol], address: int) -> FunctionSymbol | None:
    for function in functions:
        if function.contains(address):
            return function
    return None


def signed_16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def scan_text_xrefs(
    dol: DolFile,
    strings_by_address: dict[int, DolString],
    functions: list[FunctionSymbol],
    window: int = 5,
) -> list[StringXref]:
    results: list[StringXref] = []
    seen: set[tuple[int, int, str]] = set()
    for section in dol.text_sections:
        words = [
            struct.unpack_from(">I", dol.data, section.offset + rel)[0]
            for rel in range(0, section.size, 4)
        ]
        for index, first_word in enumerate(words):
            if first_word >> 26 != 15:
                continue
            reg = (first_word >> 21) & 31
            base = (first_word >> 16) & 31
            if base != 0:
                continue
            high_imm = first_word & 0xFFFF
            for next_index in range(index + 1, min(index + window + 1, len(words))):
                second_word = words[next_index]
                opcode = second_word >> 26
                second_base = (second_word >> 16) & 31
                candidate: int | None = None
                pair_kind: str | None = None
                if opcode == 14 and second_base == reg:
                    low_imm = second_word & 0xFFFF
                    candidate = ((signed_16(high_imm) << 16) + signed_16(low_imm)) & 0xFFFFFFFF
                    pair_kind = "lis/addi"
                elif opcode == 24 and second_base == reg and ((second_word >> 21) & 31) == reg:
                    low_imm = second_word & 0xFFFF
                    candidate = ((high_imm << 16) | low_imm) & 0xFFFFFFFF
                    pair_kind = "lis/ori"
                if candidate is None:
                    continue
                string_entry = strings_by_address.get(candidate)
                if string_entry is None:
                    continue
                xref_address = section.address + (index * 4)
                key = (xref_address, candidate, pair_kind)
                if key in seen:
                    continue
                seen.add(key)
                function = function_for_address(functions, xref_address)
                results.append(
                    StringXref(
                        xref_address=xref_address,
                        pair_address=section.address + (next_index * 4),
                        target_address=candidate,
                        target_text=string_entry.text,
                        pair_kind=pair_kind,
                        function_name=function.name if function is not None else None,
                        function_start=function.address if function is not None else None,
                    )
                )
    results.sort(key=lambda item: (item.target_address, item.xref_address))
    return results


def format_function_name(entry: StringXref) -> str:
    if entry.function_name is None or entry.function_start is None:
        return "unknown"
    offset = entry.xref_address - entry.function_start
    if offset == 0:
        return entry.function_name
    return f"{entry.function_name}+0x{offset:X}"


def build_neighbor_lookup(strings: list[DolString]) -> dict[int, list[DolString]]:
    by_section: dict[int, list[DolString]] = defaultdict(list)
    for entry in strings:
        by_section[entry.section_index].append(entry)
    for values in by_section.values():
        values.sort(key=lambda item: item.address)
    return by_section


def neighbor_context(
    entry: DolString,
    by_section: dict[int, list[DolString]],
    radius: int = 2,
) -> list[DolString]:
    values = by_section[entry.section_index]
    index = values.index(entry)
    start = max(0, index - radius)
    end = min(len(values), index + radius + 1)
    return [item for item in values[start:end] if item.address != entry.address]


def group_xrefs_by_target(xrefs: list[StringXref]) -> dict[int, list[StringXref]]:
    grouped: dict[int, list[StringXref]] = defaultdict(list)
    for entry in xrefs:
        grouped[entry.target_address].append(entry)
    return grouped


def interesting_strings(strings: list[DolString]) -> list[DolString]:
    return [
        entry
        for entry in strings
        if "source" in entry.tags or "file" in entry.tags
    ]


def summary_markdown(strings: list[DolString], xrefs: list[StringXref]) -> str:
    grouped_xrefs = group_xrefs_by_target(xrefs)
    source_entries = [entry for entry in strings if "source" in entry.tags]
    source_with_xrefs = [entry for entry in source_entries if entry.address in grouped_xrefs]
    source_without_xrefs = [entry for entry in source_entries if entry.address not in grouped_xrefs]
    loader_entries = [
        entry
        for entry in strings
        if "file" in entry.tags and entry.address in grouped_xrefs
    ]

    lines: list[str] = []
    lines.append("# `orig/GSAE01/sys/main.dol` string-xref audit")
    lines.append("")
    lines.append("## Source-tagged strings")
    lines.append(f"- Source-tagged strings in the EN retail DOL: {len(source_entries)}")
    lines.append(f"- Source-tagged strings with direct text xrefs: {len(source_with_xrefs)}")
    lines.append("- High-value source xrefs:")
    for entry in source_with_xrefs:
        if not any(token in entry.text for token in (".c", ".h")):
            continue
        xref_group = grouped_xrefs[entry.address]
        refs = ", ".join(
            f"`0x{xref.xref_address:08X}` `{format_function_name(xref)}`"
            for xref in xref_group[:4]
        )
        lines.append(f"  - `0x{entry.address:08X}` `{entry.text}` -> {refs}")

    lines.append("")
    lines.append("## Source strings present without direct text xrefs")
    if source_without_xrefs:
        for entry in source_without_xrefs:
            lines.append(f"- `0x{entry.address:08X}` `{entry.text}`")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Loader and file-path xrefs")
    for entry in loader_entries:
        xref_group = grouped_xrefs[entry.address]
        refs = ", ".join(
            f"`0x{xref.xref_address:08X}` `{format_function_name(xref)}`"
            for xref in xref_group[:3]
        )
        lines.append(f"- `0x{entry.address:08X}` `{entry.text}` -> {refs}")

    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/dol_xrefs.py`")
    lines.append("- Search source tags or loader strings: `python tools/orig/dol_xrefs.py --search camcontrol curves romlist`")
    lines.append("- CSV dump: `python tools/orig/dol_xrefs.py --format csv`")
    return "\n".join(lines)


def search_markdown(strings: list[DolString], xrefs: list[StringXref], patterns: list[str]) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    grouped_xrefs = group_xrefs_by_target(xrefs)
    neighbors = build_neighbor_lookup(strings)
    matches = [
        entry
        for entry in interesting_strings(strings)
        if any(pattern in entry.text.lower() for pattern in lowered)
    ]

    lines: list[str] = []
    lines.append("# DOL string search")
    lines.append("")
    if not matches:
        lines.append("- No matching strings.")
        return "\n".join(lines)

    for entry in matches:
        tag_text = ", ".join(entry.tags)
        xref_group = grouped_xrefs.get(entry.address, [])
        lines.append(f"- `0x{entry.address:08X}` `{entry.text}` ({tag_text})")
        if xref_group:
            for xref in xref_group:
                lines.append(
                    f"  - xref `0x{xref.xref_address:08X}` via `{xref.pair_kind}` in `{format_function_name(xref)}`"
                )
        else:
            lines.append("  - no direct text xrefs")
            for neighbor in neighbor_context(entry, neighbors):
                lines.append(f"  - nearby `0x{neighbor.address:08X}` `{neighbor.text}`")
    return "\n".join(lines)


def rows_to_csv(strings: list[DolString], xrefs: list[StringXref]) -> str:
    grouped_xrefs = group_xrefs_by_target(xrefs)
    fieldnames = [
        "string_address",
        "tags",
        "text",
        "xref_address",
        "pair_address",
        "pair_kind",
        "function_name",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for entry in interesting_strings(strings):
        xref_group = grouped_xrefs.get(entry.address, [])
        if not xref_group:
            writer.writerow(
                {
                    "string_address": f"0x{entry.address:08X}",
                    "tags": " | ".join(entry.tags),
                    "text": entry.text,
                    "xref_address": "",
                    "pair_address": "",
                    "pair_kind": "",
                    "function_name": "",
                }
            )
            continue
        for xref in xref_group:
            writer.writerow(
                {
                    "string_address": f"0x{entry.address:08X}",
                    "tags": " | ".join(entry.tags),
                    "text": entry.text,
                    "xref_address": f"0x{xref.xref_address:08X}",
                    "pair_address": f"0x{xref.pair_address:08X}",
                    "pair_kind": xref.pair_kind,
                    "function_name": format_function_name(xref),
                }
            )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover direct string xrefs from retail EN main.dol.")
    parser.add_argument(
        "--dol",
        type=Path,
        default=Path("orig/GSAE01/sys/main.dol"),
        help="Path to the EN main.dol.",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        default=Path("config/GSAE01/symbols.txt"),
        help="Optional symbols.txt used to name containing functions.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--search",
        nargs="+",
        help="Case-insensitive substring search over interesting retail DOL strings.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    dol = DolFile(args.dol)
    strings = scan_strings(dol)
    functions = load_function_symbols(args.symbols)
    strings_by_address = {entry.address: entry for entry in strings}
    xrefs = scan_text_xrefs(dol, strings_by_address, functions)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(strings, xrefs))
        elif args.search:
            sys.stdout.write(search_markdown(strings, xrefs, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(strings, xrefs))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
