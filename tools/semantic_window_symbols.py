#!/usr/bin/env python3
"""Find named text symbols hidden inside oversized annotated source functions.

This complements exact FUN_<addr> scanners. Some raw Ghidra imports still carry
one large function window whose annotated EN span covers several symbols that
are already known in config/GSAE01/symbols.txt. Those are good split/naming
targets because the symbol table can propagate meaning into an otherwise
anonymous decomp island.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path


SYMBOL_RE = re.compile(
    r"^(?P<name>[A-Za-z_][\w$@]*)\s*=\s*\.text:0x(?P<addr>[0-9A-Fa-f]+);"
    r"\s*// type:function(?: size:0x(?P<size>[0-9A-Fa-f]+))?"
)
INFO_RE = re.compile(
    r"/\*\s*\r?\n"
    r"\s*\* --INFO--\s*\r?\n"
    r"\s*\*\s*\r?\n"
    r"\s*\* Function:\s*(?P<label>[^\r\n]+)\r?\n"
    r".*?\* EN v1\.0 Address:\s*0x(?P<addr>[0-9A-Fa-f]+)\r?\n"
    r"\s*\* EN v1\.0 Size:\s*(?P<size>\d+)b\r?\n"
    r".*?\*/\s*"
    r"(?P<prefix>(?:[#a-zA-Z_][^\r\n]*\r?\n)*)"
    r"(?P<signature>[^;{}]*?\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\()",
    re.S,
)
AUTO_NAME_RE = re.compile(r"^(?:FUN|fn|lbl|__|_)")
CALLBACK_SUFFIXES = (
    ("getExtraSize", ("_getExtraSize",)),
    ("func08", ("_func08", "_func08_ret_0", "_func08_ret_1")),
    ("free", ("_free", "_free_nop")),
    ("render", ("_render",)),
    ("hitDetect", ("_hitDetect", "_hitDetect_nop")),
    ("update", ("_update",)),
    ("init", ("_init",)),
    ("release", ("_release", "_release_nop")),
    ("initialise", ("_initialise", "_initialise_nop")),
)


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int | None


@dataclass(frozen=True)
class HiddenSymbol:
    path: Path
    line: int
    function_name: str
    function_label: str
    start: int
    end: int
    symbol: Symbol


@dataclass(frozen=True)
class CallbackFamily:
    path: Path
    line: int
    function_name: str
    function_label: str
    start: int
    end: int
    family: str
    rows: tuple[tuple[str, HiddenSymbol], ...]


def load_text_symbols(path: Path, include_auto_names: bool) -> list[Symbol]:
    symbols: list[Symbol] = []
    for line in path.read_text(errors="ignore").splitlines():
        match = SYMBOL_RE.match(line)
        if match is None:
            continue
        name = match.group("name")
        if "@" in name:
            continue
        if not include_auto_names and AUTO_NAME_RE.match(name):
            continue
        size_text = match.group("size")
        symbols.append(
            Symbol(
                name=name,
                address=int(match.group("addr"), 16),
                size=int(size_text, 16) if size_text is not None else None,
            )
        )
    return sorted(symbols, key=lambda item: item.address)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def iter_hidden_symbols(
    source_root: Path,
    symbols: list[Symbol],
    min_contained: int,
    search: str | None,
) -> list[HiddenSymbol]:
    rows: list[HiddenSymbol] = []
    search_lower = search.lower() if search else None
    for path in source_root.rglob("*.c"):
        text = path.read_text(errors="ignore")
        file_rows: list[HiddenSymbol] = []
        for match in INFO_RE.finditer(text):
            start = int(match.group("addr"), 16)
            end = start + int(match.group("size"))
            function_name = match.group("name")
            contained = [
                symbol
                for symbol in symbols
                if start < symbol.address < end and symbol.name != function_name
            ]
            if len(contained) < min_contained:
                continue
            line = line_for_offset(text, match.start())
            for symbol in contained:
                row = HiddenSymbol(
                    path=path,
                    line=line,
                    function_name=function_name,
                    function_label=match.group("label").strip(),
                    start=start,
                    end=end,
                    symbol=symbol,
                )
                if search_lower is not None:
                    haystack = (
                        f"{path.as_posix()} {function_name} {row.function_label} {symbol.name}"
                    ).lower()
                    if search_lower not in haystack:
                        continue
                file_rows.append(row)
        rows.extend(file_rows)
    return sorted(rows, key=lambda item: (str(item.path).lower(), item.start, item.symbol.address))


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def format_markdown(rows: list[HiddenSymbol], repo_root: Path, limit: int) -> str:
    groups: dict[tuple[Path, int, int, str, str, int], list[HiddenSymbol]] = {}
    for row in rows:
        key = (
            row.path,
            row.start,
            row.end,
            row.function_name,
            row.function_label,
            row.line,
        )
        groups.setdefault(key, []).append(row)

    lines = ["# Hidden semantic symbols", ""]
    lines.append(f"- functions: `{len(groups)}`")
    lines.append(f"- contained symbols: `{len(rows)}`")
    lines.append("")

    emitted = 0
    for (path, start, end, function_name, function_label, line), entries in groups.items():
        if limit and emitted >= limit:
            break
        emitted += 1
        rel = display_path(path, repo_root)
        lines.append(
            f"- `{rel}:{line}` `{function_name}` label=`{function_label}` "
            f"span=`0x{start:08X}-0x{end:08X}` contains `{len(entries)}`"
        )
        for entry in entries[:12]:
            size = "" if entry.symbol.size is None else f" size=`0x{entry.symbol.size:X}`"
            lines.append(f"  - `0x{entry.symbol.address:08X}` `{entry.symbol.name}`{size}")
        if len(entries) > 12:
            lines.append(f"  - ... +{len(entries) - 12} more")
    return "\n".join(lines).rstrip() + "\n"


def callback_family_for(name: str) -> tuple[str, str] | None:
    for slot, suffixes in CALLBACK_SUFFIXES:
        for suffix in suffixes:
            if name.endswith(suffix):
                return name[: -len(suffix)], slot
    return None


def group_callback_families(rows: list[HiddenSymbol], min_family_slots: int) -> list[CallbackFamily]:
    grouped: dict[tuple[Path, int, int, str, str, int, str], list[tuple[str, HiddenSymbol]]] = {}
    for row in rows:
        family = callback_family_for(row.symbol.name)
        if family is None:
            continue
        family_name, slot = family
        key = (
            row.path,
            row.start,
            row.end,
            row.function_name,
            row.function_label,
            row.line,
            family_name,
        )
        grouped.setdefault(key, []).append((slot, row))

    families: list[CallbackFamily] = []
    for (path, start, end, function_name, function_label, line, family), entries in grouped.items():
        slots = {slot for slot, _row in entries}
        if len(slots) < min_family_slots:
            continue
        entries.sort(key=lambda item: item[1].symbol.address)
        families.append(
            CallbackFamily(
                path=path,
                line=line,
                function_name=function_name,
                function_label=function_label,
                start=start,
                end=end,
                family=family,
                rows=tuple(entries),
            )
        )
    return sorted(
        families,
        key=lambda item: (
            str(item.path).lower(),
            item.start,
            -len({slot for slot, _row in item.rows}),
            item.family.lower(),
        ),
    )


def format_callback_families(
    families: list[CallbackFamily], repo_root: Path, limit: int
) -> str:
    lines = ["# Hidden descriptor callback families", ""]
    lines.append(f"- families: `{len(families)}`")
    lines.append("")

    for emitted, family in enumerate(families, start=1):
        if limit and emitted > limit:
            break
        rel = display_path(family.path, repo_root)
        slots = {slot for slot, _row in family.rows}
        lines.append(
            f"- `{rel}:{family.line}` family=`{family.family}` "
            f"slots=`{len(slots)}` in `{family.function_name}` "
            f"span=`0x{family.start:08X}-0x{family.end:08X}`"
        )
        for slot, row in family.rows[:12]:
            size = "" if row.symbol.size is None else f" size=`0x{row.symbol.size:X}`"
            lines.append(f"  - `{slot}` `0x{row.symbol.address:08X}` `{row.symbol.name}`{size}")
        if len(family.rows) > 12:
            lines.append(f"  - ... +{len(family.rows) - 12} more")
    return "\n".join(lines).rstrip() + "\n"


def write_csv(rows: list[HiddenSymbol], repo_root: Path) -> None:
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "path",
            "line",
            "function_name",
            "function_label",
            "function_start",
            "function_end",
            "symbol_name",
            "symbol_address",
            "symbol_size",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                display_path(row.path, repo_root),
                row.line,
                row.function_name,
                row.function_label,
                f"0x{row.start:08X}",
                f"0x{row.end:08X}",
                row.symbol.name,
                f"0x{row.symbol.address:08X}",
                "" if row.symbol.size is None else f"0x{row.symbol.size:X}",
            ]
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"))
    parser.add_argument("--source-root", type=Path, default=Path("src/main"))
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown")
    parser.add_argument("--limit", type=int, default=25, help="maximum functions in markdown output")
    parser.add_argument(
        "--min-contained",
        type=int,
        default=1,
        help="minimum named symbols contained inside a source function span",
    )
    parser.add_argument("--search", help="case-insensitive filter over path/function/symbol names")
    parser.add_argument("--include-auto-names", action="store_true")
    parser.add_argument(
        "--descriptor-families",
        action="store_true",
        help="group hidden symbols that look like object descriptor callback families",
    )
    parser.add_argument(
        "--min-family-slots",
        type=int,
        default=3,
        help="minimum callback slots required for --descriptor-families",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    symbols = load_text_symbols(args.symbols, include_auto_names=args.include_auto_names)
    rows = iter_hidden_symbols(args.source_root, symbols, args.min_contained, args.search)

    if args.descriptor_families and args.format == "csv":
        raise SystemExit("--descriptor-families is only supported with markdown output")

    if args.descriptor_families:
        families = group_callback_families(rows, args.min_family_slots)
        sys.stdout.write(format_callback_families(families, repo_root, args.limit))
    elif args.format == "csv":
        write_csv(rows, repo_root)
    else:
        sys.stdout.write(format_markdown(rows, repo_root, args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
