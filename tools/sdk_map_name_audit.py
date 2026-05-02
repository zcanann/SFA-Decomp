#!/usr/bin/env python3
"""Audit shipped MAP symbols from donor SDK objects against SFA signatures."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from dolphin_sdk_symbols import ConfigSymbol, load_config_symbols
from sdk_dol_match import (
    RawWindow,
    describe_target_split_overlap,
    discover_reference_hits,
    normalize_path,
    parse_int,
    parse_reference_spec,
    target_dol_path_for_version,
    verdict_for_hit,
)


MAP_ENTRY_RE = re.compile(
    r"^\s+(?P<offset>UNUSED|[0-9A-Fa-f]{8})\s+"
    r"(?P<size>[0-9A-Fa-f]{6})\s+"
    r"(?P<address>[0-9A-Fa-f.]{8})\s+"
    r"(?P<align>\d+)\s+"
    r"(?P<name>.+?)\s+\t(?P<object>.+?)\s*$"
)
MEMORY_SECTION_RE = re.compile(
    r"^\s+(?P<section>\.\S+)\s+"
    r"(?P<start>[0-9A-Fa-f]{8})\s+"
    r"(?P<size>[0-9A-Fa-f]{8})\s+"
    r"(?P<offset>[0-9A-Fa-f]{8})\s*$"
)
PLACEHOLDER_PREFIXES = ("fn_", "lbl_", "FUN_", "sub_", "zz_")


@dataclass(frozen=True)
class MapSymbol:
    source_path: str
    object_name: str
    name: str
    address: int
    size: int

    @property
    def end(self) -> int:
        return self.address + self.size


def load_text_range(map_path: Path) -> tuple[int, int]:
    in_memory_map = False
    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip() == "Memory map:":
            in_memory_map = True
            continue
        if not in_memory_map:
            continue
        match = MEMORY_SECTION_RE.match(line)
        if match is None or match.group("section") != ".text":
            continue
        start = int(match.group("start"), 16)
        size = int(match.group("size"), 16)
        return start, start + size
    raise SystemExit(f"Could not find .text memory range in {map_path}")


def normalize_map_object(object_name: str) -> str:
    raw = object_name.replace("\\", "/").strip()
    if ".a " in raw:
        archive, member = raw.split(".a ", 1)
        archive += ".a"
        member = member.strip()
        if archive == "MSL_C.PPCEABI.bare.H.a":
            return f"dolphin/MSL_C/PPCEABI/bare/H/{member}"
        if archive == "Runtime.PPCEABI.H.a":
            return f"Runtime.PPCEABI.H/{member}"
        if archive == "TRK_MINNOW_DOLPHIN.a":
            return f"dolphin/TRK_MINNOW_DOLPHIN/{member}"
        if archive.endswith("D.a") and len(archive) > 3:
            return f"dolphin/{archive[:-3]}/{member}"
        return f"{archive}/{member}"
    return raw


def load_map_text_symbols(map_path: Path) -> list[MapSymbol]:
    text_start, text_end = load_text_range(map_path)
    symbols: list[MapSymbol] = []
    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = MAP_ENTRY_RE.match(line)
        if match is None:
            continue
        if match.group("offset") == "UNUSED" or "." in match.group("address"):
            continue
        address = int(match.group("address"), 16)
        size = int(match.group("size"), 16)
        if not (text_start <= address < text_end) or size == 0:
            continue
        name = match.group("name").strip()
        if name == ".text":
            continue
        object_name = match.group("object").strip()
        source_path = normalize_path(normalize_map_object(object_name))
        symbols.append(
            MapSymbol(
                source_path=source_path,
                object_name=object_name,
                name=name,
                address=address,
                size=size,
            )
        )
    symbols.sort(key=lambda item: (item.source_path, item.address, item.name))
    return symbols


def trusted_name(name: str, include_local: bool) -> bool:
    if not include_local and (name.startswith("@") or name.startswith("...")):
        return False
    if name in {".text", ".init"}:
        return False
    return True


def is_placeholder(name: str) -> bool:
    return name.startswith(PLACEHOLDER_PREFIXES)


def symbol_by_address(version: str) -> dict[int, ConfigSymbol]:
    result: dict[int, ConfigSymbol] = {}
    for symbol in load_config_symbols(Path("config") / version / "symbols.txt"):
        if symbol.section == ".text":
            result.setdefault(symbol.address, symbol)
    return result


def rebase_symbols_to_reference_config(symbols: list[MapSymbol], reference_symbols_path: Path) -> list[MapSymbol]:
    by_name_size: dict[tuple[str, int], list[ConfigSymbol]] = defaultdict(list)
    for symbol in load_config_symbols(reference_symbols_path):
        if symbol.section == ".text" and symbol.size not in (None, 0):
            by_name_size[(symbol.name, symbol.size)].append(symbol)

    rebased: list[MapSymbol] = []
    for symbol in symbols:
        candidates = by_name_size.get((symbol.name, symbol.size), [])
        if len(candidates) != 1:
            continue
        current = candidates[0]
        rebased.append(
            MapSymbol(
                source_path=symbol.source_path,
                object_name=symbol.object_name,
                name=symbol.name,
                address=current.address,
                size=symbol.size,
            )
        )
    return rebased


def filter_symbols(
    symbols: list[MapSymbol],
    path_filters: tuple[str, ...],
    include_local: bool,
    min_function_size: int,
) -> list[MapSymbol]:
    filtered: list[MapSymbol] = []
    for symbol in symbols:
        if path_filters and not any(value.lower() in symbol.source_path.lower() for value in path_filters):
            continue
        if symbol.size < min_function_size:
            continue
        if not trusted_name(symbol.name, include_local):
            continue
        filtered.append(symbol)
    return filtered


def function_windows(symbols: list[MapSymbol], game: str) -> list[RawWindow]:
    return [
        RawWindow(
            source_path=f"{symbol.source_path}::{symbol.name}",
            game=game,
            start=symbol.address,
            end=symbol.end,
            function_defs=((symbol.address, symbol.end, symbol.name),),
        )
        for symbol in symbols
    ]


def object_windows(symbols: list[MapSymbol], game: str) -> list[RawWindow]:
    grouped: dict[str, list[MapSymbol]] = defaultdict(list)
    for symbol in symbols:
        grouped[symbol.source_path].append(symbol)
    windows: list[RawWindow] = []
    for source_path, group in grouped.items():
        ordered = sorted(group, key=lambda item: item.address)
        windows.append(
            RawWindow(
                source_path=source_path,
                game=game,
                start=ordered[0].address,
                end=ordered[-1].end,
                function_defs=tuple((item.address, item.end, item.name) for item in ordered),
            )
        )
    return sorted(windows, key=lambda item: (item.source_path, item.start))


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parse a donor shipped MAP and signature-match its named SDK symbols "
            "against the current SFA DOL."
        )
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target SFA version")
    parser.add_argument(
        "--reference",
        type=parse_reference_spec,
        default=parse_reference_spec("final_fantasy_crystal_chronicles:GCCP01"),
        help="Reference project and config in project:config form",
    )
    parser.add_argument("--map", type=Path, help="Override reference MAP path")
    parser.add_argument(
        "--no-symbol-rebase",
        action="store_true",
        help="Use MAP VMAs directly instead of rebasing matching MAP names through reference symbols.txt",
    )
    parser.add_argument("--path-contains", action="append", default=[], help="Normalized donor source path filter")
    parser.add_argument("--target-range-start", type=parse_int, default=0x80003100)
    parser.add_argument("--target-range-end", type=parse_int, default=0x80300000)
    parser.add_argument("--min-score", type=float, default=0.88)
    parser.add_argument("--min-function-size", type=parse_int, default=0x20)
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--coarse-limit", type=int, default=40)
    parser.add_argument("--limit-per-reference", type=int, default=3)
    parser.add_argument("--include-local", action="store_true", help="Include local MAP names such as @123")
    parser.add_argument("--objects", action="store_true", help="Match whole donor objects instead of one function at a time")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    map_path = args.map or (args.reference.root / "orig" / args.reference.config / "game.MAP")
    if not map_path.is_file():
        raise SystemExit(f"Missing MAP file: {map_path}")

    donor_symbols = filter_symbols(
        load_map_text_symbols(map_path),
        tuple(args.path_contains),
        args.include_local,
        args.min_function_size,
    )
    if not args.no_symbol_rebase:
        donor_symbols = rebase_symbols_to_reference_config(donor_symbols, args.reference.symbols_path)
    raw_windows = object_windows(donor_symbols, args.reference.label) if args.objects else function_windows(donor_symbols, args.reference.label)
    hits = discover_reference_hits(
        version=args.version,
        dol_path=target_dol_path_for_version(args.version),
        references=raw_windows,
        range_start=args.target_range_start,
        range_end=args.target_range_end,
        min_score=args.min_score,
        limit=args.limit,
        limit_per_reference=args.limit_per_reference,
        only_unassigned=False,
        coarse_limit=args.coarse_limit,
        min_functions=1,
        min_span=args.min_function_size,
        min_largest_function=args.min_function_size,
        min_average_function_size=0,
    )

    current_symbols = symbol_by_address(args.version)
    mode = "objects" if args.objects else "functions"
    print(
        f"map-name-audit: ref={args.reference.label} mode={mode} symbols={len(donor_symbols)} "
        f"windows={len(raw_windows)} hits={len(hits)} min-score={args.min_score * 100:.2f}"
    )
    if not hits:
        print("matches:")
        print("   none")
        return 0

    print("matches:")
    for index, hit in enumerate(hits, start=1):
        donor = hit.reference.functions[0] if hit.reference.function_count == 1 else None
        target = hit.target.functions[0] if hit.target.function_count == 1 else None
        current = current_symbols.get(target.start) if target is not None else None
        rename_note = ""
        if donor is not None and target is not None and current is not None:
            if current.name != donor.name and is_placeholder(current.name):
                rename_note = f" rename-candidate={current.name}->{donor.name}"
            elif current.name != donor.name:
                rename_note = f" name-diff={current.name}->{donor.name}"
        print(
            f"  {index:>2}. score={hit.overall_score * 100:.2f} {verdict_for_hit(hit)} "
            f"target=0x{hit.target.start:08X}-0x{hit.target.end:08X} "
            f"ref={hit.reference.source_path} "
            f"size={hit.size_score * 100:.2f}{rename_note}"
        )
        print(f"      {describe_target_split_overlap(args.version, hit.target.start, hit.target.end)}")
        if donor is not None and target is not None:
            print(f"      donor={donor.name} target={target.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
