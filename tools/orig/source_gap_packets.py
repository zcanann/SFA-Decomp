from __future__ import annotations

import argparse
import csv
import io
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import FunctionSymbol, load_function_symbols
from tools.orig.source_boundaries import (
    build_split_ranges,
    describe_gap as describe_boundary_gap,
    split_gap_context,
)
from tools.orig.source_corridors import (
    SourceAnchor,
    SourceCorridor,
    build_anchors,
    build_corridors,
    fit_summary,
    format_symbol_span,
)
from tools.orig.source_reference_hints import build_groups, collect_reference_hints, parse_source_inventory
from tools.orig.source_recovery import parse_debug_split_text_ranges


@dataclass(frozen=True)
class GapPathHint:
    basename: str
    resolution_status: str
    resolved_paths: tuple[str, ...]


@dataclass(frozen=True)
class SourceGapPacket:
    left: SourceAnchor
    right: SourceAnchor
    gap_basenames: tuple[str, ...]
    gap_path_hints: tuple[GapPathHint, ...]
    exact_debug_interval_paths: tuple[str, ...]
    gap_functions: tuple[FunctionSymbol, ...]
    split_status: str
    current_split_paths: tuple[str, ...]
    gap_split_start: int | None
    gap_split_end: int | None
    gap_prev_path: str | None
    gap_next_path: str | None
    score: int

    @property
    def en_gap_start(self) -> int | None:
        return None if self.gap_functions == () else self.gap_functions[0].address

    @property
    def en_gap_end(self) -> int | None:
        if not self.gap_functions:
            return None
        last = self.gap_functions[-1]
        return last.address + last.size

    @property
    def en_gap_size(self) -> int | None:
        if self.en_gap_start is None or self.en_gap_end is None:
            return None
        return self.en_gap_end - self.en_gap_start

    @property
    def gap_path_count(self) -> int:
        return len(self.gap_basenames)

    @property
    def unique_path_count(self) -> int:
        return sum(hint.resolution_status in {"exact-interval", "global-unique"} for hint in self.gap_path_hints)

    @property
    def ambiguous_path_count(self) -> int:
        return sum(hint.resolution_status.startswith("ambiguous") for hint in self.gap_path_hints)

    @property
    def unresolved_path_count(self) -> int:
        return sum(hint.resolution_status == "unresolved" for hint in self.gap_path_hints)

    @property
    def exact_debug_interval_count(self) -> int:
        return len(self.exact_debug_interval_paths)


def exact_interval_paths(
    left: SourceAnchor,
    right: SourceAnchor,
    debug_split_paths: list[str],
) -> tuple[str, ...]:
    if left.debug_split_index is None or right.debug_split_index is None:
        return ()
    if left.debug_split_index >= right.debug_split_index:
        return ()
    return tuple(debug_split_paths[left.debug_split_index + 1 : right.debug_split_index])


def debug_paths_by_basename(paths: tuple[str, ...] | list[str]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for path in paths:
        mapping.setdefault(Path(path).name.lower(), []).append(path.replace("\\", "/"))
    return mapping


def resolve_gap_path(
    basename: str,
    debug_paths_by_basename: dict[str, list[str]],
    interval_paths_by_basename: dict[str, list[str]],
) -> GapPathHint:
    key = Path(basename).name.lower()
    interval_matches = tuple(interval_paths_by_basename.get(key, []))
    global_matches = tuple(debug_paths_by_basename.get(key, []))

    if len(interval_matches) == 1:
        return GapPathHint(basename=basename, resolution_status="exact-interval", resolved_paths=interval_matches)
    if len(interval_matches) > 1:
        return GapPathHint(basename=basename, resolution_status="ambiguous-interval", resolved_paths=interval_matches)
    if len(global_matches) == 1:
        return GapPathHint(basename=basename, resolution_status="global-unique", resolved_paths=global_matches)
    if len(global_matches) > 1:
        return GapPathHint(basename=basename, resolution_status="ambiguous-global", resolved_paths=global_matches)
    return GapPathHint(basename=basename, resolution_status="unresolved", resolved_paths=())


def packet_score(
    corridor: SourceCorridor,
    path_hints: tuple[GapPathHint, ...],
    split_status: str,
    exact_interval_count: int,
) -> int:
    score = 1200
    score -= len(corridor.srcfile_gap_paths) * 90
    score -= len(corridor.gap_functions) * 4
    score += sum(140 for hint in path_hints if hint.resolution_status in {"exact-interval", "global-unique"})
    score -= sum(90 for hint in path_hints if hint.resolution_status.startswith("ambiguous"))
    score -= sum(120 for hint in path_hints if hint.resolution_status == "unresolved")

    if split_status == "unsplit":
        score += 120
    elif split_status == "single-split":
        score += 40

    if len(corridor.srcfile_gap_paths) == 1:
        score += 220
    elif len(corridor.srcfile_gap_paths) <= 3:
        score += 100

    if corridor.left.fit_status == "seed-near-fit":
        score += 80
    if corridor.right.fit_status == "seed-near-fit":
        score += 80
    if corridor.left.fit_status == "seed-too-wide":
        score += 40
    if corridor.right.fit_status == "seed-too-wide":
        score += 40

    if exact_interval_count:
        score -= max(0, exact_interval_count - len(corridor.srcfile_gap_paths)) * 2
    return score


def build_gap_packets(
    corridors: list[SourceCorridor],
    debug_split_paths: list[str],
    current_split_ranges,
) -> list[SourceGapPacket]:
    debug_path_index = debug_paths_by_basename(debug_split_paths)

    packets: list[SourceGapPacket] = []
    for corridor in corridors:
        if corridor.gap_path_count == 0:
            continue
        exact_paths = exact_interval_paths(corridor.left, corridor.right, debug_split_paths)
        interval_path_index = debug_paths_by_basename(exact_paths)
        path_hints = tuple(
            resolve_gap_path(
                basename=basename,
                debug_paths_by_basename=debug_path_index,
                interval_paths_by_basename=interval_path_index,
            )
            for basename in corridor.srcfile_gap_paths
        )
        en_gap_start = None if not corridor.gap_functions else corridor.gap_functions[0].address
        en_gap_end = None if not corridor.gap_functions else corridor.gap_functions[-1].address + corridor.gap_functions[-1].size
        split_status, current_split_paths, gap_split_start, gap_split_end, gap_prev_path, gap_next_path = split_gap_context(
            current_split_ranges,
            en_gap_start,
            en_gap_end,
        )
        packets.append(
            SourceGapPacket(
                left=corridor.left,
                right=corridor.right,
                gap_basenames=corridor.srcfile_gap_paths,
                gap_path_hints=path_hints,
                exact_debug_interval_paths=exact_paths,
                gap_functions=corridor.gap_functions,
                split_status=split_status,
                current_split_paths=current_split_paths,
                gap_split_start=gap_split_start,
                gap_split_end=gap_split_end,
                gap_prev_path=gap_prev_path,
                gap_next_path=gap_next_path,
                score=packet_score(corridor, path_hints, split_status, len(exact_paths)),
            )
        )

    packets.sort(key=lambda item: (-item.score, item.left.retail_source_name.lower(), item.right.retail_source_name.lower()))
    return packets


def describe_packet_gap(packet: SourceGapPacket) -> str:
    dummy = type(
        "PacketGap",
        (),
        {
            "split_status": packet.split_status,
            "current_split_paths": packet.current_split_paths,
            "gap_start": packet.gap_split_start,
            "gap_end": packet.gap_split_end,
            "gap_prev_path": packet.gap_prev_path,
            "gap_next_path": packet.gap_next_path,
        },
    )
    return describe_boundary_gap(dummy)  # type: ignore[arg-type]


def gap_path_preview(packet: SourceGapPacket, limit: int = 6) -> str:
    parts: list[str] = []
    for hint in packet.gap_path_hints[:limit]:
        if hint.resolved_paths:
            rendered = ", ".join(f"`{path}`" for path in hint.resolved_paths[:2])
            if len(hint.resolved_paths) > 2:
                rendered += f", ... (+{len(hint.resolved_paths) - 2} more)"
            parts.append(f"`{hint.basename}` -> {rendered} ({hint.resolution_status})")
        else:
            parts.append(f"`{hint.basename}` ({hint.resolution_status})")
    if len(packet.gap_path_hints) > limit:
        parts.append(f"... (+{len(packet.gap_path_hints) - limit} more)")
    return "; ".join(parts) if parts else "none"


def exact_interval_preview(packet: SourceGapPacket, limit: int = 6) -> str:
    if not packet.exact_debug_interval_paths:
        return "none"
    preview = ", ".join(f"`{path}`" for path in packet.exact_debug_interval_paths[:limit])
    if len(packet.exact_debug_interval_paths) > limit:
        preview += f", ... (+{len(packet.exact_debug_interval_paths) - limit} more)"
    return preview


def function_preview(functions: tuple[FunctionSymbol, ...], limit: int = 8) -> str:
    if not functions:
        return "none"
    preview = ", ".join(f"`{format_symbol_span(function)}`" for function in functions[:limit])
    if len(functions) > limit:
        preview += f", ... (+{len(functions) - limit} more)"
    return preview


def summary_markdown(packets: list[SourceGapPacket], limit: int) -> str:
    single_file = [packet for packet in packets if packet.gap_path_count == 1]
    short_multi = [
        packet
        for packet in packets
        if 2 <= packet.gap_path_count <= 6 and packet.unresolved_path_count == 0 and packet.ambiguous_path_count == 0
    ]
    fully_resolved = [packet for packet in packets if packet.unresolved_path_count == 0 and packet.ambiguous_path_count == 0]
    unsplit = [packet for packet in packets if packet.split_status == "unsplit"]
    broad = [packet for packet in packets if packet.gap_path_count >= 8]

    lines: list[str] = []
    lines.append("# Retail source gap packets")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Source-order gap packets: `{len(packets)}`")
    lines.append(f"- One-file packets: `{len(single_file)}`")
    lines.append(f"- Fully resolved short multi-file packets (2-6 names): `{len(short_multi)}`")
    lines.append(f"- Fully resolved gap-path packets: `{len(fully_resolved)}`")
    lines.append(f"- Packets still outside current `splits.txt` coverage: `{len(unsplit)}`")
    lines.append("")

    lines.append("## Highest-value one-file packets")
    if single_file:
        for packet in single_file[:limit]:
            gap_text = "unknown"
            if packet.en_gap_start is not None and packet.en_gap_end is not None and packet.en_gap_size is not None:
                gap_text = f"`0x{packet.en_gap_start:08X}-0x{packet.en_gap_end:08X}` size=`0x{packet.en_gap_size:X}`"
            lines.append(
                f"- `{packet.left.retail_source_name}` -> `{packet.right.retail_source_name}` "
                f"gap={gap_text} functions=`{len(packet.gap_functions)}`"
            )
            lines.append("  missing file: " + gap_path_preview(packet, limit=2))
            lines.append("  current split status: " + describe_packet_gap(packet))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Fully Resolved Short Multi-File Packets")
    if short_multi:
        for packet in short_multi[:limit]:
            gap_text = "unknown"
            if packet.en_gap_size is not None:
                gap_text = f"`0x{packet.en_gap_size:X}`"
            lines.append(
                f"- `{packet.left.retail_source_name}` -> `{packet.right.retail_source_name}` "
                f"missing=`{packet.gap_path_count}` en_gap={gap_text} functions=`{len(packet.gap_functions)}`"
            )
            lines.append("  path hints: " + gap_path_preview(packet))
            if 0 < packet.exact_debug_interval_count <= 16:
                lines.append("  exact debug interval: " + exact_interval_preview(packet))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Broad Neighborhood Packets")
    if broad:
        for packet in broad[: min(limit, len(broad))]:
            lines.append(
                f"- `{packet.left.retail_source_name}` -> `{packet.right.retail_source_name}` "
                f"missing=`{packet.gap_path_count}` unresolved=`{packet.unresolved_path_count}` ambiguous=`{packet.ambiguous_path_count}`"
            )
            lines.append("  first hints: " + gap_path_preview(packet))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_gap_packets.py`")
    lines.append("- Inspect one corridor or missing file: `python tools/orig/source_gap_packets.py --search objanim objhits`")
    lines.append("- CSV dump: `python tools/orig/source_gap_packets.py --format csv`")
    return "\n".join(lines)


def search_markdown(packets: list[SourceGapPacket], patterns: list[str]) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    visible: list[SourceGapPacket] = []
    for packet in packets:
        fields = [
            packet.left.retail_source_name.lower(),
            packet.right.retail_source_name.lower(),
            packet.left.suggested_path.lower(),
            packet.right.suggested_path.lower(),
            packet.left.fit_status.lower(),
            packet.right.fit_status.lower(),
            packet.split_status.lower(),
        ]
        fields.extend(item.lower() for item in packet.gap_basenames)
        fields.extend(hint.resolution_status.lower() for hint in packet.gap_path_hints)
        fields.extend(path.lower() for hint in packet.gap_path_hints for path in hint.resolved_paths)
        fields.extend(path.lower() for path in packet.exact_debug_interval_paths)
        fields.extend(function.name.lower() for function in packet.gap_functions)
        if packet.en_gap_start is not None:
            fields.append(f"0x{packet.en_gap_start:08x}")
        if packet.en_gap_end is not None:
            fields.append(f"0x{packet.en_gap_end:08x}")
        if any(any(pattern in field for field in fields) for pattern in lowered):
            visible.append(packet)

    lines = ["# Retail source gap packet search", ""]
    if not visible:
        lines.append("- No matching source gap packets.")
        return "\n".join(lines)

    for packet in visible:
        lines.append(f"## `{packet.left.retail_source_name}` -> `{packet.right.retail_source_name}`")
        lines.append(f"- left anchor: `{packet.left.suggested_path}` {fit_summary(packet.left)}")
        lines.append(f"- right anchor: `{packet.right.suggested_path}` {fit_summary(packet.right)}")
        if packet.en_gap_start is not None and packet.en_gap_end is not None and packet.en_gap_size is not None:
            lines.append(
                f"- current EN gap: `0x{packet.en_gap_start:08X}-0x{packet.en_gap_end:08X}` "
                f"size=`0x{packet.en_gap_size:X}` functions=`{len(packet.gap_functions)}`"
            )
        else:
            lines.append(f"- current EN gap: no uncovered functions between anchors (`{len(packet.gap_functions)}` functions)")
        lines.append("- current split status: " + describe_packet_gap(packet))
        lines.append("- gap path hints: " + gap_path_preview(packet, limit=12))
        lines.append("- gap EN functions: " + function_preview(packet.gap_functions))
        lines.append("- exact debug interval: " + exact_interval_preview(packet, limit=12))
        lines.append("")
    return "\n".join(lines).rstrip()


def rows_to_csv(packets: list[SourceGapPacket]) -> str:
    fieldnames = [
        "left_source",
        "left_path",
        "left_fit_status",
        "right_source",
        "right_path",
        "right_fit_status",
        "gap_basenames",
        "gap_path_count",
        "unique_path_count",
        "ambiguous_path_count",
        "unresolved_path_count",
        "resolved_paths",
        "resolution_statuses",
        "en_gap_start",
        "en_gap_end",
        "en_gap_size",
        "gap_function_count",
        "gap_functions",
        "split_status",
        "current_split_paths",
        "gap_split_start",
        "gap_split_end",
        "gap_prev_path",
        "gap_next_path",
        "exact_debug_interval_count",
        "exact_debug_interval_paths",
        "score",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for packet in packets:
        writer.writerow(
            {
                "left_source": packet.left.retail_source_name,
                "left_path": packet.left.suggested_path,
                "left_fit_status": packet.left.fit_status,
                "right_source": packet.right.retail_source_name,
                "right_path": packet.right.suggested_path,
                "right_fit_status": packet.right.fit_status,
                "gap_basenames": ",".join(packet.gap_basenames),
                "gap_path_count": packet.gap_path_count,
                "unique_path_count": packet.unique_path_count,
                "ambiguous_path_count": packet.ambiguous_path_count,
                "unresolved_path_count": packet.unresolved_path_count,
                "resolved_paths": ",".join(path for hint in packet.gap_path_hints for path in hint.resolved_paths),
                "resolution_statuses": ",".join(hint.resolution_status for hint in packet.gap_path_hints),
                "en_gap_start": "" if packet.en_gap_start is None else f"0x{packet.en_gap_start:08X}",
                "en_gap_end": "" if packet.en_gap_end is None else f"0x{packet.en_gap_end:08X}",
                "en_gap_size": "" if packet.en_gap_size is None else f"0x{packet.en_gap_size:X}",
                "gap_function_count": len(packet.gap_functions),
                "gap_functions": ",".join(format_symbol_span(function) for function in packet.gap_functions),
                "split_status": packet.split_status,
                "current_split_paths": ",".join(packet.current_split_paths),
                "gap_split_start": "" if packet.gap_split_start is None else f"0x{packet.gap_split_start:08X}",
                "gap_split_end": "" if packet.gap_split_end is None else f"0x{packet.gap_split_end:08X}",
                "gap_prev_path": packet.gap_prev_path or "",
                "gap_next_path": packet.gap_next_path or "",
                "exact_debug_interval_count": packet.exact_debug_interval_count,
                "exact_debug_interval_paths": ",".join(packet.exact_debug_interval_paths),
                "score": packet.score,
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Turn retail-backed source corridors into ready-to-work missing-file gap packets."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for the retail source crosswalk.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for path resolution.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for approximate source order.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference inventory mined only for side-path hints.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side-path hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for side-path hints.")
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across anchor names, gap basenames, resolved paths, and EN gap functions.")
    parser.add_argument("--limit", type=int, default=6, help="Maximum rows to show in summary sections.")
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    groups = build_groups(
        dol=args.dol,
        symbols=args.symbols,
        debug_symbols=args.debug_symbols,
        debug_splits=args.debug_splits,
        debug_srcfiles=args.debug_srcfiles,
    )
    reference_hints = collect_reference_hints(
        groups=groups,
        reference_configure=args.reference_configure,
        reference_symbols=args.reference_symbols,
        reference_inventory=args.reference_inventory,
        reference_dll_registry=args.reference_dll_registry,
        reference_object_xmls=tuple(args.reference_object_xml),
    )
    current_functions = load_function_symbols(args.symbols)
    debug_split_paths = list(parse_debug_split_text_ranges(args.debug_splits))
    srcfiles_entries = parse_source_inventory(args.debug_srcfiles)
    current_split_ranges = build_split_ranges(args.splits)

    anchors = build_anchors(
        groups=groups,
        reference_hints=reference_hints,
        current_functions=current_functions,
        debug_split_paths=debug_split_paths,
        srcfiles_entries=srcfiles_entries,
    )
    corridors = build_corridors(anchors, srcfiles_entries, current_functions)
    packets = build_gap_packets(corridors, debug_split_paths, current_split_ranges)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(packets))
        elif args.search:
            sys.stdout.write(search_markdown(packets, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(packets, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
