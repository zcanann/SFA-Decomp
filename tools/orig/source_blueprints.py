from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import load_function_symbols
from tools.orig.source_boundaries import build_boundary_hints, build_split_ranges
from tools.orig.source_corridors import build_anchors, build_corridors
from tools.orig.source_gap_packets import SourceGapPacket, build_gap_packets
from tools.orig.source_reference_hints import build_groups, collect_reference_hints, parse_source_inventory
from tools.orig.source_recovery import parse_debug_split_text_ranges
from tools.orig.source_skeleton import build_islands
from tools.orig.source_worklist import WorkItem, build_work_items


CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


@dataclass(frozen=True)
class BlueprintAnchor:
    item: WorkItem
    ordinal: int
    plan_start: int
    plan_end: int
    span_source: str

    @property
    def retail_source_name(self) -> str:
        return self.item.retail_source_name

    @property
    def suggested_path(self) -> str:
        return self.item.suggested_path

    @property
    def confidence(self) -> str:
        return self.item.confidence

    @property
    def action(self) -> str:
        return self.item.action

    @property
    def plan_size(self) -> int:
        return self.plan_end - self.plan_start


@dataclass(frozen=True)
class BlueprintBlock:
    start: int
    end: int
    anchors: tuple[BlueprintAnchor, ...]
    packets: tuple[SourceGapPacket, ...]
    conflict_anchor_names: tuple[str, ...]
    score: int

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def short_packet_count(self) -> int:
        return len(self.packets)

    @property
    def anchor_count(self) -> int:
        return len(self.anchors)


def unique_strings(values: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def span_text(start: int, end: int) -> str:
    return f"`0x{start:08X}-0x{end:08X}`"


def source_span(item: WorkItem) -> tuple[int, int, str] | None:
    if item.suggested_start is not None and item.suggested_end is not None:
        return item.suggested_start, item.suggested_end, "suggested-window"
    if item.action == "shared-island" and item.island_span_start is not None and item.island_span_end is not None:
        return item.island_span_start, item.island_span_end, "shared-island"
    if item.current_seed_start is not None and item.current_seed_end is not None:
        return item.current_seed_start, item.current_seed_end, "current-seed"
    return None


def build_blueprint_anchors(items: list[WorkItem]) -> list[BlueprintAnchor]:
    ordered_items = [
        item
        for item in items
        if item.current_seed_start is not None or item.suggested_start is not None
    ]
    ordered_items.sort(
        key=lambda item: (
            0xFFFFFFFF if item.current_seed_start is None else item.current_seed_start,
            0xFFFFFFFF if item.suggested_start is None else item.suggested_start,
            item.retail_source_name.lower(),
        )
    )

    anchors: list[BlueprintAnchor] = []
    for ordinal, item in enumerate(ordered_items, start=1):
        span = source_span(item)
        if span is None:
            continue
        plan_start, plan_end, span_source = span
        anchors.append(
            BlueprintAnchor(
                item=item,
                ordinal=ordinal,
                plan_start=plan_start,
                plan_end=plan_end,
                span_source=span_source,
            )
        )
    return anchors


def packet_lookup(packets: list[SourceGapPacket], max_gap_paths: int) -> dict[tuple[str, str], SourceGapPacket]:
    lookup: dict[tuple[str, str], SourceGapPacket] = {}
    for packet in packets:
        if packet.gap_path_count > max_gap_paths:
            continue
        key = (packet.left.retail_source_name.lower(), packet.right.retail_source_name.lower())
        lookup[key] = packet
    return lookup


def anchor_conflicts(anchors: tuple[BlueprintAnchor, ...]) -> tuple[str, ...]:
    conflicts: list[str] = []
    for index, left in enumerate(anchors):
        for right in anchors[index + 1 :]:
            if left.plan_start < right.plan_end and right.plan_start < left.plan_end:
                conflicts.extend((left.retail_source_name, right.retail_source_name))
    return unique_strings(conflicts)


def block_score(anchors: tuple[BlueprintAnchor, ...], packets: tuple[SourceGapPacket, ...], conflicts: tuple[str, ...]) -> int:
    score = sum(anchor.item.score for anchor in anchors)
    score += len(packets) * 4000
    score -= len(conflicts) * 800
    score -= sum(packet.unresolved_path_count * 240 for packet in packets)
    score -= sum(packet.ambiguous_path_count * 180 for packet in packets)
    return score


def build_blocks(anchors: list[BlueprintAnchor], packets: list[SourceGapPacket], max_gap_paths: int) -> list[BlueprintBlock]:
    if not anchors:
        return []

    packet_by_pair = packet_lookup(packets, max_gap_paths=max_gap_paths)

    blocks: list[BlueprintBlock] = []
    current_anchors: list[BlueprintAnchor] = [anchors[0]]
    current_packets: list[SourceGapPacket] = []
    current_start = anchors[0].plan_start
    current_end = anchors[0].plan_end

    for anchor in anchors[1:]:
        previous = current_anchors[-1]
        packet = packet_by_pair.get((previous.retail_source_name.lower(), anchor.retail_source_name.lower()))
        overlaps = anchor.plan_start <= current_end
        linked = packet is not None
        if overlaps or linked:
            current_anchors.append(anchor)
            if packet is not None:
                current_packets.append(packet)
                if packet.en_gap_start is not None and packet.en_gap_end is not None:
                    current_start = min(current_start, packet.en_gap_start)
                    current_end = max(current_end, packet.en_gap_end)
            current_start = min(current_start, anchor.plan_start)
            current_end = max(current_end, anchor.plan_end)
            continue

        anchor_tuple = tuple(current_anchors)
        packet_tuple = tuple(current_packets)
        conflicts = anchor_conflicts(anchor_tuple)
        blocks.append(
            BlueprintBlock(
                start=current_start,
                end=current_end,
                anchors=anchor_tuple,
                packets=packet_tuple,
                conflict_anchor_names=conflicts,
                score=block_score(anchor_tuple, packet_tuple, conflicts),
            )
        )
        current_anchors = [anchor]
        current_packets = []
        current_start = anchor.plan_start
        current_end = anchor.plan_end

    anchor_tuple = tuple(current_anchors)
    packet_tuple = tuple(current_packets)
    conflicts = anchor_conflicts(anchor_tuple)
    blocks.append(
        BlueprintBlock(
            start=current_start,
            end=current_end,
            anchors=anchor_tuple,
            packets=packet_tuple,
            conflict_anchor_names=conflicts,
            score=block_score(anchor_tuple, packet_tuple, conflicts),
        )
    )
    blocks.sort(key=lambda item: item.start)
    return blocks


def gap_path_preview(packet: SourceGapPacket, limit: int = 8) -> str:
    parts: list[str] = []
    for hint in packet.gap_path_hints[:limit]:
        if hint.resolved_paths:
            parts.append(f"`{hint.resolved_paths[0]}`")
        else:
            parts.append(f"`{hint.basename}`")
    if len(packet.gap_path_hints) > limit:
        parts.append(f"... (+{len(packet.gap_path_hints) - limit} more)")
    return ", ".join(parts) if parts else "none"


def anchor_line(anchor: BlueprintAnchor) -> str:
    parts = [
        f"`{anchor.item.suggested_path}`",
        f"action=`{anchor.item.action}`",
        f"confidence=`{anchor.item.confidence}`",
        f"plan={span_text(anchor.plan_start, anchor.plan_end)}",
        f"size=`0x{anchor.plan_size:X}`",
        f"from=`{anchor.span_source}`",
    ]
    if anchor.item.retail_labels:
        parts.append("labels=" + ",".join(f"`{label}`" for label in anchor.item.retail_labels))
    if anchor.item.window_coverage:
        parts.append(f"xrefs=`{anchor.item.window_coverage}`")
    return " ".join(parts)


def packet_line(packet: SourceGapPacket) -> str:
    parts = [
        f"gap {span_text(packet.en_gap_start, packet.en_gap_end) if packet.en_gap_start is not None and packet.en_gap_end is not None else '`none`'}",
        f"missing=`{packet.gap_path_count}`",
        f"resolved=`{packet.unique_path_count}`",
    ]
    if packet.unresolved_path_count:
        parts.append(f"unresolved=`{packet.unresolved_path_count}`")
    if packet.ambiguous_path_count:
        parts.append(f"ambiguous=`{packet.ambiguous_path_count}`")
    parts.append("files: " + gap_path_preview(packet))
    return " ".join(parts)


def residual_items(items: list[WorkItem]) -> list[WorkItem]:
    return [
        item
        for item in items
        if item.current_seed_start is None
        and item.suggested_start is None
    ]


def summary_markdown(blocks: list[BlueprintBlock], items: list[WorkItem], limit: int) -> str:
    bridged = [block for block in blocks if block.short_packet_count > 0]
    conflicted = [block for block in blocks if block.conflict_anchor_names]
    ranked = sorted(blocks, key=lambda item: (-item.score, item.start))
    residual = residual_items(items)

    lines: list[str] = []
    lines.append("# Retail source blueprint blocks")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Blueprint blocks: `{len(blocks)}`")
    lines.append(f"- Blocks bridged by short gap packets: `{len(bridged)}`")
    lines.append(f"- Blocks with overlapping planned windows: `{len(conflicted)}`")
    lines.append(f"- Retail anchors represented in blocks: `{sum(block.anchor_count for block in blocks)}`")
    lines.append(f"- Residual no-window anchors: `{len(residual)}`")
    lines.append("")

    lines.append("## Highest-Leverage Blocks")
    for block in ranked[:limit]:
        lines.append(
            f"- block {span_text(block.start, block.end)} size=`0x{block.size:X}` anchors=`{block.anchor_count}` packets=`{block.short_packet_count}`"
        )
        if block.conflict_anchor_names:
            lines.append("  overlap warnings: " + ", ".join(f"`{name}`" for name in block.conflict_anchor_names))
        for index, anchor in enumerate(block.anchors):
            lines.append("  - " + anchor_line(anchor))
            if index < len(block.anchors) - 1:
                packet = next(
                    (
                        candidate
                        for candidate in block.packets
                        if candidate.left.retail_source_name == anchor.retail_source_name
                        and candidate.right.retail_source_name == block.anchors[index + 1].retail_source_name
                    ),
                    None,
                )
                if packet is not None:
                    lines.append("    " + packet_line(packet))
    lines.append("")

    lines.append("## Residual Anchors")
    if residual:
        for item in residual:
            lines.append(f"- `{item.retail_source_name}` action=`{item.action}` target=`{item.suggested_path}`")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_blueprints.py`")
    lines.append("- Inspect one neighborhood: `python tools/orig/source_blueprints.py --search objanim objhits`")
    lines.append("- Structured dump: `python tools/orig/source_blueprints.py --format json`")
    return "\n".join(lines)


def search_fields(block: BlueprintBlock) -> list[str]:
    fields = [
        f"0x{block.start:08x}",
        f"0x{block.end:08x}",
    ]
    for anchor in block.anchors:
        fields.extend(
            [
                anchor.retail_source_name.lower(),
                anchor.suggested_path.lower(),
                anchor.action.lower(),
                anchor.confidence.lower(),
                anchor.span_source.lower(),
            ]
        )
        fields.extend(label.lower() for label in anchor.item.retail_labels)
    for packet in block.packets:
        fields.extend(
            [
                packet.left.retail_source_name.lower(),
                packet.right.retail_source_name.lower(),
                packet.split_status.lower(),
            ]
        )
        fields.extend(path.lower() for path in packet.gap_basenames)
        fields.extend(path.lower() for hint in packet.gap_path_hints for path in hint.resolved_paths)
    return fields


def detailed_markdown(blocks: list[BlueprintBlock], patterns: list[str]) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    visible = [
        block
        for block in blocks
        if any(any(pattern in field for field in search_fields(block)) for pattern in lowered)
    ]

    lines = ["# Retail source blueprint search", ""]
    if not visible:
        lines.append("- No matching blueprint blocks.")
        return "\n".join(lines)

    for block in visible:
        lines.append(f"## {span_text(block.start, block.end)}")
        lines.append(f"- size: `0x{block.size:X}`")
        lines.append(f"- anchors: `{block.anchor_count}`")
        lines.append(f"- short gap packets: `{block.short_packet_count}`")
        if block.conflict_anchor_names:
            lines.append("- overlap warnings: " + ", ".join(f"`{name}`" for name in block.conflict_anchor_names))
        lines.append("- ordered skeleton:")
        for index, anchor in enumerate(block.anchors):
            lines.append(f"  - {anchor_line(anchor)}")
            if anchor.item.current_seed_start is not None and anchor.item.current_seed_end is not None:
                lines.append(
                    f"    seed={span_text(anchor.item.current_seed_start, anchor.item.current_seed_end)} size=`0x{anchor.item.current_seed_size:X}`"
                )
            if index < len(block.anchors) - 1:
                packet = next(
                    (
                        candidate
                        for candidate in block.packets
                        if candidate.left.retail_source_name == anchor.retail_source_name
                        and candidate.right.retail_source_name == block.anchors[index + 1].retail_source_name
                    ),
                    None,
                )
                if packet is not None:
                    lines.append(f"    {packet_line(packet)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def rows_to_csv(blocks: list[BlueprintBlock]) -> str:
    fieldnames = [
        "start",
        "end",
        "size",
        "anchor_count",
        "short_packet_count",
        "conflicts",
        "anchors",
        "actions",
        "paths",
        "gap_files",
        "score",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for block in blocks:
        writer.writerow(
            {
                "start": f"0x{block.start:08X}",
                "end": f"0x{block.end:08X}",
                "size": f"0x{block.size:X}",
                "anchor_count": block.anchor_count,
                "short_packet_count": block.short_packet_count,
                "conflicts": ",".join(block.conflict_anchor_names),
                "anchors": ",".join(anchor.retail_source_name for anchor in block.anchors),
                "actions": ",".join(anchor.action for anchor in block.anchors),
                "paths": ",".join(anchor.suggested_path for anchor in block.anchors),
                "gap_files": ",".join(
                    basename
                    for packet in block.packets
                    for basename in packet.gap_basenames
                ),
                "score": block.score,
            }
        )
    return buffer.getvalue()


def rows_to_json(blocks: list[BlueprintBlock], residual: list[WorkItem]) -> str:
    payload = {
        "blocks": [
            {
                "start": f"0x{block.start:08X}",
                "end": f"0x{block.end:08X}",
                "size": f"0x{block.size:X}",
                "anchor_count": block.anchor_count,
                "short_packet_count": block.short_packet_count,
                "conflict_anchor_names": list(block.conflict_anchor_names),
                "anchors": [
                    {
                        "retail_source_name": anchor.retail_source_name,
                        "suggested_path": anchor.suggested_path,
                        "action": anchor.action,
                        "confidence": anchor.confidence,
                        "plan_start": f"0x{anchor.plan_start:08X}",
                        "plan_end": f"0x{anchor.plan_end:08X}",
                        "plan_size": f"0x{anchor.plan_size:X}",
                        "span_source": anchor.span_source,
                        "seed_start": None if anchor.item.current_seed_start is None else f"0x{anchor.item.current_seed_start:08X}",
                        "seed_end": None if anchor.item.current_seed_end is None else f"0x{anchor.item.current_seed_end:08X}",
                        "seed_size": None if anchor.item.current_seed_size is None else f"0x{anchor.item.current_seed_size:X}",
                        "retail_labels": list(anchor.item.retail_labels),
                    }
                    for anchor in block.anchors
                ],
                "packets": [
                    {
                        "left": packet.left.retail_source_name,
                        "right": packet.right.retail_source_name,
                        "en_gap_start": None if packet.en_gap_start is None else f"0x{packet.en_gap_start:08X}",
                        "en_gap_end": None if packet.en_gap_end is None else f"0x{packet.en_gap_end:08X}",
                        "en_gap_size": None if packet.en_gap_size is None else f"0x{packet.en_gap_size:X}",
                        "gap_path_count": packet.gap_path_count,
                        "resolved_count": packet.unique_path_count,
                        "ambiguous_count": packet.ambiguous_path_count,
                        "unresolved_count": packet.unresolved_path_count,
                        "gap_paths": list(packet.gap_basenames),
                        "resolved_paths": [path for hint in packet.gap_path_hints for path in hint.resolved_paths],
                    }
                    for packet in block.packets
                ],
            }
            for block in blocks
        ],
        "residual": [
            {
                "retail_source_name": item.retail_source_name,
                "suggested_path": item.suggested_path,
                "action": item.action,
                "confidence": item.confidence,
            }
            for item in residual
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge retail source anchors and short gap packets into address-ordered blueprint blocks."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for the retail source crosswalk.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for exact split-size context.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for source-order context.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference inventory mined only for side-path hints.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side-path hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for side-path hints.")
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across anchors, paths, and gap files.")
    parser.add_argument("--limit", type=int, default=6, help="Maximum blocks to show in the summary.")
    parser.add_argument("--max-gap-paths", type=int, default=8, help="Maximum in-between filenames allowed when bridging anchors into one blueprint block.")
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
    split_ranges = build_split_ranges(args.splits)
    hints = build_boundary_hints(groups, reference_hints, current_functions, split_ranges)
    debug_split_paths = list(parse_debug_split_text_ranges(args.debug_splits))
    srcfiles_entries = parse_source_inventory(args.debug_srcfiles)
    anchors = build_anchors(
        groups=groups,
        reference_hints=reference_hints,
        current_functions=current_functions,
        debug_split_paths=debug_split_paths,
        srcfiles_entries=srcfiles_entries,
    )
    corridors = build_corridors(anchors, srcfiles_entries, current_functions)
    islands = build_islands(
        hints=hints,
        current_functions=current_functions,
        split_ranges=split_ranges,
        max_gap_bytes=0x3000,
        max_gap_functions=8,
    )
    items = build_work_items(anchors, hints, corridors, islands, current_functions)
    packets = build_gap_packets(corridors, debug_split_paths, split_ranges)
    blueprint_anchors = build_blueprint_anchors(items)
    blocks = build_blocks(blueprint_anchors, packets, max_gap_paths=args.max_gap_paths)

    if args.search:
        lowered = [pattern.lower() for pattern in args.search]
        visible_blocks = [
            block
            for block in blocks
            if any(any(pattern in field for field in search_fields(block)) for pattern in lowered)
        ]
    else:
        visible_blocks = blocks

    residual = residual_items(items)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible_blocks))
        elif args.format == "json":
            sys.stdout.write(rows_to_json(visible_blocks, residual))
        elif args.search:
            sys.stdout.write(detailed_markdown(visible_blocks, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(blocks, items, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
