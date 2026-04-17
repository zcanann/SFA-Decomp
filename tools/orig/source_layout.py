from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import load_function_symbols
from tools.orig.source_boundaries import build_boundary_hints, build_split_ranges
from tools.orig.source_blueprints import BlueprintAnchor, BlueprintBlock, build_blocks, build_blueprint_anchors
from tools.orig.source_corridors import build_anchors, build_corridors
from tools.orig.source_gap_packets import SourceGapPacket, build_gap_packets
from tools.orig.source_gap_windows import GapWindowPlan, build_window_plans, debug_split_info_map
from tools.orig.source_reference_hints import build_groups, collect_reference_hints, parse_source_inventory
from tools.orig.source_recovery import parse_debug_split_text_ranges
from tools.orig.source_skeleton import build_islands
from tools.orig.source_worklist import build_work_items


CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

BROAD_EXACT_LAYOUT_LIMIT = 128
BROAD_HINTED_LAYOUT_LIMIT = 128


@dataclass(frozen=True)
class LayoutEntry:
    block_index: int
    ordinal: int
    kind: str
    retail_source_name: str
    suggested_path: str
    current_start: int
    current_end: int
    confidence: str
    source_mode: str
    reason: str
    action: str | None
    debug_size: int | None
    delta: int | None
    xref_coverage: str | None
    left_source: str | None = None
    right_source: str | None = None

    @property
    def current_size(self) -> int:
        return self.current_end - self.current_start


@dataclass(frozen=True)
class LayoutBlock:
    blueprint: BlueprintBlock
    entries: tuple[LayoutEntry, ...]
    gap_count: int
    overlap_count: int
    gap_bytes: int
    overlap_bytes: int
    score: int

    @property
    def start(self) -> int:
        return min(entry.current_start for entry in self.entries)

    @property
    def end(self) -> int:
        return max(entry.current_end for entry in self.entries)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def anchor_count(self) -> int:
        return sum(entry.kind == "anchor" for entry in self.entries)

    @property
    def gap_entry_count(self) -> int:
        return sum(entry.kind == "gap-window" for entry in self.entries)

    @property
    def placeholder_count(self) -> int:
        return sum(entry.kind == "gap-packet" for entry in self.entries)

    @property
    def contiguous(self) -> bool:
        return self.gap_count == 0 and self.overlap_count == 0


def span_text(start: int, end: int) -> str:
    return f"`0x{start:08X}-0x{end:08X}`"


def write_text_if_changed(path: Path, text: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def sanitize_filename_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "block"


def packet_key(left: str, right: str) -> tuple[str, str]:
    return left.lower(), right.lower()


def gap_plan_lookup(plans: list[GapWindowPlan]) -> dict[tuple[str, str], GapWindowPlan]:
    return {
        packet_key(plan.packet.left.retail_source_name, plan.packet.right.retail_source_name): plan
        for plan in plans
    }


def gap_packet_lookup(packets: list[SourceGapPacket]) -> dict[tuple[str, str], SourceGapPacket]:
    return {
        packet_key(packet.left.retail_source_name, packet.right.retail_source_name): packet
        for packet in packets
    }


def anchor_entry(block_index: int, ordinal: int, anchor: BlueprintAnchor) -> LayoutEntry:
    return LayoutEntry(
        block_index=block_index,
        ordinal=ordinal,
        kind="anchor",
        retail_source_name=anchor.retail_source_name,
        suggested_path=anchor.suggested_path,
        current_start=anchor.plan_start,
        current_end=anchor.plan_end,
        confidence=anchor.confidence,
        source_mode=anchor.span_source,
        reason=anchor.item.reason,
        action=anchor.action,
        debug_size=anchor.item.debug_target_size,
        delta=anchor.item.window_delta,
        xref_coverage=anchor.item.window_coverage,
    )


def gap_window_entries(
    block_index: int,
    ordinal: int,
    plan: GapWindowPlan,
) -> list[LayoutEntry]:
    entries: list[LayoutEntry] = []
    for offset, estimate in enumerate(plan.window_estimates):
        entries.append(
            LayoutEntry(
                block_index=block_index,
                ordinal=ordinal + offset,
                kind="gap-window",
                retail_source_name=estimate.basename,
                suggested_path=estimate.path,
                current_start=estimate.current_start,
                current_end=estimate.current_end,
                confidence=plan.confidence,
                source_mode=plan.layout_mode,
                reason=plan.confidence_reason,
                action=None,
                debug_size=estimate.debug_size,
                delta=estimate.scaled_delta,
                xref_coverage=None,
                left_source=plan.packet.left.retail_source_name,
                right_source=plan.packet.right.retail_source_name,
            )
        )
    return entries


def placeholder_gap_entry(
    block_index: int,
    ordinal: int,
    packet: SourceGapPacket,
) -> LayoutEntry | None:
    if packet.en_gap_start is None or packet.en_gap_end is None:
        return None
    return LayoutEntry(
        block_index=block_index,
        ordinal=ordinal,
        kind="gap-packet",
        retail_source_name=f"{packet.left.retail_source_name} -> {packet.right.retail_source_name}",
        suggested_path=",".join(packet.gap_basenames),
        current_start=packet.en_gap_start,
        current_end=packet.en_gap_end,
        confidence="low",
        source_mode="packet-only",
        reason=(
            f"{packet.gap_path_count} missing files still need per-file sizing; "
            f"resolved={packet.unique_path_count} ambiguous={packet.ambiguous_path_count} "
            f"unresolved={packet.unresolved_path_count}"
        ),
        action=None,
        debug_size=None,
        delta=None,
        xref_coverage=None,
        left_source=packet.left.retail_source_name,
        right_source=packet.right.retail_source_name,
    )


def coverage_metrics(entries: tuple[LayoutEntry, ...]) -> tuple[int, int, int, int]:
    gap_count = 0
    overlap_count = 0
    gap_bytes = 0
    overlap_bytes = 0
    for left, right in zip(entries, entries[1:]):
        if left.current_end < right.current_start:
            gap_count += 1
            gap_bytes += right.current_start - left.current_end
        elif left.current_end > right.current_start:
            overlap_count += 1
            overlap_bytes += left.current_end - right.current_start
    return gap_count, overlap_count, gap_bytes, overlap_bytes


def layout_score(block: BlueprintBlock, entries: tuple[LayoutEntry, ...], gap_count: int, overlap_count: int) -> int:
    score = block.score
    score += len(entries) * 120
    score -= gap_count * 800
    score -= overlap_count * 800
    if gap_count == 0 and overlap_count == 0:
        score += 600
    return score


def build_layout_blocks(
    blocks: list[BlueprintBlock],
    plans: list[GapWindowPlan],
    packets: list[SourceGapPacket],
) -> list[LayoutBlock]:
    plan_by_pair = gap_plan_lookup(plans)
    packet_by_pair = gap_packet_lookup(packets)

    layout_blocks: list[LayoutBlock] = []
    for block_index, block in enumerate(blocks, start=1):
        entries: list[LayoutEntry] = []
        ordinal = 1
        for index, anchor in enumerate(block.anchors):
            entries.append(anchor_entry(block_index, ordinal, anchor))
            ordinal += 1
            if index >= len(block.anchors) - 1:
                continue

            right_anchor = block.anchors[index + 1]
            key = packet_key(anchor.retail_source_name, right_anchor.retail_source_name)
            plan = plan_by_pair.get(key)
            if plan is not None:
                gap_entries = gap_window_entries(block_index, ordinal, plan)
                entries.extend(gap_entries)
                ordinal += len(gap_entries)
                continue

            packet = packet_by_pair.get(key)
            if packet is None:
                continue
            placeholder = placeholder_gap_entry(block_index, ordinal, packet)
            if placeholder is not None:
                entries.append(placeholder)
                ordinal += 1

        if not entries:
            continue
        ordered = tuple(entries)
        gap_count, overlap_count, gap_bytes, overlap_bytes = coverage_metrics(ordered)
        layout_blocks.append(
            LayoutBlock(
                blueprint=block,
                entries=ordered,
                gap_count=gap_count,
                overlap_count=overlap_count,
                gap_bytes=gap_bytes,
                overlap_bytes=overlap_bytes,
                score=layout_score(block, ordered, gap_count, overlap_count),
            )
        )

    layout_blocks.sort(key=lambda item: item.start)
    return layout_blocks


def short_entry_line(entry: LayoutEntry) -> str:
    parts = [
        f"`{entry.suggested_path}`",
        f"{span_text(entry.current_start, entry.current_end)}",
        f"size=`0x{entry.current_size:X}`",
        f"kind=`{entry.kind}`",
        f"confidence=`{entry.confidence}`",
        f"from=`{entry.source_mode}`",
    ]
    if entry.action:
        parts.append(f"action=`{entry.action}`")
    if entry.debug_size is not None:
        parts.append(f"debug=`0x{entry.debug_size:X}`")
    if entry.delta is not None:
        parts.append(f"delta=`{entry.delta:+#x}`")
    if entry.xref_coverage:
        parts.append(f"xrefs=`{entry.xref_coverage}`")
    if entry.left_source and entry.right_source:
        parts.append(f"packet=`{entry.left_source}` -> `{entry.right_source}`")
    return " ".join(parts)


def coverage_text(block: LayoutBlock) -> str:
    if block.contiguous:
        return "tiled"
    parts: list[str] = []
    if block.gap_count:
        parts.append(f"gaps=`{block.gap_count}` bytes=`0x{block.gap_bytes:X}`")
    if block.overlap_count:
        parts.append(f"overlaps=`{block.overlap_count}` bytes=`0x{block.overlap_bytes:X}`")
    return " ".join(parts)


def block_filename(index: int, width: int, block: LayoutBlock) -> str:
    first = sanitize_filename_component(Path(block.entries[0].suggested_path).stem)
    if block.entry_count == 1:
        return f"{index:0{width}d}-{first}.md"
    last = sanitize_filename_component(Path(block.entries[-1].suggested_path).stem)
    return f"{index:0{width}d}-{first}-to-{last}.md"


def ordered_path_preview(block: LayoutBlock, limit: int = 16) -> str:
    preview = " -> ".join(f"`{entry.suggested_path}`" for entry in block.entries[:limit])
    if block.entry_count > limit:
        preview += f" -> ... (+{block.entry_count - limit} more)"
    return preview


def next_steps(block: LayoutBlock) -> tuple[str, ...]:
    steps: list[str] = []
    split_now = [entry.suggested_path for entry in block.entries if entry.action == "split-now"]
    resize = [
        entry.suggested_path
        for entry in block.entries
        if entry.action in {"expand-window", "shrink-window"}
    ]
    if split_now:
        steps.append(
            "Start from the near-fit anchor rows "
            + ", ".join(f"`{path}`" for path in split_now)
            + " and use the surrounding rows only as local edge guards."
        )
    if resize:
        steps.append(
            "Resize-first files in this block are "
            + ", ".join(f"`{path}`" for path in resize)
            + "; avoid asserting final boundaries until those windows are tested."
        )
    if block.placeholder_count:
        steps.append("Resolve the remaining `gap-packet` placeholder rows before treating this block as a final file layout.")
    if block.overlap_count:
        steps.append("Keep overlapping rows in one neighborhood while working outward from the strongest retail-backed anchors.")
    if block.contiguous:
        steps.append("This block already tiles cleanly enough to use as a first-pass source skeleton.")
    if not steps:
        steps.append("Use this block as an exploratory source-order sketch and tighten the weak rows with local strings, data, or objdiff.")
    return tuple(steps)


def block_markdown(block: LayoutBlock) -> str:
    lines: list[str] = []
    lines.append(f"# Retail Source Layout Block: {span_text(block.start, block.end)}")
    lines.append("")
    lines.append("Generated by `python tools/orig/source_layout.py --materialize-all`.")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- block span: {span_text(block.start, block.end)} size=`0x{block.size:X}`")
    lines.append(f"- entries: `{block.entry_count}`")
    lines.append(f"- anchor rows: `{block.anchor_count}`")
    lines.append(f"- gap-window rows: `{block.gap_entry_count}`")
    lines.append(f"- placeholder rows: `{block.placeholder_count}`")
    lines.append(f"- layout score: `{block.score}`")
    lines.append(f"- coverage: {coverage_text(block)}")
    lines.append("- ordered paths: " + ordered_path_preview(block))
    if block.blueprint.conflict_anchor_names:
        lines.append("- overlap warnings: " + ", ".join(f"`{name}`" for name in block.blueprint.conflict_anchor_names))
    lines.append("")
    lines.append("## Ordered Layout")
    for entry in block.entries:
        lines.append(f"- {short_entry_line(entry)}")
        lines.append(f"  why: {entry.reason}")
    lines.append("")
    lines.append("## Recommended Next Steps")
    for step in next_steps(block):
        lines.append(f"- {step}")
    return "\n".join(lines) + "\n"


def block_index_markdown(blocks: list[LayoutBlock], output_root: Path) -> str:
    width = max(2, len(str(len(blocks))))
    lines = ["# Retail Source Layout Briefs", ""]
    lines.append("Generated by `python tools/orig/source_layout.py --materialize-all`.")
    lines.append("")
    for index, block in enumerate(blocks, start=1):
        filename = block_filename(index, width, block)
        lines.append(
            f"- [{filename}]({filename}) span={span_text(block.start, block.end)} entries=`{block.entry_count}` coverage={coverage_text(block)}"
        )
    lines.append("")
    lines.append(f"- Brief root: `{output_root.as_posix()}`")
    return "\n".join(lines) + "\n"


def materialize_blocks(blocks: list[LayoutBlock], output_root: Path) -> tuple[int, int]:
    written = 0
    unchanged = 0
    width = max(2, len(str(len(blocks))))
    for index, block in enumerate(blocks, start=1):
        path = output_root / block_filename(index, width, block)
        if write_text_if_changed(path, block_markdown(block)):
            written += 1
        else:
            unchanged += 1
    index_path = output_root / "README.md"
    if write_text_if_changed(index_path, block_index_markdown(blocks, output_root)):
        written += 1
    else:
        unchanged += 1
    return written, unchanged


def summary_markdown(
    layout_blocks: list[LayoutBlock],
    packets: list[SourceGapPacket],
    plans: list[GapWindowPlan],
    limit: int,
) -> str:
    ranked = sorted(layout_blocks, key=lambda item: (-item.score, item.start))
    tiled = [block for block in layout_blocks if block.contiguous]
    placeholder = [block for block in layout_blocks if block.placeholder_count]
    exact_entries = [
        entry
        for block in layout_blocks
        for entry in block.entries
        if entry.kind == "gap-window" and entry.source_mode == "exact-debug-interval"
    ]
    exact_blocks = [
        block
        for block in layout_blocks
        if any(entry.kind == "gap-window" and entry.source_mode == "exact-debug-interval" for entry in block.entries)
    ]

    lines: list[str] = []
    lines.append("# Retail source layout")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Layout blocks: `{len(layout_blocks)}`")
    lines.append(f"- Ordered file entries: `{sum(block.entry_count for block in layout_blocks)}`")
    lines.append(f"- Anchor-backed entries: `{sum(block.anchor_count for block in layout_blocks)}`")
    lines.append(f"- Gap-window entries: `{sum(block.gap_entry_count for block in layout_blocks)}`")
    lines.append(f"- Exact-debug-interval gap windows: `{len(exact_entries)}` in `{len(exact_blocks)}` blocks")
    lines.append(f"- Blocks that tile cleanly: `{len(tiled)}`")
    lines.append(f"- Blocks still carrying packet placeholders: `{len(placeholder)}`")
    lines.append(f"- Gap packets with per-file windows: `{len(plans)}/{len(packets)}`")
    lines.append("")
    lines.append("## Highest-value layouts")
    for block in ranked[:limit]:
        lines.append(
            f"- block {span_text(block.start, block.end)} size=`0x{block.size:X}` "
            f"entries=`{block.entry_count}` coverage={coverage_text(block)}"
        )
        lines.append(
            "  files: "
            + " -> ".join(f"`{entry.suggested_path}`" for entry in block.entries[:10])
            + ("" if block.entry_count <= 10 else f" -> ... (+{block.entry_count - 10} more)")
        )
        for entry in block.entries[: min(block.entry_count, 8)]:
            lines.append("  - " + short_entry_line(entry))
        if block.entry_count > 8:
            lines.append(f"  - ... (+{block.entry_count - 8} more entries)")
    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_layout.py`")
    lines.append("- Inspect one block, path, or source: `python tools/orig/source_layout.py --search expgfx modgfx curves`")
    lines.append(
        f"- Broad exact-interval layouts: `python tools/orig/source_layout.py --broad-exact-layout`"
    )
    lines.append("- Broad hint-driven layouts: `python tools/orig/source_layout.py --broad-hinted-layout`")
    lines.append("- CSV dump: `python tools/orig/source_layout.py --format csv`")
    lines.append("- JSON dump: `python tools/orig/source_layout.py --format json`")
    lines.append("- Write layout briefs: `python tools/orig/source_layout.py --materialize-all`")
    return "\n".join(lines)


def block_search_fields(block: LayoutBlock) -> list[str]:
    fields = [
        f"0x{block.start:08x}",
        f"0x{block.end:08x}",
        coverage_text(block).lower(),
    ]
    for entry in block.entries:
        fields.extend(
            [
                entry.retail_source_name.lower(),
                entry.suggested_path.lower(),
                entry.kind.lower(),
                entry.confidence.lower(),
                entry.source_mode.lower(),
                f"0x{entry.current_start:08x}",
                f"0x{entry.current_end:08x}",
            ]
        )
        if entry.action:
            fields.append(entry.action.lower())
        if entry.left_source:
            fields.append(entry.left_source.lower())
        if entry.right_source:
            fields.append(entry.right_source.lower())
    return fields


def detailed_markdown(blocks: list[LayoutBlock]) -> str:
    lines = ["# Retail source layout search", ""]
    if not blocks:
        lines.append("- No matching layout blocks.")
        return "\n".join(lines)

    for block in blocks:
        lines.append(f"## {span_text(block.start, block.end)}")
        lines.append(f"- size: `0x{block.size:X}`")
        lines.append(f"- entries: `{block.entry_count}`")
        lines.append(f"- coverage: {coverage_text(block)}")
        lines.append(f"- blueprint score: `{block.blueprint.score}`")
        if block.blueprint.conflict_anchor_names:
            lines.append("- overlap warnings: " + ", ".join(f"`{name}`" for name in block.blueprint.conflict_anchor_names))
        lines.append("- ordered files:")
        for entry in block.entries:
            lines.append(f"  - {short_entry_line(entry)}")
            lines.append(f"    why: {entry.reason}")
        lines.append("")
    return "\n".join(lines).rstrip()


def rows_to_csv(blocks: list[LayoutBlock]) -> str:
    fieldnames = [
        "block_index",
        "block_start",
        "block_end",
        "block_size",
        "block_score",
        "block_coverage",
        "ordinal",
        "kind",
        "retail_source_name",
        "suggested_path",
        "current_start",
        "current_end",
        "current_size",
        "confidence",
        "source_mode",
        "action",
        "debug_size",
        "delta",
        "xref_coverage",
        "left_source",
        "right_source",
        "reason",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for block in blocks:
        for entry in block.entries:
            writer.writerow(
                {
                    "block_index": entry.block_index,
                    "block_start": f"0x{block.start:08X}",
                    "block_end": f"0x{block.end:08X}",
                    "block_size": f"0x{block.size:X}",
                    "block_score": block.score,
                    "block_coverage": coverage_text(block),
                    "ordinal": entry.ordinal,
                    "kind": entry.kind,
                    "retail_source_name": entry.retail_source_name,
                    "suggested_path": entry.suggested_path,
                    "current_start": f"0x{entry.current_start:08X}",
                    "current_end": f"0x{entry.current_end:08X}",
                    "current_size": f"0x{entry.current_size:X}",
                    "confidence": entry.confidence,
                    "source_mode": entry.source_mode,
                    "action": entry.action or "",
                    "debug_size": "" if entry.debug_size is None else f"0x{entry.debug_size:X}",
                    "delta": "" if entry.delta is None else f"{entry.delta:+#x}",
                    "xref_coverage": entry.xref_coverage or "",
                    "left_source": entry.left_source or "",
                    "right_source": entry.right_source or "",
                    "reason": entry.reason,
                }
            )
    return buffer.getvalue()


def rows_to_json(blocks: list[LayoutBlock]) -> str:
    payload = {
        "blocks": [
            {
                "start": f"0x{block.start:08X}",
                "end": f"0x{block.end:08X}",
                "size": f"0x{block.size:X}",
                "score": block.score,
                "coverage": coverage_text(block),
                "entries": [
                    {
                        "ordinal": entry.ordinal,
                        "kind": entry.kind,
                        "retail_source_name": entry.retail_source_name,
                        "suggested_path": entry.suggested_path,
                        "current_start": f"0x{entry.current_start:08X}",
                        "current_end": f"0x{entry.current_end:08X}",
                        "current_size": f"0x{entry.current_size:X}",
                        "confidence": entry.confidence,
                        "source_mode": entry.source_mode,
                        "action": entry.action,
                        "debug_size": None if entry.debug_size is None else f"0x{entry.debug_size:X}",
                        "delta": entry.delta,
                        "xref_coverage": entry.xref_coverage,
                        "left_source": entry.left_source,
                        "right_source": entry.right_source,
                        "reason": entry.reason,
                    }
                    for entry in block.entries
                ],
            }
            for block in blocks
        ]
    }
    return json.dumps(payload, indent=2) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Flatten retail-backed anchor windows and short-gap estimates into one ordered per-file layout."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for split sizing.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for file order and size context.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for source order.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference inventory mined only for side-path hints.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side-path hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for side-path hints.")
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across file paths, retail names, and addresses.")
    parser.add_argument("--limit", type=int, default=6, help="Maximum blocks to show in summary mode.")
    parser.add_argument("--max-gap-paths", type=int, default=8, help="Maximum in-between filenames allowed when bridging anchors into one layout block.")
    parser.add_argument("--exact-interval-limit", type=int, default=16, help="Use the full exact debug interval only when it has at most this many paths.")
    parser.add_argument("--hinted-path-limit", type=int, default=8, help="Skip broad hint-only packets with more than this many uniquely resolved paths.")
    parser.add_argument("--materialize-top", type=int, default=0, help="Write the top N visible layout blocks under --output-root.")
    parser.add_argument("--materialize-all", action="store_true", help="Write every visible layout block under --output-root.")
    parser.add_argument("--output-root", type=Path, default=Path("docs/orig/source_layout_briefs"), help="Destination directory for generated layout briefs.")
    parser.add_argument(
        "--broad-exact-layout",
        action="store_true",
        help=(
            "Raise --exact-interval-limit to a broader exploratory preset so larger exact-debug "
            "corridor windows can be flattened without spelling out a custom limit."
        ),
    )
    parser.add_argument(
        "--broad-hinted-layout",
        action="store_true",
        help=(
            "Raise --hinted-path-limit to a broader exploratory preset so large global-unique "
            "hint packets can be flattened without spelling out a custom limit."
        ),
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.broad_exact_layout:
        args.exact_interval_limit = max(args.exact_interval_limit, BROAD_EXACT_LAYOUT_LIMIT)
    if args.broad_hinted_layout:
        args.hinted_path_limit = max(args.hinted_path_limit, BROAD_HINTED_LAYOUT_LIMIT)

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
    debug_functions = load_function_symbols(args.debug_symbols)
    split_ranges = build_split_ranges(args.splits)
    debug_split_ranges = parse_debug_split_text_ranges(args.debug_splits)
    debug_split_paths = list(debug_split_ranges)
    srcfiles_entries = parse_source_inventory(args.debug_srcfiles)

    hints = build_boundary_hints(
        groups,
        reference_hints,
        current_functions,
        split_ranges,
        args.dol,
    )
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
    packets = build_gap_packets(corridors, debug_split_paths, debug_split_ranges, split_ranges)
    debug_info = debug_split_info_map(debug_split_ranges, debug_functions)
    plans = build_window_plans(
        packets,
        debug_info=debug_info,
        current_split_ranges=split_ranges,
        exact_interval_limit=args.exact_interval_limit,
        hinted_path_limit=args.hinted_path_limit,
    )
    blueprint_anchors = build_blueprint_anchors(items)
    blocks = build_blocks(blueprint_anchors, packets, max_gap_paths=args.max_gap_paths)
    layout_blocks = build_layout_blocks(blocks, plans, packets)

    if args.search:
        lowered = [pattern.lower() for pattern in args.search]
        visible = [
            block
            for block in layout_blocks
            if any(any(pattern in field for field in block_search_fields(block)) for pattern in lowered)
        ]
    else:
        visible = layout_blocks

    if args.materialize_all:
        materialized_blocks = visible
    elif args.materialize_top > 0:
        materialized_blocks = visible[: args.materialize_top]
    else:
        materialized_blocks = []

    if materialized_blocks:
        written, unchanged = materialize_blocks(materialized_blocks, args.output_root)
        print(
            f"materialized={len(materialized_blocks)} written={written} unchanged={unchanged} root={args.output_root.as_posix()}",
            file=sys.stderr,
        )

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible))
        elif args.format == "json":
            sys.stdout.write(rows_to_json(visible))
        elif args.search:
            sys.stdout.write(detailed_markdown(visible))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(visible, packets, plans, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
