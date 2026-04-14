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

from tools.orig.dol_xrefs import FunctionSymbol, load_function_symbols
from tools.orig.source_boundaries import (
    BoundaryHint,
    build_boundary_hints,
    build_split_ranges,
    format_symbol_span,
)
from tools.orig.source_corridors import (
    SourceAnchor,
    SourceCorridor,
    build_anchors,
    build_corridors,
)
from tools.orig.source_reference_hints import (
    build_groups,
    collect_reference_hints,
    parse_source_inventory,
)
from tools.orig.source_recovery import parse_debug_split_text_ranges
from tools.orig.source_skeleton import SourceIsland, build_islands


ACTION_ORDER = {
    "split-now": 0,
    "expand-window": 1,
    "shrink-window": 2,
    "shared-island": 3,
    "corridor-packet": 4,
    "seed-only": 5,
    "no-en-xrefs": 6,
}

CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


@dataclass(frozen=True)
class WindowEstimate:
    start_index: int
    end_index: int
    start: int
    end: int
    size: int
    target_size: int
    delta: int
    covered_xrefs: int
    total_xrefs: int
    score: int

    @property
    def coverage_text(self) -> str:
        return f"{self.covered_xrefs}/{self.total_xrefs}"


@dataclass(frozen=True)
class WorkItem:
    retail_source_name: str
    suggested_path: str
    action: str
    confidence: str
    reason: str
    xref_count: int
    retail_labels: tuple[str, ...]
    current_seed_start: int | None
    current_seed_end: int | None
    current_seed_size: int | None
    current_seed_functions: int
    suggested_start: int | None
    suggested_end: int | None
    suggested_size: int | None
    debug_target_size: int | None
    window_delta: int | None
    window_coverage: str | None
    split_status: str
    fit_status: str | None
    bundle_count: int
    xref_functions: tuple[str, ...]
    island_sources: tuple[str, ...]
    island_span_start: int | None
    island_span_end: int | None
    prev_corridor_paths: tuple[str, ...]
    next_corridor_paths: tuple[str, ...]
    debug_prev_paths: tuple[str, ...]
    debug_next_paths: tuple[str, ...]
    score: int


def unique_strings(values: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def basename(path: str) -> str:
    return Path(path).name


def write_text_if_changed(path: Path, text: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def sanitize_filename_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "item"


def lookup_by_name(items, key: str = "retail_source_name") -> dict[str, object]:
    mapping: dict[str, object] = {}
    for item in items:
        mapping[getattr(item, key).lower()] = item
    return mapping


def build_corridor_lookup(corridors: list[SourceCorridor]) -> tuple[dict[str, SourceCorridor], dict[str, SourceCorridor]]:
    prev_by_name: dict[str, SourceCorridor] = {}
    next_by_name: dict[str, SourceCorridor] = {}
    for corridor in corridors:
        prev_by_name[corridor.right.retail_source_name.lower()] = corridor
        next_by_name[corridor.left.retail_source_name.lower()] = corridor
    return prev_by_name, next_by_name


def build_island_lookup(islands: list[SourceIsland]) -> dict[str, SourceIsland]:
    mapping: dict[str, SourceIsland] = {}
    for island in islands:
        for member in island.members:
            mapping[member.hint.retail_source_name.lower()] = island
    return mapping


def envelope_indices(
    current_functions: list[FunctionSymbol],
    anchor: SourceAnchor,
    island: SourceIsland | None,
    radius: int = 16,
    max_radius: int = 128,
) -> tuple[int, int] | None:
    if anchor.function_start_index is None or anchor.function_end_index is None:
        return None
    start_index = anchor.function_start_index
    end_index = anchor.function_end_index
    if island is not None:
        start_index = min(start_index, island.function_start_index)
        end_index = max(end_index, island.function_end_index)
    min_index = max(0, start_index - radius)
    max_index = min(len(current_functions) - 1, end_index + radius)

    if anchor.debug_split_size is None or anchor.debug_split_size <= 0:
        return min_index, max_index

    target_span = int(anchor.debug_split_size * 1.25)
    while True:
        span_start = current_functions[min_index].address
        span_end = current_functions[max_index].address + current_functions[max_index].size
        if span_end - span_start >= target_span:
            return min_index, max_index
        if min_index == 0 and max_index == len(current_functions) - 1:
            return min_index, max_index
        grown = False
        if min_index > 0 and start_index - min_index < max_radius:
            min_index -= 1
            grown = True
        if max_index < len(current_functions) - 1 and max_index - end_index < max_radius:
            max_index += 1
            grown = True
        if not grown:
            return min_index, max_index


def estimate_window(
    current_functions: list[FunctionSymbol],
    anchor: SourceAnchor,
    hint: BoundaryHint,
    island: SourceIsland | None,
) -> WindowEstimate | None:
    if anchor.debug_split_size is None or anchor.debug_split_size <= 0:
        return None
    envelope = envelope_indices(current_functions, anchor, island)
    if envelope is None:
        return None

    min_index, max_index = envelope
    if min_index > max_index:
        return None

    xref_addresses = {function.address for function in hint.xref_functions}
    if not xref_addresses:
        return None

    index_by_address = {function.address: index for index, function in enumerate(current_functions)}
    xref_indices = [index_by_address[address] for address in xref_addresses if address in index_by_address]
    if not xref_indices:
        return None

    best: WindowEstimate | None = None
    for start_index in range(min_index, max_index + 1):
        start_addr = current_functions[start_index].address
        for end_index in range(start_index, max_index + 1):
            end_function = current_functions[end_index]
            end_addr = end_function.address + end_function.size
            size = end_addr - start_addr
            covered = sum(1 for index in xref_indices if start_index <= index <= end_index)
            if covered == 0:
                continue

            delta = size - anchor.debug_split_size
            coverage_ratio = covered / len(xref_indices)
            score = 0
            score += int(coverage_ratio * 100000)
            score -= abs(delta) * 8
            score -= (end_index - start_index) * 6
            if start_index <= anchor.function_start_index <= end_index:
                score += 1200
            if start_index <= anchor.function_end_index <= end_index:
                score += 1200
            if anchor.fit_status == "seed-too-small" and delta >= 0:
                score += 600
            if anchor.fit_status == "seed-too-wide" and delta <= 0:
                score += 600
            if island is not None:
                if start_index >= island.function_start_index and end_index <= island.function_end_index:
                    score += 300
                else:
                    score -= 300

            candidate = WindowEstimate(
                start_index=start_index,
                end_index=end_index,
                start=start_addr,
                end=end_addr,
                size=size,
                target_size=anchor.debug_split_size,
                delta=delta,
                covered_xrefs=covered,
                total_xrefs=len(xref_indices),
                score=score,
            )
            if best is None or candidate.score > best.score:
                best = candidate
    return best


def window_text(estimate: WindowEstimate | None) -> tuple[int | None, int | None, int | None, int | None, str | None]:
    if estimate is None:
        return None, None, None, None, None
    return (
        estimate.start,
        estimate.end,
        estimate.size,
        estimate.delta,
        estimate.coverage_text,
    )


def classify_anchor(
    anchor: SourceAnchor,
    hint: BoundaryHint,
    island: SourceIsland | None,
    prev_corridor: SourceCorridor | None,
    next_corridor: SourceCorridor | None,
    estimate: WindowEstimate | None,
) -> tuple[str, str, str]:
    if anchor.en_span_size is None:
        return "no-en-xrefs", "low", "Retail source tag exists, but no current EN text xref resolved yet."

    if anchor.debug_split_size is not None:
        if anchor.fit_status == "seed-near-fit":
            if island is not None and island.member_count > 1:
                members = ", ".join(f"`{name}`" for name in island.source_names)
                return (
                    "shared-island",
                    "medium",
                    f"Seed is already near the debug split size, but it shares one EN island with {members}.",
                )
            return (
                "split-now",
                "high",
                "Seed is already close to the debug split size and has enough retail evidence to start a first-pass split.",
            )
        if anchor.fit_status == "seed-too-small":
            if estimate is not None:
                return (
                    "expand-window",
                    "high" if estimate.covered_xrefs == estimate.total_xrefs else "medium",
                    f"Seed is smaller than the debug split size; expand toward `0x{estimate.start:08X}-0x{estimate.end:08X}` first.",
                )
            return (
                "expand-window",
                "medium",
                "Seed is smaller than the debug split size; expand into adjacent functions before naming a final boundary.",
            )
        if anchor.fit_status == "seed-too-wide":
            if estimate is not None:
                return (
                    "shrink-window",
                    "medium",
                    f"Seed is wider than the debug split size; the best compact candidate is `0x{estimate.start:08X}-0x{estimate.end:08X}`.",
                )
            return (
                "shrink-window",
                "low",
                "Seed is wider than the debug split size; narrow it before materializing a file boundary.",
            )

    if island is not None and island.member_count > 1:
        members = ", ".join(f"`{name}`" for name in island.source_names)
        return (
            "shared-island",
            "medium",
            f"Retail tags already define a shared EN island with {members}; split the island before naming leaf functions.",
        )

    corridor_names = unique_strings(
        [*(prev_corridor.srcfile_gap_paths if prev_corridor is not None else ()), *(next_corridor.srcfile_gap_paths if next_corridor is not None else ())]
    )
    if corridor_names:
        preview = ", ".join(f"`{basename(path)}`" for path in corridor_names[:5])
        return (
            "corridor-packet",
            "medium",
            f"Retail seed is best treated as one packet inside a debug-side source corridor containing {preview}.",
        )

    if hint.xref_count > 0:
        return (
            "seed-only",
            "low",
            "Retail source tag resolves to current EN code, but there is not enough size/order context yet for a stronger boundary claim.",
        )
    return "no-en-xrefs", "low", "Retail source tag exists, but no current EN anchor is ready."


def priority_score(action: str, confidence: str, hint: BoundaryHint, anchor: SourceAnchor, estimate: WindowEstimate | None) -> int:
    score = 0
    score += (len(ACTION_ORDER) - ACTION_ORDER[action]) * 100000
    score += (len(CONFIDENCE_ORDER) - CONFIDENCE_ORDER[confidence]) * 20000
    score += hint.xref_count * 3000
    score += len(hint.retail_labels) * 1200
    score += len(hint.bundle_ids) * 800
    if estimate is not None:
        score += estimate.covered_xrefs * 500
        score -= abs(estimate.delta)
    elif anchor.debug_split_size is not None and anchor.size_delta is not None:
        score -= abs(anchor.size_delta)
    return score


def build_work_items(
    anchors: list[SourceAnchor],
    hints: list[BoundaryHint],
    corridors: list[SourceCorridor],
    islands: list[SourceIsland],
    current_functions: list[FunctionSymbol],
) -> list[WorkItem]:
    hint_by_name = lookup_by_name(hints)
    prev_corridor_by_name, next_corridor_by_name = build_corridor_lookup(corridors)
    island_by_name = build_island_lookup(islands)

    items: list[WorkItem] = []
    for anchor in anchors:
        hint = hint_by_name[anchor.retail_source_name.lower()]
        assert isinstance(hint, BoundaryHint)
        prev_corridor = prev_corridor_by_name.get(anchor.retail_source_name.lower())
        next_corridor = next_corridor_by_name.get(anchor.retail_source_name.lower())
        island = island_by_name.get(anchor.retail_source_name.lower())
        estimate = estimate_window(current_functions, anchor, hint, island)
        action, confidence, reason = classify_anchor(anchor, hint, island, prev_corridor, next_corridor, estimate)
        suggested_start, suggested_end, suggested_size, window_delta, coverage = window_text(estimate)

        island_sources = ()
        island_span_start = None
        island_span_end = None
        if island is not None:
            island_sources = island.source_names
            island_span_start = island.span_start
            island_span_end = island.span_end

        score = priority_score(action, confidence, hint, anchor, estimate)
        items.append(
            WorkItem(
                retail_source_name=anchor.retail_source_name,
                suggested_path=anchor.suggested_path,
                action=action,
                confidence=confidence,
                reason=reason,
                xref_count=anchor.xref_count,
                retail_labels=anchor.retail_labels,
                current_seed_start=anchor.en_span_start,
                current_seed_end=anchor.en_span_end,
                current_seed_size=anchor.en_span_size,
                current_seed_functions=anchor.en_function_count,
                suggested_start=suggested_start,
                suggested_end=suggested_end,
                suggested_size=suggested_size,
                debug_target_size=anchor.debug_split_size,
                window_delta=window_delta,
                window_coverage=coverage,
                split_status=hint.split_status,
                fit_status=None if anchor.debug_split_size is None else anchor.fit_status,
                bundle_count=len(hint.bundle_ids),
                xref_functions=tuple(format_symbol_span(function) for function in hint.xref_functions),
                island_sources=island_sources,
                island_span_start=island_span_start,
                island_span_end=island_span_end,
                prev_corridor_paths=() if prev_corridor is None else prev_corridor.srcfile_gap_paths,
                next_corridor_paths=() if next_corridor is None else next_corridor.srcfile_gap_paths,
                debug_prev_paths=anchor.split_prev_paths,
                debug_next_paths=anchor.split_next_paths,
                score=score,
            )
        )

    items.sort(
        key=lambda item: (
            ACTION_ORDER[item.action],
            CONFIDENCE_ORDER[item.confidence],
            -item.score,
            item.retail_source_name.lower(),
        )
    )
    return items


def preview_paths(paths: tuple[str, ...], limit: int = 5) -> str:
    if not paths:
        return "none"
    preview = ", ".join(f"`{basename(path)}`" for path in paths[:limit])
    if len(paths) > limit:
        preview += f", ... (+{len(paths) - limit} more)"
    return preview


def span_text(start: int | None, end: int | None, size: int | None) -> str:
    if start is None or end is None or size is None:
        return "none"
    return f"`0x{start:08X}-0x{end:08X}` size=`0x{size:X}`"


def markdown_for_item(item: WorkItem) -> list[str]:
    lines = [
        f"- `{item.retail_source_name}` action=`{item.action}` confidence=`{item.confidence}` target=`{item.suggested_path}`"
    ]
    lines.append(
        "  current seed: "
        + span_text(item.current_seed_start, item.current_seed_end, item.current_seed_size)
        + f" functions=`{item.current_seed_functions}` xrefs=`{item.xref_count}`"
    )
    if item.debug_target_size is not None:
        lines.append(
            f"  debug target: `0x{item.debug_target_size:X}` fit=`{item.fit_status}`"
        )
    if item.suggested_start is not None:
        lines.append(
            "  suggested window: "
            + span_text(item.suggested_start, item.suggested_end, item.suggested_size)
            + f" delta=`{item.window_delta:+#x}` xrefs=`{item.window_coverage}`"
        )
    if item.retail_labels:
        lines.append("  retail labels: " + ", ".join(f"`{label}`" for label in item.retail_labels))
    if item.island_sources and len(item.island_sources) > 1:
        lines.append(
            "  shared island: "
            + ", ".join(f"`{name}`" for name in item.island_sources)
            + f" span={span_text(item.island_span_start, item.island_span_end, None if item.island_span_start is None or item.island_span_end is None else item.island_span_end - item.island_span_start)}"
        )
    if item.prev_corridor_paths:
        lines.append("  previous corridor: " + preview_paths(item.prev_corridor_paths))
    if item.next_corridor_paths:
        lines.append("  next corridor: " + preview_paths(item.next_corridor_paths))
    if item.debug_prev_paths or item.debug_next_paths:
        parts: list[str] = []
        if item.debug_prev_paths:
            parts.append("before " + preview_paths(item.debug_prev_paths))
        if item.debug_next_paths:
            parts.append("after " + preview_paths(item.debug_next_paths))
        lines.append("  debug neighbors: " + "; ".join(parts))
    lines.append("  why: " + item.reason)
    return lines


def summary_markdown(items: list[WorkItem], limit: int) -> str:
    split_now = [item for item in items if item.action == "split-now"]
    resize = [item for item in items if item.action in {"expand-window", "shrink-window"}]
    packets = [item for item in items if item.action in {"shared-island", "corridor-packet"}]
    residual = [item for item in items if item.action in {"seed-only", "no-en-xrefs"}]

    lines: list[str] = []
    lines.append("# Retail source boundary worklist")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Worklist entries: `{len(items)}`")
    lines.append(f"- `split-now` candidates: `{len(split_now)}`")
    lines.append(f"- resize candidates (`expand-window` / `shrink-window`): `{len(resize)}`")
    lines.append(f"- packet-style candidates (`shared-island` / `corridor-packet`): `{len(packets)}`")
    lines.append(f"- low-signal residuals: `{len(residual)}`")
    lines.append("")

    lines.append("## Split Now")
    if split_now:
        for item in split_now[:limit]:
            lines.extend(markdown_for_item(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Resize First")
    if resize:
        for item in resize[:limit]:
            lines.extend(markdown_for_item(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Packet Work")
    if packets:
        for item in packets[:limit]:
            lines.extend(markdown_for_item(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Low-Signal Residuals")
    if residual:
        for item in residual[: min(limit, len(residual))]:
            lines.append(
                f"- `{item.retail_source_name}` action=`{item.action}` confidence=`{item.confidence}` target=`{item.suggested_path}`"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_worklist.py`")
    lines.append("- Search one file or action: `python tools/orig/source_worklist.py --search SHthorntail split-now corridor`")
    lines.append("- CSV dump: `python tools/orig/source_worklist.py --format csv`")
    lines.append("- JSON dump: `python tools/orig/source_worklist.py --format json`")
    lines.append("- Write packet briefs: `python tools/orig/source_worklist.py --materialize-all`")
    return "\n".join(lines)


def search_markdown(items: list[WorkItem]) -> str:
    lines = ["# Retail source boundary worklist search", ""]
    if not items:
        lines.append("- No matching worklist entries.")
        return "\n".join(lines)

    for item in items:
        lines.extend(markdown_for_item(item))
    return "\n".join(lines)


def item_matches(item: WorkItem, patterns: list[str]) -> bool:
    lowered = [pattern.lower() for pattern in patterns]
    fields = [
        item.retail_source_name.lower(),
        item.suggested_path.lower(),
        item.action.lower(),
        item.confidence.lower(),
        item.reason.lower(),
    ]
    fields.extend(label.lower() for label in item.retail_labels)
    fields.extend(path.lower() for path in item.island_sources)
    fields.extend(path.lower() for path in item.prev_corridor_paths)
    fields.extend(path.lower() for path in item.next_corridor_paths)
    fields.extend(path.lower() for path in item.debug_prev_paths)
    fields.extend(path.lower() for path in item.debug_next_paths)
    return any(any(pattern in field for field in fields) for pattern in lowered)


def filter_items(items: list[WorkItem], patterns: list[str] | None) -> list[WorkItem]:
    if not patterns:
        return list(items)
    return [item for item in items if item_matches(item, patterns)]


def rows_to_json(items: list[WorkItem]) -> str:
    rows: list[dict[str, object]] = []
    for item in items:
        rows.append(
            {
                "retail_source_name": item.retail_source_name,
                "suggested_path": item.suggested_path,
                "action": item.action,
                "confidence": item.confidence,
                "reason": item.reason,
                "xref_count": item.xref_count,
                "retail_labels": list(item.retail_labels),
                "current_seed_start": None if item.current_seed_start is None else f"0x{item.current_seed_start:08X}",
                "current_seed_end": None if item.current_seed_end is None else f"0x{item.current_seed_end:08X}",
                "current_seed_size": None if item.current_seed_size is None else f"0x{item.current_seed_size:X}",
                "current_seed_functions": item.current_seed_functions,
                "suggested_start": None if item.suggested_start is None else f"0x{item.suggested_start:08X}",
                "suggested_end": None if item.suggested_end is None else f"0x{item.suggested_end:08X}",
                "suggested_size": None if item.suggested_size is None else f"0x{item.suggested_size:X}",
                "debug_target_size": None if item.debug_target_size is None else f"0x{item.debug_target_size:X}",
                "window_delta": item.window_delta,
                "window_coverage": item.window_coverage,
                "split_status": item.split_status,
                "fit_status": item.fit_status,
                "bundle_count": item.bundle_count,
                "xref_functions": list(item.xref_functions),
                "island_sources": list(item.island_sources),
                "island_span_start": None if item.island_span_start is None else f"0x{item.island_span_start:08X}",
                "island_span_end": None if item.island_span_end is None else f"0x{item.island_span_end:08X}",
                "prev_corridor_paths": list(item.prev_corridor_paths),
                "next_corridor_paths": list(item.next_corridor_paths),
                "debug_prev_paths": list(item.debug_prev_paths),
                "debug_next_paths": list(item.debug_next_paths),
                "score": item.score,
            }
        )
    return json.dumps(rows, indent=2) + "\n"


def functions_in_span(
    current_functions: list[FunctionSymbol],
    start: int | None,
    end: int | None,
) -> tuple[FunctionSymbol, ...]:
    if start is None or end is None:
        return ()
    return tuple(
        function
        for function in current_functions
        if start <= function.address and function.address < end
    )


def next_steps_for_action(item: WorkItem) -> tuple[str, ...]:
    if item.action == "split-now":
        return (
            "Claim the suggested EN window as a first-pass split candidate and verify the function count against nearby rodata/data ownership.",
            "Use the corridor neighbors only as edge guards; the retail evidence is already strong enough to start a real source file.",
        )
    if item.action == "expand-window":
        return (
            "Inspect the suggested window as one candidate file before naming the final boundary.",
            "Verify that the retail xref function lands inside the expanded range and that adjacent functions do not obviously belong to the corridor neighbors.",
        )
    if item.action == "shrink-window":
        return (
            "Trim the current seed around the retail-xref functions before materializing a file boundary.",
            "Prefer the compact suggested window as the first hypothesis, then validate surrounding rodata and call patterns.",
        )
    if item.action == "shared-island":
        return (
            "Treat the shared island as one small packet first, then separate the leaf files once constructor or registration boundaries are clearer.",
            "Open every tiny function in the island together; splitting them independently is likely to overfit weak evidence.",
        )
    if item.action == "corridor-packet":
        return (
            "Work the whole corridor packet instead of asserting a narrow final boundary immediately.",
            "Use the listed gap neighbors to decide whether this source should become one file or part of a larger missing cluster.",
        )
    if item.action == "seed-only":
        return (
            "Keep this as a naming seed only until more size or corridor context appears.",
        )
    return (
        "Keep this as supporting naming evidence and revisit after more EN xrefs or adjacent file structure has been recovered.",
    )


def packet_markdown(item: WorkItem, current_functions: list[FunctionSymbol]) -> str:
    inspect_start = item.suggested_start if item.suggested_start is not None else item.current_seed_start
    inspect_end = item.suggested_end if item.suggested_end is not None else item.current_seed_end
    inspect_functions = functions_in_span(current_functions, inspect_start, inspect_end)
    seed_functions = functions_in_span(current_functions, item.current_seed_start, item.current_seed_end)

    lines: list[str] = []
    lines.append(f"# Retail Source Boundary Packet: `{item.retail_source_name}`")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- action: `{item.action}`")
    lines.append(f"- confidence: `{item.confidence}`")
    lines.append(f"- suggested path: `{item.suggested_path}`")
    lines.append(f"- split status: `{item.split_status}`")
    lines.append(f"- retail bundles: `{item.bundle_count}`")
    lines.append(f"- current seed: {span_text(item.current_seed_start, item.current_seed_end, item.current_seed_size)}")
    if item.debug_target_size is not None:
        lines.append(f"- debug target size: `0x{item.debug_target_size:X}`")
    if item.fit_status:
        lines.append(f"- fit status: `{item.fit_status}`")
    if item.suggested_start is not None:
        lines.append(
            "- suggested window: "
            + span_text(item.suggested_start, item.suggested_end, item.suggested_size)
            + f" delta=`{item.window_delta:+#x}` xref_coverage=`{item.window_coverage}`"
        )
    if item.retail_labels:
        lines.append("- retail labels: " + ", ".join(f"`{label}`" for label in item.retail_labels))
    lines.append(f"- xref count: `{item.xref_count}`")
    lines.append("")
    lines.append("## Why")
    lines.append(f"- {item.reason}")
    lines.append("")
    lines.append("## EN Xref Functions")
    if item.xref_functions:
        for value in item.xref_functions:
            lines.append(f"- `{value}`")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Current Seed Functions")
    if seed_functions:
        for function in seed_functions:
            lines.append(f"- `{format_symbol_span(function)}` size=`0x{function.size:X}`")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Suggested Inspection Window")
    if inspect_functions:
        for function in inspect_functions[:40]:
            lines.append(f"- `{format_symbol_span(function)}` size=`0x{function.size:X}`")
        if len(inspect_functions) > 40:
            lines.append(f"- ... (+{len(inspect_functions) - 40} more functions)")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Corridor Context")
    lines.append("- previous corridor: " + preview_paths(item.prev_corridor_paths))
    lines.append("- next corridor: " + preview_paths(item.next_corridor_paths))
    if item.debug_prev_paths or item.debug_next_paths:
        if item.debug_prev_paths:
            lines.append("- debug neighbors before: " + preview_paths(item.debug_prev_paths))
        if item.debug_next_paths:
            lines.append("- debug neighbors after: " + preview_paths(item.debug_next_paths))
    if len(item.island_sources) > 1:
        lines.append("- shared island sources: " + ", ".join(f"`{name}`" for name in item.island_sources))
        if item.island_span_start is not None and item.island_span_end is not None:
            lines.append(
                "- shared island span: "
                + span_text(
                    item.island_span_start,
                    item.island_span_end,
                    item.island_span_end - item.island_span_start,
                )
            )
    lines.append("")
    lines.append("## Recommended Next Steps")
    for step in next_steps_for_action(item):
        lines.append(f"- {step}")
    return "\n".join(lines) + "\n"


def packet_filename(index: int, width: int, item: WorkItem) -> str:
    stem = Path(item.retail_source_name).stem
    return f"{index:0{width}d}-{item.action}-{sanitize_filename_component(stem)}.md"


def packet_index_markdown(items: list[WorkItem], output_root: Path) -> str:
    width = max(2, len(str(len(items))))
    lines = ["# Retail Source Boundary Packets", ""]
    lines.append("Generated by `python tools/orig/source_worklist.py --materialize-all`.")
    lines.append("")
    for index, item in enumerate(items, start=1):
        filename = packet_filename(index, width, item)
        lines.append(
            f"- [{filename}]({filename}) action=`{item.action}` confidence=`{item.confidence}` target=`{item.suggested_path}`"
        )
    lines.append("")
    lines.append(f"- Packet root: `{output_root.as_posix()}`")
    return "\n".join(lines) + "\n"


def materialize_packets(
    items: list[WorkItem],
    current_functions: list[FunctionSymbol],
    output_root: Path,
) -> tuple[int, int]:
    written = 0
    unchanged = 0
    width = max(2, len(str(len(items))))
    for index, item in enumerate(items, start=1):
        text = packet_markdown(item, current_functions)
        path = output_root / packet_filename(index, width, item)
        if write_text_if_changed(path, text):
            written += 1
        else:
            unchanged += 1
    index_path = output_root / "README.md"
    if write_text_if_changed(index_path, packet_index_markdown(items, output_root)):
        written += 1
    else:
        unchanged += 1
    return written, unchanged


def rows_to_csv(items: list[WorkItem]) -> str:
    fieldnames = [
        "retail_source_name",
        "suggested_path",
        "action",
        "confidence",
        "reason",
        "xref_count",
        "retail_labels",
        "current_seed_start",
        "current_seed_end",
        "current_seed_size",
        "current_seed_functions",
        "suggested_start",
        "suggested_end",
        "suggested_size",
        "debug_target_size",
        "window_delta",
        "window_coverage",
        "split_status",
        "fit_status",
        "bundle_count",
        "xref_functions",
        "island_sources",
        "island_span_start",
        "island_span_end",
        "prev_corridor_paths",
        "next_corridor_paths",
        "debug_prev_paths",
        "debug_next_paths",
        "score",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for item in items:
        writer.writerow(
            {
                "retail_source_name": item.retail_source_name,
                "suggested_path": item.suggested_path,
                "action": item.action,
                "confidence": item.confidence,
                "reason": item.reason,
                "xref_count": item.xref_count,
                "retail_labels": ",".join(item.retail_labels),
                "current_seed_start": "" if item.current_seed_start is None else f"0x{item.current_seed_start:08X}",
                "current_seed_end": "" if item.current_seed_end is None else f"0x{item.current_seed_end:08X}",
                "current_seed_size": "" if item.current_seed_size is None else f"0x{item.current_seed_size:X}",
                "current_seed_functions": item.current_seed_functions,
                "suggested_start": "" if item.suggested_start is None else f"0x{item.suggested_start:08X}",
                "suggested_end": "" if item.suggested_end is None else f"0x{item.suggested_end:08X}",
                "suggested_size": "" if item.suggested_size is None else f"0x{item.suggested_size:X}",
                "debug_target_size": "" if item.debug_target_size is None else f"0x{item.debug_target_size:X}",
                "window_delta": "" if item.window_delta is None else f"{item.window_delta}",
                "window_coverage": item.window_coverage or "",
                "split_status": item.split_status,
                "fit_status": item.fit_status or "",
                "bundle_count": item.bundle_count,
                "xref_functions": ",".join(item.xref_functions),
                "island_sources": ",".join(item.island_sources),
                "island_span_start": "" if item.island_span_start is None else f"0x{item.island_span_start:08X}",
                "island_span_end": "" if item.island_span_end is None else f"0x{item.island_span_end:08X}",
                "prev_corridor_paths": ",".join(item.prev_corridor_paths),
                "next_corridor_paths": ",".join(item.next_corridor_paths),
                "debug_prev_paths": ",".join(item.debug_prev_paths),
                "debug_next_paths": ",".join(item.debug_next_paths),
                "score": item.score,
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge retail EN source tags, split-fit context, and source-order corridors into one recovery worklist."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for the retail source crosswalk.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for file-order and size context.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for approximate source order.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference inventory mined only for side-path hints.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side-path hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for side-path hints.")
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across file names, actions, and corridor context.")
    parser.add_argument("--limit", type=int, default=6, help="Maximum entries per summary section.")
    parser.add_argument("--materialize-top", type=int, default=0, help="Write the top N visible worklist packets under --output-root.")
    parser.add_argument("--materialize-all", action="store_true", help="Write every visible worklist packet under --output-root.")
    parser.add_argument("--output-root", type=Path, default=Path("docs/orig/source_worklist_packets"), help="Destination directory for generated worklist packets.")
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
    hints = build_boundary_hints(
        groups,
        reference_hints,
        current_functions,
        build_split_ranges(args.splits),
        args.dol,
    )
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
        split_ranges=build_split_ranges(args.splits),
        max_gap_bytes=0x3000,
        max_gap_functions=8,
    )
    items = build_work_items(anchors, hints, corridors, islands, current_functions)
    visible_items = filter_items(items, args.search)

    if args.materialize_all:
        materialized_items = visible_items
    elif args.materialize_top > 0:
        materialized_items = visible_items[: args.materialize_top]
    else:
        materialized_items = []

    if materialized_items:
        written, unchanged = materialize_packets(materialized_items, current_functions, args.output_root)
        print(
            f"materialized={len(materialized_items)} written={written} unchanged={unchanged} root={args.output_root.as_posix()}",
            file=sys.stderr,
        )

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible_items))
        elif args.format == "json":
            sys.stdout.write(rows_to_json(visible_items))
        elif args.search:
            sys.stdout.write(search_markdown(visible_items))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(items, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
