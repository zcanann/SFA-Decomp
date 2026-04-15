from __future__ import annotations

import argparse
import bisect
import csv
import io
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import FunctionSymbol, load_function_symbols
from tools.orig.source_boundaries import build_split_ranges
from tools.orig.source_corridors import build_anchors, build_corridors, format_symbol_span
from tools.orig.source_gap_packets import SourceGapPacket, build_gap_packets
from tools.orig.source_reference_hints import build_groups, collect_reference_hints, parse_source_inventory
from tools.orig.source_recovery import parse_debug_split_text_ranges


BROAD_EXACT_INTERVAL_LIMIT = 128


@dataclass(frozen=True)
class DebugSplitInfo:
    path: str
    start: int
    end: int
    function_count: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class GapWindowEstimate:
    ordinal: int
    path: str
    basename: str
    source_mode: str
    debug_start: int
    debug_end: int
    debug_size: int
    debug_function_count: int
    current_start: int
    current_end: int
    current_size: int
    current_function_count: int
    scaled_target_size: int
    scaled_delta: int
    start_function_index: int
    end_function_index: int
    functions: tuple[FunctionSymbol, ...]


@dataclass(frozen=True)
class GapWindowPlan:
    packet: SourceGapPacket
    candidate_paths: tuple[str, ...]
    window_estimates: tuple[GapWindowEstimate, ...]
    layout_mode: str
    confidence: str
    confidence_reason: str
    debug_total_size: int
    scale_ratio: float
    omitted_exact_interval_count: int
    unresolved_gap_names: tuple[str, ...]
    ambiguous_gap_names: tuple[str, ...]

    @property
    def packet_name(self) -> str:
        return f"{self.packet.left.retail_source_name} -> {self.packet.right.retail_source_name}"

    @property
    def estimated_count(self) -> int:
        return len(self.window_estimates)


def write_text_if_changed(path: Path, text: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def sanitize_filename_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "packet"


def debug_split_info_map(
    debug_split_ranges: dict[str, tuple[int, int]],
    debug_functions: list[FunctionSymbol],
) -> dict[str, DebugSplitInfo]:
    addresses = [function.address for function in debug_functions]
    result: dict[str, DebugSplitInfo] = {}
    for path, (start, end) in debug_split_ranges.items():
        function_count = bisect.bisect_left(addresses, end) - bisect.bisect_left(addresses, start)
        normalized = path.replace("\\", "/")
        result[normalized] = DebugSplitInfo(
            path=normalized,
            start=start,
            end=end,
            function_count=function_count,
        )
    return result


def unique_ordered_paths(paths: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for path in paths:
        normalized = path.replace("\\", "/")
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def exact_interval_candidate_paths(
    packet: SourceGapPacket,
    debug_info: dict[str, DebugSplitInfo],
    max_paths: int,
    function_count: int,
) -> tuple[str, ...]:
    paths = [
        path.replace("\\", "/")
        for path in packet.exact_debug_interval_paths
        if path.replace("\\", "/") in debug_info
    ]
    if not paths:
        return ()
    if len(paths) > max_paths or len(paths) > function_count:
        return ()
    return unique_ordered_paths(paths)


def hinted_candidate_paths(
    packet: SourceGapPacket,
    debug_info: dict[str, DebugSplitInfo],
    max_paths: int,
) -> tuple[str, ...]:
    chosen: list[str] = []
    for hint in packet.gap_path_hints:
        if hint.resolution_status not in {"exact-interval", "global-unique"}:
            continue
        if len(hint.resolved_paths) != 1:
            continue
        path = hint.resolved_paths[0].replace("\\", "/")
        if path not in debug_info:
            continue
        chosen.append(path)
    unique = unique_ordered_paths(chosen)
    if len(unique) > max_paths:
        return ()
    return unique


def choose_candidate_paths(
    packet: SourceGapPacket,
    debug_info: dict[str, DebugSplitInfo],
    exact_interval_limit: int,
    hinted_path_limit: int,
) -> tuple[tuple[str, ...], str, int]:
    function_count = len(packet.gap_functions)
    exact_paths = exact_interval_candidate_paths(packet, debug_info, exact_interval_limit, function_count)
    if exact_paths:
        omitted = max(0, len(packet.exact_debug_interval_paths) - len(exact_paths))
        return exact_paths, "exact-debug-interval", omitted

    hinted_paths = hinted_candidate_paths(packet, debug_info, max_paths=hinted_path_limit)
    if hinted_paths:
        omitted = max(0, len(packet.exact_debug_interval_paths) - len(exact_paths))
        return hinted_paths, "resolved-gap-hints", omitted

    return (), "none", max(0, len(packet.exact_debug_interval_paths))


def boundary_cost(current_cumulative: list[int], index: int, target: float) -> int:
    return abs(current_cumulative[index] - int(round(target)))


def choose_segment_boundaries(current_cumulative: list[int], target_cumulative: list[float]) -> list[int] | None:
    file_count = len(target_cumulative)
    function_count = len(current_cumulative)
    if file_count == 0 or function_count == 0 or file_count > function_count:
        return None
    if file_count == 1:
        return [function_count - 1]

    dp: list[list[float]] = [[math.inf] * function_count for _ in range(file_count)]
    prev_choice: list[list[int | None]] = [[None] * function_count for _ in range(file_count)]

    for end_index in range(0, function_count - (file_count - 1)):
        dp[0][end_index] = boundary_cost(current_cumulative, end_index, target_cumulative[0])

    for file_index in range(1, file_count):
        min_end_index = file_index
        max_end_index = function_count - (file_count - file_index)
        for end_index in range(min_end_index, max_end_index + 1):
            best_cost = math.inf
            best_prev: int | None = None
            for prev_end in range(file_index - 1, end_index):
                previous = dp[file_index - 1][prev_end]
                if math.isinf(previous):
                    continue
                cost = previous + boundary_cost(current_cumulative, end_index, target_cumulative[file_index])
                if cost < best_cost:
                    best_cost = cost
                    best_prev = prev_end
            dp[file_index][end_index] = best_cost
            prev_choice[file_index][end_index] = best_prev

    last_index = function_count - 1
    if math.isinf(dp[file_count - 1][last_index]):
        return None

    boundaries = [last_index] * file_count
    cursor = last_index
    for file_index in range(file_count - 1, 0, -1):
        boundaries[file_index] = cursor
        previous = prev_choice[file_index][cursor]
        if previous is None:
            return None
        cursor = previous
    boundaries[0] = cursor
    return boundaries


def scale_reason(
    packet: SourceGapPacket,
    candidate_paths: tuple[str, ...],
    scale_ratio: float,
) -> tuple[str, str]:
    unresolved = tuple(hint.basename for hint in packet.gap_path_hints if hint.resolution_status == "unresolved")
    ambiguous = tuple(hint.basename for hint in packet.gap_path_hints if hint.resolution_status.startswith("ambiguous"))
    fully_resolved = len(candidate_paths) == packet.gap_path_count and not unresolved and not ambiguous
    exact_mode = bool(packet.exact_debug_interval_paths) and len(candidate_paths) == len(packet.exact_debug_interval_paths)

    if fully_resolved and 0.75 <= scale_ratio <= 1.35:
        return "high", "Resolved debug sizes cover the current EN gap closely."
    if exact_mode and 0.55 <= scale_ratio <= 1.8:
        return "high", "Exact debug interval paths give a complete local ordering and the EN/debug size ratio is reasonable."
    if fully_resolved and 0.45 <= scale_ratio <= 2.4:
        return "medium", "All named gap files resolved cleanly, but the EN/debug size ratio still needs local verification."
    if candidate_paths and not unresolved and not ambiguous:
        return "medium", "Resolved gap names give a usable local skeleton, but the interval is only partially constrained."
    return "low", "Only a partial set of gap files could be sized or ordered; treat these as exploratory windows."


def build_window_plan(
    packet: SourceGapPacket,
    debug_info: dict[str, DebugSplitInfo],
    exact_interval_limit: int,
    hinted_path_limit: int,
) -> GapWindowPlan | None:
    if not packet.gap_functions:
        return None

    candidate_paths, layout_mode, omitted_exact_count = choose_candidate_paths(
        packet,
        debug_info,
        exact_interval_limit=exact_interval_limit,
        hinted_path_limit=hinted_path_limit,
    )
    if not candidate_paths:
        return None

    debug_sizes = [debug_info[path].size for path in candidate_paths]
    debug_total_size = sum(debug_sizes)
    if debug_total_size <= 0 or packet.en_gap_size is None:
        return None

    current_cumulative: list[int] = []
    running_current = 0
    for function in packet.gap_functions:
        running_current += function.size
        current_cumulative.append(running_current)

    scale_ratio = packet.en_gap_size / debug_total_size
    target_cumulative: list[float] = []
    running_debug = 0.0
    for size in debug_sizes:
        running_debug += size
        target_cumulative.append(running_debug * scale_ratio)

    boundaries = choose_segment_boundaries(current_cumulative, target_cumulative)
    if boundaries is None:
        return None

    estimates: list[GapWindowEstimate] = []
    start_index = 0
    for ordinal, (path, end_index) in enumerate(zip(candidate_paths, boundaries), start=1):
        info = debug_info[path]
        scaled_target = int(round(info.size * scale_ratio))
        segment_functions = tuple(packet.gap_functions[start_index : end_index + 1])
        current_start = segment_functions[0].address
        current_end = segment_functions[-1].address + segment_functions[-1].size
        current_size = current_end - current_start
        estimates.append(
            GapWindowEstimate(
                ordinal=ordinal,
                path=path,
                basename=Path(path).name,
                source_mode=layout_mode,
                debug_start=info.start,
                debug_end=info.end,
                debug_size=info.size,
                debug_function_count=info.function_count,
                current_start=current_start,
                current_end=current_end,
                current_size=current_size,
                current_function_count=len(segment_functions),
                scaled_target_size=scaled_target,
                scaled_delta=current_size - scaled_target,
                start_function_index=start_index,
                end_function_index=end_index,
                functions=segment_functions,
            )
        )
        start_index = end_index + 1

    confidence, confidence_reason = scale_reason(packet, candidate_paths, scale_ratio)
    unresolved_names = tuple(
        hint.basename
        for hint in packet.gap_path_hints
        if hint.resolution_status == "unresolved"
    )
    ambiguous_names = tuple(
        hint.basename
        for hint in packet.gap_path_hints
        if hint.resolution_status.startswith("ambiguous")
    )
    return GapWindowPlan(
        packet=packet,
        candidate_paths=candidate_paths,
        window_estimates=tuple(estimates),
        layout_mode=layout_mode,
        confidence=confidence,
        confidence_reason=confidence_reason,
        debug_total_size=debug_total_size,
        scale_ratio=scale_ratio,
        omitted_exact_interval_count=omitted_exact_count,
        unresolved_gap_names=unresolved_names,
        ambiguous_gap_names=ambiguous_names,
    )


def build_window_plans(
    packets: list[SourceGapPacket],
    debug_info: dict[str, DebugSplitInfo],
    exact_interval_limit: int,
    hinted_path_limit: int,
) -> list[GapWindowPlan]:
    plans: list[GapWindowPlan] = []
    for packet in packets:
        plan = build_window_plan(
            packet,
            debug_info=debug_info,
            exact_interval_limit=exact_interval_limit,
            hinted_path_limit=hinted_path_limit,
        )
        if plan is not None:
            plans.append(plan)
    plans.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[item.confidence],
            -item.estimated_count,
            0xFFFFFFFF if item.packet.en_gap_start is None else item.packet.en_gap_start,
            item.packet.left.retail_source_name.lower(),
        )
    )
    return plans


def plan_search_fields(plan: GapWindowPlan) -> list[str]:
    fields = [
        plan.packet.left.retail_source_name.lower(),
        plan.packet.right.retail_source_name.lower(),
        plan.packet.left.suggested_path.lower(),
        plan.packet.right.suggested_path.lower(),
        plan.layout_mode.lower(),
        plan.confidence.lower(),
    ]
    fields.extend(path.lower() for path in plan.candidate_paths)
    fields.extend(name.lower() for name in plan.unresolved_gap_names)
    fields.extend(name.lower() for name in plan.ambiguous_gap_names)
    for estimate in plan.window_estimates:
        fields.extend(
            [
                estimate.basename.lower(),
                estimate.path.lower(),
                f"0x{estimate.current_start:08x}",
                f"0x{estimate.current_end:08x}",
            ]
        )
        fields.extend(function.name.lower() for function in estimate.functions)
    return fields


def filter_plans(plans: list[GapWindowPlan], patterns: list[str] | None) -> list[GapWindowPlan]:
    if not patterns:
        return plans
    lowered = [pattern.lower() for pattern in patterns]
    return [
        plan
        for plan in plans
        if any(any(pattern in field for field in plan_search_fields(plan)) for pattern in lowered)
    ]


def plan_filename(index: int, width: int, plan: GapWindowPlan) -> str:
    left_stem = sanitize_filename_component(Path(plan.packet.left.retail_source_name).stem)
    right_stem = sanitize_filename_component(Path(plan.packet.right.retail_source_name).stem)
    return f"{index:0{width}d}-{left_stem}-to-{right_stem}.md"


def format_ratio(value: float) -> str:
    return f"{value:.2f}x"


def estimate_summary_line(estimate: GapWindowEstimate) -> str:
    return (
        f"`{estimate.path}` "
        f"current=`0x{estimate.current_start:08X}-0x{estimate.current_end:08X}` size=`0x{estimate.current_size:X}` "
        f"debug=`0x{estimate.debug_size:X}` scaled=`0x{estimate.scaled_target_size:X}` "
        f"delta=`{estimate.scaled_delta:+#x}` functions=`{estimate.current_function_count}`"
    )


def plan_markdown(plan: GapWindowPlan) -> str:
    packet = plan.packet
    lines: list[str] = []
    lines.append(f"# `{packet.left.retail_source_name}` -> `{packet.right.retail_source_name}` gap windows")
    lines.append("")
    lines.append("Generated by `python tools/orig/source_gap_windows.py --materialize-all`.")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- left anchor: `{packet.left.suggested_path}`")
    lines.append(f"- right anchor: `{packet.right.suggested_path}`")
    if packet.en_gap_start is not None and packet.en_gap_end is not None and packet.en_gap_size is not None:
        lines.append(
            f"- current EN gap: `0x{packet.en_gap_start:08X}-0x{packet.en_gap_end:08X}` "
            f"size=`0x{packet.en_gap_size:X}` functions=`{len(packet.gap_functions)}`"
        )
    lines.append(f"- layout mode: `{plan.layout_mode}`")
    lines.append(f"- confidence: `{plan.confidence}`")
    lines.append(f"- confidence note: {plan.confidence_reason}")
    lines.append(
        f"- debug size total for estimated paths: `0x{plan.debug_total_size:X}` "
        f"EN/debug ratio=`{format_ratio(plan.scale_ratio)}`"
    )
    lines.append(f"- estimated windows: `{plan.estimated_count}`")
    if plan.omitted_exact_interval_count:
        lines.append(f"- omitted exact-interval paths: `{plan.omitted_exact_interval_count}`")
    if plan.unresolved_gap_names:
        lines.append("- unresolved gap names: " + ", ".join(f"`{name}`" for name in plan.unresolved_gap_names))
    if plan.ambiguous_gap_names:
        lines.append("- ambiguous gap names: " + ", ".join(f"`{name}`" for name in plan.ambiguous_gap_names))
    lines.append("")
    lines.append("## Estimated Windows")
    for estimate in plan.window_estimates:
        lines.append(f"### `{estimate.path}`")
        lines.append(
            f"- current EN window: `0x{estimate.current_start:08X}-0x{estimate.current_end:08X}` "
            f"size=`0x{estimate.current_size:X}` functions=`{estimate.current_function_count}`"
        )
        lines.append(
            f"- debug split: `0x{estimate.debug_start:08X}-0x{estimate.debug_end:08X}` "
            f"size=`0x{estimate.debug_size:X}` functions=`{estimate.debug_function_count}`"
        )
        lines.append(
            f"- scaled target: `0x{estimate.scaled_target_size:X}` delta=`{estimate.scaled_delta:+#x}`"
        )
        lines.append("- functions:")
        for function in estimate.functions[:16]:
            lines.append(f"  - `{format_symbol_span(function)}` size=`0x{function.size:X}`")
        if len(estimate.functions) > 16:
            lines.append(f"  - ... (+{len(estimate.functions) - 16} more functions)")
    lines.append("")
    lines.append("## Recommended Next Steps")
    lines.append("- Use these windows as first-pass split boundaries, not source-truth.")
    if plan.confidence == "high":
        lines.append("- This packet is strong enough to start sketching one file per estimated window immediately.")
    elif plan.confidence == "medium":
        lines.append("- Verify nearby rodata/data ownership before materializing stubs or final split paths.")
    else:
        lines.append("- Treat these as exploratory sub-windows and confirm the missing neighbors before locking boundaries.")
    return "\n".join(lines) + "\n"


def plan_index_markdown(plans: list[GapWindowPlan], output_root: Path) -> str:
    width = max(2, len(str(len(plans))))
    lines = ["# Retail Source Gap Window Briefs", ""]
    lines.append("Generated by `python tools/orig/source_gap_windows.py --materialize-all`.")
    lines.append("")
    for index, plan in enumerate(plans, start=1):
        filename = plan_filename(index, width, plan)
        lines.append(
            f"- [{filename}]({filename}) confidence=`{plan.confidence}` "
            f"windows=`{plan.estimated_count}` mode=`{plan.layout_mode}` "
            f"packet=`{plan.packet.left.suggested_path}` -> `{plan.packet.right.suggested_path}`"
        )
    lines.append("")
    lines.append(f"- Packet root: `{output_root.as_posix()}`")
    return "\n".join(lines) + "\n"


def materialize_plans(plans: list[GapWindowPlan], output_root: Path) -> tuple[int, int]:
    written = 0
    unchanged = 0
    width = max(2, len(str(len(plans))))
    for index, plan in enumerate(plans, start=1):
        path = output_root / plan_filename(index, width, plan)
        if write_text_if_changed(path, plan_markdown(plan)):
            written += 1
        else:
            unchanged += 1
    index_path = output_root / "README.md"
    if write_text_if_changed(index_path, plan_index_markdown(plans, output_root)):
        written += 1
    else:
        unchanged += 1
    return written, unchanged


def summary_markdown(plans: list[GapWindowPlan], limit: int) -> str:
    high = [plan for plan in plans if plan.confidence == "high"]
    medium = [plan for plan in plans if plan.confidence == "medium"]
    exact = [plan for plan in plans if plan.layout_mode == "exact-debug-interval"]
    partial = [
        plan
        for plan in plans
        if plan.unresolved_gap_names or plan.ambiguous_gap_names or plan.layout_mode != "exact-debug-interval"
    ]

    lines: list[str] = []
    lines.append("# Retail source gap windows")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Gap packets with per-file EN estimates: `{len(plans)}`")
    lines.append(f"- High-confidence plans: `{len(high)}`")
    lines.append(f"- Medium-confidence plans: `{len(medium)}`")
    lines.append(f"- Exact-debug-interval plans: `{len(exact)}`")
    lines.append(f"- Partial or seed-only plans: `{len(partial)}`")
    lines.append("")
    lines.append("## Highest-value plans")
    for plan in plans[:limit]:
        packet = plan.packet
        gap_text = "unknown"
        if packet.en_gap_start is not None and packet.en_gap_end is not None and packet.en_gap_size is not None:
            gap_text = f"`0x{packet.en_gap_start:08X}-0x{packet.en_gap_end:08X}` size=`0x{packet.en_gap_size:X}`"
        lines.append(
            f"- `{plan.packet_name}` confidence=`{plan.confidence}` mode=`{plan.layout_mode}` "
            f"windows=`{plan.estimated_count}` gap={gap_text} EN/debug=`{format_ratio(plan.scale_ratio)}`"
        )
        for estimate in plan.window_estimates[: min(4, len(plan.window_estimates))]:
            lines.append("  " + estimate_summary_line(estimate))
        if len(plan.window_estimates) > 4:
            lines.append(f"  ... (+{len(plan.window_estimates) - 4} more windows)")
    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_gap_windows.py`")
    lines.append("- Inspect one gap or file: `python tools/orig/source_gap_windows.py --search objanim objhits`")
    lines.append(
        f"- Broad exact-interval corridors: `python tools/orig/source_gap_windows.py --broad-exact-intervals`"
    )
    lines.append("- CSV dump: `python tools/orig/source_gap_windows.py --format csv`")
    lines.append("- JSON dump: `python tools/orig/source_gap_windows.py --format json`")
    lines.append("- Write window briefs: `python tools/orig/source_gap_windows.py --materialize-all`")
    return "\n".join(lines)


def search_markdown(plans: list[GapWindowPlan]) -> str:
    lines = ["# Retail source gap window search", ""]
    if not plans:
        lines.append("- No matching gap-window plans.")
        return "\n".join(lines)

    for plan in plans:
        packet = plan.packet
        lines.append(f"## `{plan.packet_name}`")
        if packet.en_gap_start is not None and packet.en_gap_end is not None and packet.en_gap_size is not None:
            lines.append(
                f"- gap: `0x{packet.en_gap_start:08X}-0x{packet.en_gap_end:08X}` "
                f"size=`0x{packet.en_gap_size:X}` functions=`{len(packet.gap_functions)}`"
            )
        else:
            lines.append("- gap: none")
        lines.append(f"- confidence: `{plan.confidence}`")
        lines.append(f"- layout mode: `{plan.layout_mode}`")
        lines.append(f"- confidence note: {plan.confidence_reason}")
        for estimate in plan.window_estimates:
            lines.append("- " + estimate_summary_line(estimate))
        lines.append("")
    return "\n".join(lines).rstrip()


def rows_to_csv(plans: list[GapWindowPlan]) -> str:
    fieldnames = [
        "left_source",
        "right_source",
        "confidence",
        "layout_mode",
        "packet_gap_start",
        "packet_gap_end",
        "packet_gap_size",
        "scale_ratio",
        "path",
        "basename",
        "debug_start",
        "debug_end",
        "debug_size",
        "debug_function_count",
        "current_start",
        "current_end",
        "current_size",
        "current_function_count",
        "scaled_target_size",
        "scaled_delta",
        "function_spans",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for plan in plans:
        for estimate in plan.window_estimates:
            writer.writerow(
                {
                    "left_source": plan.packet.left.retail_source_name,
                    "right_source": plan.packet.right.retail_source_name,
                    "confidence": plan.confidence,
                    "layout_mode": plan.layout_mode,
                    "packet_gap_start": "" if plan.packet.en_gap_start is None else f"0x{plan.packet.en_gap_start:08X}",
                    "packet_gap_end": "" if plan.packet.en_gap_end is None else f"0x{plan.packet.en_gap_end:08X}",
                    "packet_gap_size": "" if plan.packet.en_gap_size is None else f"0x{plan.packet.en_gap_size:X}",
                    "scale_ratio": f"{plan.scale_ratio:.6f}",
                    "path": estimate.path,
                    "basename": estimate.basename,
                    "debug_start": f"0x{estimate.debug_start:08X}",
                    "debug_end": f"0x{estimate.debug_end:08X}",
                    "debug_size": f"0x{estimate.debug_size:X}",
                    "debug_function_count": estimate.debug_function_count,
                    "current_start": f"0x{estimate.current_start:08X}",
                    "current_end": f"0x{estimate.current_end:08X}",
                    "current_size": f"0x{estimate.current_size:X}",
                    "current_function_count": estimate.current_function_count,
                    "scaled_target_size": f"0x{estimate.scaled_target_size:X}",
                    "scaled_delta": f"{estimate.scaled_delta:+#x}",
                    "function_spans": ",".join(format_symbol_span(function) for function in estimate.functions),
                }
            )
    return buffer.getvalue()


def rows_to_json(plans: list[GapWindowPlan]) -> str:
    rows: list[dict[str, object]] = []
    for plan in plans:
        rows.append(
            {
                "left_source": plan.packet.left.retail_source_name,
                "right_source": plan.packet.right.retail_source_name,
                "confidence": plan.confidence,
                "confidence_reason": plan.confidence_reason,
                "layout_mode": plan.layout_mode,
                "packet_gap_start": None if plan.packet.en_gap_start is None else f"0x{plan.packet.en_gap_start:08X}",
                "packet_gap_end": None if plan.packet.en_gap_end is None else f"0x{plan.packet.en_gap_end:08X}",
                "packet_gap_size": None if plan.packet.en_gap_size is None else f"0x{plan.packet.en_gap_size:X}",
                "debug_total_size": f"0x{plan.debug_total_size:X}",
                "scale_ratio": plan.scale_ratio,
                "candidate_paths": list(plan.candidate_paths),
                "unresolved_gap_names": list(plan.unresolved_gap_names),
                "ambiguous_gap_names": list(plan.ambiguous_gap_names),
                "window_estimates": [
                    {
                        "path": estimate.path,
                        "basename": estimate.basename,
                        "debug_start": f"0x{estimate.debug_start:08X}",
                        "debug_end": f"0x{estimate.debug_end:08X}",
                        "debug_size": f"0x{estimate.debug_size:X}",
                        "debug_function_count": estimate.debug_function_count,
                        "current_start": f"0x{estimate.current_start:08X}",
                        "current_end": f"0x{estimate.current_end:08X}",
                        "current_size": f"0x{estimate.current_size:X}",
                        "current_function_count": estimate.current_function_count,
                        "scaled_target_size": f"0x{estimate.scaled_target_size:X}",
                        "scaled_delta": estimate.scaled_delta,
                        "functions": [format_symbol_span(function) for function in estimate.functions],
                    }
                    for estimate in plan.window_estimates
                ],
            }
        )
    return json.dumps(rows, indent=2) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Estimate per-file EN source windows inside retail-backed gap packets."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the retail EN main.dol.")
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"), help="Current EN symbols.txt.")
    parser.add_argument("--splits", type=Path, default=Path("config/GSAE01/splits.txt"), help="Current EN splits.txt.")
    parser.add_argument("--debug-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Debug-side symbols used for debug split sizes and function counts.")
    parser.add_argument("--debug-splits", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"), help="Debug-side splits used for gap file sizes and ordering.")
    parser.add_argument("--debug-srcfiles", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Debug-side source inventory used for approximate source order.")
    parser.add_argument("--reference-configure", type=Path, default=Path("reference_projects/rena-tools/sfadebug/configure.py"), help="Reference configure.py mined only for side-path hints.")
    parser.add_argument("--reference-symbols", type=Path, default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"), help="Reference symbols mined only for side-function hints.")
    parser.add_argument("--reference-inventory", type=Path, default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"), help="Reference inventory mined only for side-path hints.")
    parser.add_argument("--reference-dll-registry", type=Path, default=Path("reference_projects/rena-tools/StarFoxAdventures/data/KD/dlls.xml"), help="Reference DLL registry mined only for side-path hints.")
    parser.add_argument("--reference-object-xml", type=Path, nargs="*", default=(Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects.xml"), Path("reference_projects/rena-tools/StarFoxAdventures/data/U0/objects2.xml")), help="Reference object XML files mined only for side-path hints.")
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive substring search across packet names, estimated paths, and EN function ranges.")
    parser.add_argument("--limit", type=int, default=6, help="Maximum rows to show in summary sections.")
    parser.add_argument("--exact-interval-limit", type=int, default=16, help="Use the full exact debug interval only when it has at most this many paths.")
    parser.add_argument("--hinted-path-limit", type=int, default=8, help="Skip broad hint-only packets with more than this many uniquely resolved paths.")
    parser.add_argument(
        "--broad-exact-intervals",
        action="store_true",
        help=(
            "Raise --exact-interval-limit to a broader exploratory preset so full exact-debug intervals "
            "like DIMBoss -> SHthorntail can be projected without spelling out a custom limit."
        ),
    )
    parser.add_argument("--materialize-top", type=int, default=0, help="Write the top N visible window briefs under --output-root.")
    parser.add_argument("--materialize-all", action="store_true", help="Write every visible window brief under --output-root.")
    parser.add_argument("--output-root", type=Path, default=Path("docs/orig/source_gap_window_briefs"), help="Destination directory for generated gap-window briefs.")
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.broad_exact_intervals:
        args.exact_interval_limit = max(args.exact_interval_limit, BROAD_EXACT_INTERVAL_LIMIT)

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
    debug_split_ranges = parse_debug_split_text_ranges(args.debug_splits)
    debug_split_paths = list(debug_split_ranges)
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
    debug_info = debug_split_info_map(debug_split_ranges, debug_functions)
    plans = build_window_plans(
        packets,
        debug_info=debug_info,
        exact_interval_limit=args.exact_interval_limit,
        hinted_path_limit=args.hinted_path_limit,
    )
    visible_plans = filter_plans(plans, args.search)

    if args.materialize_all:
        materialized_plans = visible_plans
    elif args.materialize_top > 0:
        materialized_plans = visible_plans[: args.materialize_top]
    else:
        materialized_plans = []

    if materialized_plans:
        written, unchanged = materialize_plans(materialized_plans, args.output_root)
        print(
            f"materialized={len(materialized_plans)} written={written} unchanged={unchanged} root={args.output_root.as_posix()}",
            file=sys.stderr,
        )

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible_plans))
        elif args.format == "json":
            sys.stdout.write(rows_to_json(visible_plans))
        elif args.search:
            sys.stdout.write(search_markdown(visible_plans))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(plans, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
