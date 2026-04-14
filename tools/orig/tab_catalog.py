from __future__ import annotations

import argparse
import csv
import io
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


SPECIAL_FAMILIES = {"MAPS.TAB", "OBJECTS.TAB"}
SPECIAL_PATTERN = re.compile(r"^MOD\d+\.TAB$", re.IGNORECASE)


@dataclass(frozen=True)
class ModeAnalysis:
    mode: str
    prefix_ratio: float
    leading_zero: bool
    zero_entries: int
    positive_entries: int
    consumed_positive_entries: int
    outlier_entries: int
    unique_offsets: tuple[int, ...]
    chunk_count: int | None
    tail_gap: int | None
    min_chunk_size: int | None
    max_chunk_size: int | None


@dataclass(frozen=True)
class TabAnalysis:
    family: str
    relative_path: str
    payload_path: str | None
    payload_size: int | None
    status: str
    mode: str | None
    word_count: int
    flag_counts: tuple[tuple[int, int], ...]
    prefix_ratio: float
    zero_entries: int
    positive_entries: int
    unique_offsets: int
    chunk_count: int | None
    tail_gap: int | None
    min_chunk_size: int | None
    max_chunk_size: int | None
    outlier_entries: int


def iter_tab_files(files_root: Path, include_special: bool) -> list[Path]:
    tabs = [
        path
        for path in files_root.rglob("*")
        if path.is_file() and path.suffix.lower() == ".tab"
    ]
    if include_special:
        return sorted(tabs)
    return sorted(
        path
        for path in tabs
        if path.name.upper() not in SPECIAL_FAMILIES and SPECIAL_PATTERN.fullmatch(path.name) is None
    )


def read_words(path: Path) -> list[int]:
    data = path.read_bytes()
    if len(data) % 4 != 0:
        raise ValueError(f"Tab size is not word-aligned: {path}")
    return [struct.unpack_from(">I", data, offset)[0] for offset in range(0, len(data), 4)]


def resolve_payload_path(tab_path: Path, files_root: Path) -> Path | None:
    stem = tab_path.stem
    candidates = [
        tab_path.with_name(f"{stem}.bin"),
        tab_path.with_name(f"{stem}.BIN"),
    ]
    if tab_path.parent != files_root:
        candidates.extend(
            [
                files_root / f"{stem}.bin",
                files_root / f"{stem}.BIN",
            ]
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def dedupe_in_order(values: list[int]) -> list[int]:
    result: list[int] = []
    for value in values:
        if result and result[-1] == value:
            continue
        result.append(value)
    return result


def analyze_mode(words: list[int], payload_size: int, *, mask: int, mode: str) -> ModeAnalysis:
    values = [word & mask for word in words]
    terminator = mask
    while values and values[-1] in {0, terminator}:
        values.pop()

    leading_zero = bool(values and values[0] == 0)
    zero_entries = values.count(0) - (1 if leading_zero else 0)
    positive_values = [value for value in values if value not in {0, terminator}]

    if payload_size == 0:
        return ModeAnalysis(
            mode=mode,
            prefix_ratio=1.0 if not positive_values else 0.0,
            leading_zero=leading_zero,
            zero_entries=max(zero_entries, 0),
            positive_entries=len(positive_values),
            consumed_positive_entries=0 if positive_values else len(positive_values),
            outlier_entries=len(positive_values),
            unique_offsets=(),
            chunk_count=0,
            tail_gap=0,
            min_chunk_size=None,
            max_chunk_size=None,
        )

    prefix: list[int] = []
    for value in positive_values:
        if value > payload_size:
            break
        if prefix and value < prefix[-1]:
            break
        prefix.append(value)

    prefix_ratio = (len(prefix) / len(positive_values)) if positive_values else 0.0
    offsets = ([0] if leading_zero else []) + prefix
    unique_offsets = tuple(dedupe_in_order(offsets))

    chunk_count: int | None = None
    tail_gap: int | None = None
    min_chunk_size: int | None = None
    max_chunk_size: int | None = None
    if unique_offsets:
        tail_gap = payload_size - unique_offsets[-1]
        if tail_gap >= 0:
            boundaries = list(unique_offsets)
            if boundaries[-1] != payload_size:
                boundaries.append(payload_size)
            chunk_sizes = [boundaries[index + 1] - boundaries[index] for index in range(len(boundaries) - 1)]
            if chunk_sizes:
                chunk_count = len(chunk_sizes)
                min_chunk_size = min(chunk_sizes)
                max_chunk_size = max(chunk_sizes)

    return ModeAnalysis(
        mode=mode,
        prefix_ratio=prefix_ratio,
        leading_zero=leading_zero,
        zero_entries=max(zero_entries, 0),
        positive_entries=len(positive_values),
        consumed_positive_entries=len(prefix),
        outlier_entries=len(positive_values) - len(prefix),
        unique_offsets=unique_offsets,
        chunk_count=chunk_count,
        tail_gap=tail_gap,
        min_chunk_size=min_chunk_size,
        max_chunk_size=max_chunk_size,
    )


def score_mode(analysis: ModeAnalysis, tail_tolerance: int) -> tuple[float, int, int, int]:
    return (
        analysis.prefix_ratio,
        1 if analysis.tail_gap is not None and 0 <= analysis.tail_gap <= tail_tolerance else 0,
        -1 if analysis.tail_gap is None else -analysis.tail_gap,
        1 if analysis.mode == "raw32" else 0,
    )


def classify_status(payload_size: int | None, analysis: ModeAnalysis | None, tail_tolerance: int) -> str:
    if payload_size is None:
        return "no-payload"
    if analysis is None:
        return "unresolved"
    if payload_size == 0:
        return "empty-payload" if analysis.positive_entries == 0 else "unresolved"
    if not analysis.unique_offsets:
        return "unresolved"
    if analysis.prefix_ratio >= 0.95 and analysis.tail_gap is not None and 0 <= analysis.tail_gap <= tail_tolerance:
        return "split-ready"
    if analysis.prefix_ratio >= 0.95:
        return "partial"
    return "unresolved"


def analyze_tab(tab_path: Path, files_root: Path, tail_tolerance: int) -> TabAnalysis:
    words = read_words(tab_path)
    payload_path = resolve_payload_path(tab_path, files_root)
    payload_size = payload_path.stat().st_size if payload_path is not None else None

    best_analysis: ModeAnalysis | None = None
    if payload_size is not None:
        candidates = [
            analyze_mode(words, payload_size, mask=0xFFFFFFFF, mode="raw32"),
            analyze_mode(words, payload_size, mask=0x00FFFFFF, mode="low24"),
        ]
        best_analysis = max(candidates, key=lambda item: score_mode(item, tail_tolerance))

    status = classify_status(payload_size, best_analysis, tail_tolerance)
    flag_counter = Counter((word >> 24) & 0xFF for word in words if word != 0xFFFFFFFF)
    relative_path = tab_path.relative_to(files_root).as_posix()
    payload_relative = None if payload_path is None else payload_path.relative_to(files_root).as_posix()

    return TabAnalysis(
        family=tab_path.name.upper(),
        relative_path=relative_path,
        payload_path=payload_relative,
        payload_size=payload_size,
        status=status,
        mode=None if best_analysis is None else best_analysis.mode,
        word_count=len(words),
        flag_counts=tuple(sorted(flag_counter.items())),
        prefix_ratio=0.0 if best_analysis is None else best_analysis.prefix_ratio,
        zero_entries=0 if best_analysis is None else best_analysis.zero_entries,
        positive_entries=0 if best_analysis is None else best_analysis.positive_entries,
        unique_offsets=0 if best_analysis is None else len(best_analysis.unique_offsets),
        chunk_count=None if best_analysis is None else best_analysis.chunk_count,
        tail_gap=None if best_analysis is None else best_analysis.tail_gap,
        min_chunk_size=None if best_analysis is None else best_analysis.min_chunk_size,
        max_chunk_size=None if best_analysis is None else best_analysis.max_chunk_size,
        outlier_entries=0 if best_analysis is None else best_analysis.outlier_entries,
    )


def format_flags(flag_counts: tuple[tuple[int, int], ...]) -> str:
    if not flag_counts:
        return "none"
    return ", ".join(f"0x{flag:02X} x{count}" for flag, count in flag_counts)


def min_max(values: list[int | None]) -> tuple[int | None, int | None]:
    concrete = [value for value in values if value is not None]
    if not concrete:
        return None, None
    return min(concrete), max(concrete)


def summarize_family(items: list[TabAnalysis]) -> dict[str, object]:
    statuses = Counter(item.status for item in items)
    modes = Counter(item.mode for item in items if item.mode is not None)
    flag_totals = Counter()
    for item in items:
        for flag, count in item.flag_counts:
            flag_totals[flag] += count
    chunk_min, chunk_max = min_max([item.chunk_count for item in items if item.status in {"split-ready", "partial"}])
    tail_min, tail_max = min_max([item.tail_gap for item in items if item.status in {"split-ready", "partial"}])
    payload_min, payload_max = min_max([item.payload_size for item in items])
    return {
        "family": items[0].family,
        "count": len(items),
        "statuses": statuses,
        "modes": modes,
        "flags": tuple(sorted(flag_totals.items())),
        "chunk_min": chunk_min,
        "chunk_max": chunk_max,
        "tail_min": tail_min,
        "tail_max": tail_max,
        "payload_min": payload_min,
        "payload_max": payload_max,
    }


def build_family_summaries(items: list[TabAnalysis]) -> list[dict[str, object]]:
    grouped: dict[str, list[TabAnalysis]] = defaultdict(list)
    for item in items:
        grouped[item.family].append(item)
    return [summarize_family(grouped[family]) for family in sorted(grouped)]


def status_label(summary: dict[str, object]) -> str:
    statuses: Counter[str] = summary["statuses"]  # type: ignore[assignment]
    count = summary["count"]  # type: ignore[assignment]
    if statuses["split-ready"] == count:
        return "split-ready"
    if statuses["split-ready"] + statuses["empty-payload"] == count and statuses["split-ready"]:
        return "split-ready-with-empty-cases"
    if statuses["split-ready"] and statuses["split-ready"] + statuses["partial"] == count and statuses["split-ready"] >= count - 1:
        return "mostly-split-ready"
    if statuses["partial"]:
        return "partial"
    if statuses["unresolved"]:
        return "unresolved"
    if statuses["no-payload"]:
        return "no-payload"
    if statuses["empty-payload"]:
        return "empty-payload"
    return "mixed"


def family_line(summary: dict[str, object]) -> str:
    statuses: Counter[str] = summary["statuses"]  # type: ignore[assignment]
    modes: Counter[str] = summary["modes"]  # type: ignore[assignment]
    mode_text = ",".join(f"{name}:{count}" for name, count in sorted(modes.items())) if modes else "none"
    chunk_range = (
        "n/a"
        if summary["chunk_min"] is None
        else f"{summary['chunk_min']}..{summary['chunk_max']}"
    )
    tail_range = (
        "n/a"
        if summary["tail_min"] is None
        else f"{summary['tail_min']}..{summary['tail_max']}"
    )
    payload_range = (
        "n/a"
        if summary["payload_min"] is None
        else f"{summary['payload_min']}..{summary['payload_max']}"
    )
    return (
        f"- `{summary['family']}`: instances={summary['count']}, status=`{status_label(summary)}`, "
        f"modes=`{mode_text}`, payload=`{payload_range}`, chunks=`{chunk_range}`, "
        f"tail_gap=`{tail_range}`, flags=`{format_flags(summary['flags'])}`, "
        f"split_ready={statuses['split-ready']}, partial={statuses['partial']}, "
        f"empty={statuses['empty-payload']}, unresolved={statuses['unresolved']}, no_payload={statuses['no-payload']}"
    )


def summary_markdown(items: list[TabAnalysis], tail_tolerance: int, include_special: bool) -> str:
    family_summaries = build_family_summaries(items)
    ready = [
        summary
        for summary in family_summaries
        if status_label(summary) in {"split-ready", "split-ready-with-empty-cases", "mostly-split-ready"}
    ]
    partial = [summary for summary in family_summaries if status_label(summary) == "partial"]
    unresolved = [
        summary
        for summary in family_summaries
        if status_label(summary) not in {"split-ready", "split-ready-with-empty-cases", "mostly-split-ready", "partial"}
    ]
    status_counts = Counter(item.status for item in items)

    lines: list[str] = []
    lines.append("# `orig/GSAE01/files/*.tab` catalog")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Tab instances audited: {len(items)}")
    lines.append(f"- Families audited: {len(family_summaries)}")
    lines.append(f"- Split-ready instances: {status_counts['split-ready']}")
    lines.append(f"- Partial instances: {status_counts['partial']}")
    lines.append(f"- Empty-payload instances: {status_counts['empty-payload']}")
    lines.append(f"- No-payload instances: {status_counts['no-payload']}")
    lines.append(f"- Unresolved instances: {status_counts['unresolved']}")
    lines.append(f"- Tail-gap tolerance for \"split-ready\": <= `{tail_tolerance}` bytes")
    lines.append(
        "- Special families "
        + ("included" if include_special else "excluded")
        + ": `MAPS.tab`, `OBJECTS.tab`, `mod*.tab`"
    )
    lines.append("")

    lines.append("## High-value findings")
    lines.append(
        "- `ANIM.TAB`, `MODELS.tab`, and `VOXMAP.tab` already behave like retail split maps across the EN map set, while `ANIMCURV.tab` is split-ready in all but one EN instance."
    )
    lines.append(
        "- Root families like `AMAP.TAB` and `PREANIM.TAB`, plus globals like `SCREENS.tab`, `SAVEGAME.tab`, `SPRITES.tab`, `MODLINES.tab`, and `HITS.tab`, already provide real split maps or compact per-entry testcase data."
    )
    lines.append(
        "- `TEX0.tab`, `TEX1.tab`, and `TEXPRE.tab` look like flagged low-24-bit tables, but the recovered prefix only covers part of each payload and ends with one footer-like outlier entry, so they are not safe split scaffolds yet."
    )
    lines.append(
        "- `GAMETEXT.tab`, `MODANIM.TAB`, `OBJSEQ.tab`, `OBJSEQ2C.tab`, `TRKBLK.tab`, and `DLLS.tab` still look structured or payload-less and need family-specific decoding instead of generic offset splitting."
    )
    lines.append("")

    lines.append("## Split-Ready Families")
    if ready:
        for summary in ready:
            lines.append(family_line(summary))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Partial Families")
    if partial:
        for summary in partial:
            lines.append(family_line(summary))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Unresolved Or No-Payload Families")
    if unresolved:
        for summary in unresolved:
            lines.append(family_line(summary))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Practical Use")
    lines.append("- Summary: `python tools/orig/tab_catalog.py`")
    lines.append("- CSV dump: `python tools/orig/tab_catalog.py --format csv`")
    lines.append("- Search by family, path, or status:")
    lines.append("  - `python tools/orig/tab_catalog.py --search ANIM.TAB MODELS.tab`")
    lines.append("  - `python tools/orig/tab_catalog.py --search status:partial TEX1.tab`")
    lines.append("  - `python tools/orig/tab_catalog.py --search darkicemines/ANIMCURV.tab`")
    return "\n".join(lines)


def matches_pattern(item: TabAnalysis, pattern: str) -> bool:
    if pattern.startswith("status:"):
        return item.status == pattern[7:]
    if pattern.startswith("family:"):
        return pattern[7:] in item.family.lower()
    return (
        pattern in item.family.lower()
        or pattern in item.relative_path.lower()
        or (item.payload_path is not None and pattern in item.payload_path.lower())
        or pattern == item.status.lower()
    )


def search_markdown(items: list[TabAnalysis], patterns: list[str]) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    matches = [
        item
        for item in items
        if any(matches_pattern(item, pattern) for pattern in lowered)
    ]

    lines: list[str] = []
    lines.append("# Tab search")
    lines.append("")
    if not matches:
        lines.append("- No matching tab families.")
        return "\n".join(lines)

    for item in matches[:30]:
        payload_text = "none" if item.payload_path is None else item.payload_path
        lines.append(
            f"- `{item.relative_path}`: family=`{item.family}`, status=`{item.status}`, mode=`{item.mode}`, "
            f"payload=`{payload_text}`, chunks={item.chunk_count}, tail_gap={item.tail_gap}, "
            f"prefix_ratio={item.prefix_ratio:.3f}, flags=`{format_flags(item.flag_counts)}`"
        )
    if len(matches) > 30:
        lines.append(f"- ... {len(matches) - 30} more matches omitted")
    return "\n".join(lines)


def rows_to_csv(items: list[TabAnalysis]) -> str:
    fieldnames = [
        "family",
        "relative_path",
        "payload_path",
        "payload_size",
        "status",
        "mode",
        "word_count",
        "flags",
        "prefix_ratio",
        "zero_entries",
        "positive_entries",
        "unique_offsets",
        "chunk_count",
        "tail_gap",
        "min_chunk_size",
        "max_chunk_size",
        "outlier_entries",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for item in items:
        writer.writerow(
            {
                "family": item.family,
                "relative_path": item.relative_path,
                "payload_path": item.payload_path or "",
                "payload_size": "" if item.payload_size is None else item.payload_size,
                "status": item.status,
                "mode": item.mode or "",
                "word_count": item.word_count,
                "flags": format_flags(item.flag_counts),
                "prefix_ratio": f"{item.prefix_ratio:.6f}",
                "zero_entries": item.zero_entries,
                "positive_entries": item.positive_entries,
                "unique_offsets": item.unique_offsets,
                "chunk_count": "" if item.chunk_count is None else item.chunk_count,
                "tail_gap": "" if item.tail_gap is None else item.tail_gap,
                "min_chunk_size": "" if item.min_chunk_size is None else item.min_chunk_size,
                "max_chunk_size": "" if item.max_chunk_size is None else item.max_chunk_size,
                "outlier_entries": item.outlier_entries,
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover split-friendly retail `.tab` families from orig/ assets.")
    parser.add_argument(
        "--files-root",
        type=Path,
        default=Path("orig/GSAE01/files"),
        help="Path to the extracted EN files/ directory.",
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
        help="Substring search across family names, paths, and statuses.",
    )
    parser.add_argument(
        "--tail-tolerance",
        type=int,
        default=32,
        help="Maximum remaining payload bytes still treated as split-ready.",
    )
    parser.add_argument(
        "--include-special",
        action="store_true",
        help="Include `MAPS.tab`, `OBJECTS.tab`, and `mod*.tab` even though dedicated tools already cover them.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    files_root = args.files_root.resolve()
    items = [analyze_tab(path, files_root, args.tail_tolerance) for path in iter_tab_files(files_root, args.include_special)]

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(items))
        elif args.search:
            sys.stdout.write(search_markdown(items, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(items, args.tail_tolerance, args.include_special))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
