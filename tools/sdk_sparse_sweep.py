#!/usr/bin/env python3
"""Batch sparse-anchor sweep for likely-missing SDK files."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from dolphin_sdk_symbols import load_splits
from sdk_dol_match import (
    ReferenceSpec,
    load_dol,
    normalize_path,
    select_reference_window,
    sparse_reference_source_matches,
    sparse_verdict_for_cluster,
    target_dol_path_for_version,
)
from sdk_reference_inventory import (
    build_inventory,
    canonicalize_sdk_path,
    load_configured_objects,
    load_target_splits,
    parse_refspec,
    source_exists,
)

DEFAULT_CORRIDOR_GAP = 0x4000


@dataclass(frozen=True)
class SweepCandidate:
    path: str
    references: tuple[str, ...]
    ref_count: int
    min_span: int
    max_span: int
    source_exists: bool
    configured: bool


def parse_int(value: str) -> int:
    return int(value, 0)


def corridor_prefix(path: str) -> str:
    normalized = normalize_path(path)
    if "/" not in normalized:
        return normalized
    parent = normalized.rsplit("/", 1)[0]
    return parent + "/"


def target_search_ranges(version: str, path: str, corridor_gap: int) -> list[tuple[int, int]]:
    prefix = corridor_prefix(path)
    splits = sorted(
        (
            split
            for split in load_splits(Path("config") / version / "splits.txt")
            if split.section == ".text" and split.path.startswith(prefix)
        ),
        key=lambda split: split.start,
    )
    if not splits:
        return []

    ranges: list[tuple[int, int]] = []
    current_start = splits[0].start
    current_end = splits[0].end
    for split in splits[1:]:
        if split.start - current_end > corridor_gap:
            ranges.append((current_start, current_end))
            current_start = split.start
            current_end = split.end
            continue
        current_end = max(current_end, split.end)
    ranges.append((current_start, current_end))
    return ranges


def make_candidate_rows(
    version: str,
    references: list,
    min_refs: int,
    max_span: int | None,
    require_source: bool,
    require_cfg_missing: bool,
) -> list[SweepCandidate]:
    target_splits, target_canonical = load_target_splits(version)
    configured_objects, configured_canonical = load_configured_objects()
    inventory = build_inventory(references)
    rows: list[SweepCandidate] = []

    for path, per_ref in inventory.items():
        canonical_path = canonicalize_sdk_path(path)
        ref_count = len(per_ref)
        if ref_count < min_refs:
            continue
        if canonical_path in target_canonical:
            continue

        sizes = [unit.text_size for unit in per_ref.values()]
        max_observed_span = max(sizes)
        if max_span is not None and max_observed_span > max_span:
            continue

        has_source = source_exists(path)
        if require_source and not has_source:
            continue

        configured = path in configured_objects or canonical_path in configured_canonical
        if require_cfg_missing and configured:
            continue

        rows.append(
            SweepCandidate(
                path=canonical_path,
                references=tuple(sorted(per_ref)),
                ref_count=ref_count,
                min_span=min(sizes),
                max_span=max_observed_span,
                source_exists=has_source,
                configured=configured,
            )
        )

    rows.sort(key=lambda row: (-row.ref_count, row.max_span, row.path))
    return rows


def resolve_reference_spec(label: str) -> ReferenceSpec:
    project, config = label.split(":", 1)
    validated = parse_refspec(f"{project}:{config}")
    return ReferenceSpec(project=validated.project, config=validated.config)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Batch sparse-anchor sweep for SDK files that look missing from current EN splits."
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument(
        "--reference",
        type=parse_refspec,
        action="append",
        required=True,
        help="Reference project and config in project:config form. Can be repeated.",
    )
    parser.add_argument("--min-refs", type=int, default=1, help="Minimum reference count to include")
    parser.add_argument(
        "--max-span",
        type=parse_int,
        default=0x1200,
        help="Maximum observed reference .text span to include (default: 0x1200)",
    )
    parser.add_argument(
        "--min-function-size",
        type=parse_int,
        default=0x20,
        help="Minimum per-function size for sparse matching (default: 0x20)",
    )
    parser.add_argument(
        "--min-anchor-score",
        type=float,
        default=0.55,
        help="Minimum single-function anchor score (default: 0.55)",
    )
    parser.add_argument(
        "--limit-per-reference",
        type=int,
        default=4,
        help="Maximum one-function target hits to keep per reference function (default: 4)",
    )
    parser.add_argument(
        "--coarse-limit",
        type=int,
        default=4,
        help="Cheap shortlist size before full one-function comparison (default: 4)",
    )
    parser.add_argument(
        "--cluster-gap",
        type=parse_int,
        default=0x200,
        help="Maximum byte gap between sparse hits when clustering (default: 0x200)",
    )
    parser.add_argument(
        "--corridor-gap",
        type=parse_int,
        default=DEFAULT_CORRIDOR_GAP,
        help="Maximum split gap for merging target subsystem corridors (default: 0x4000)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of candidates to print (default: 20)",
    )
    parser.add_argument(
        "--require-source",
        action="store_true",
        help="Only include candidates that already have a local source file",
    )
    parser.add_argument(
        "--require-cfg-missing",
        action="store_true",
        help="Only include candidates not already covered by configure.py",
    )
    return parser


def main() -> int:
    args = make_parser().parse_args()
    dol_path = target_dol_path_for_version(args.version)
    load_dol(dol_path)

    candidates = make_candidate_rows(
        version=args.version,
        references=args.reference,
        min_refs=args.min_refs,
        max_span=args.max_span,
        require_source=args.require_source,
        require_cfg_missing=args.require_cfg_missing,
    )
    if not candidates:
        print("no matching SDK candidates")
        return 0

    printed = 0
    for candidate in candidates:
        search_ranges = target_search_ranges(args.version, candidate.path, args.corridor_gap)
        if not search_ranges:
            continue

        reference_window = None
        reference_label = None
        for label in candidate.references:
            spec = resolve_reference_spec(label)
            try:
                reference_window = select_reference_window(spec, candidate.path)
            except FileNotFoundError:
                continue
            except SystemExit:
                continue
            reference_label = label
            break
        if reference_window is None or reference_label is None:
            continue

        best = None
        best_range = None
        for search_range in search_ranges:
            clusters = sparse_reference_source_matches(
                version=args.version,
                dol_path=dol_path,
                reference_window=reference_window,
                target_range_start=search_range[0],
                target_range_end=search_range[1],
                only_unassigned=False,
                coarse_limit=args.coarse_limit,
                limit_per_reference=args.limit_per_reference,
                limit=1,
                min_function_size=args.min_function_size,
                min_anchor_score=args.min_anchor_score,
                cluster_gap=args.cluster_gap,
            )
            if not clusters:
                continue
            if best is None or clusters[0].overall_score > best.overall_score:
                best = clusters[0]
                best_range = search_range
        print(
            f"path={candidate.path} refs={candidate.ref_count} "
            f"span=0x{candidate.min_span:X}-0x{candidate.max_span:X} "
            f"src={'yes' if candidate.source_exists else 'no'} "
            f"cfg={'yes' if candidate.configured else 'no'} "
            f"corridors={len(search_ranges)} "
            f"ref={reference_label}"
        )
        if best is None:
            print("  best=none")
        else:
            print(
                f"  search=0x{best_range[0]:08X}-0x{best_range[1]:08X} "
                f"best=0x{best.start:08X}-0x{best.end:08X} "
                f"score={best.overall_score * 100:.2f} "
                f"avg={best.average_score * 100:.2f} "
                f"cover-bytes={best.coverage_bytes_ratio * 100:.2f} "
                f"cover-funcs={best.coverage_function_ratio * 100:.2f} "
                f"order={best.order_ratio * 100:.2f} "
                f"{sparse_verdict_for_cluster(best)}"
            )
        printed += 1
        if printed >= args.limit:
            break

    if printed == 0:
        print("no candidates produced sparse results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
