#!/usr/bin/env python3
"""Rank reference projects by high-confidence SDK signature hits in GSAE01."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sdk_dol_match import (
    DEFAULT_SDK_FILTERS,
    collect_reference_raw_functions,
    collect_reference_raw_windows,
    discover_reference_hits,
    load_target_text_splits,
    parse_int,
    parse_reference_spec,
    target_dol_path_for_version,
    verdict_for_hit,
)


DEFAULT_REFERENCES = (
    "animal_crossing:GAFE01_00",
    "final_fantasy_crystal_chronicles:GCCE01",
    "marioparty4:GMPE01_00",
    "metroid_prime:GM8E01_00",
    "pikmin:GPIE01_00",
    "super_mario_strikers:G4QE01",
    "super_mario_sunshine:GMSJ01",
    "twilight_princess:GZ2E01",
    "wind_waker:GZLE01",
)


@dataclass
class DonorStats:
    hits: int = 0
    source_likely: int = 0
    exact_sizes: int = 0
    compared_functions: int = 0
    bytes: int = 0
    score_sum: float = 0.0

    @property
    def average_score(self) -> float:
        if self.hits == 0:
            return 0.0
        return self.score_sum / self.hits


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Score matcher-ready reference projects by SDK-like signature hits "
            "against the current GSAE01 DOL."
        )
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target SFA version")
    parser.add_argument(
        "--reference",
        action="append",
        type=parse_reference_spec,
        help="Reference project and config in project:config form. Defaults to matcher-ready local references.",
    )
    parser.add_argument(
        "--target-range-start",
        type=parse_int,
        default=0x80003100,
        help="Start of the target DOL search range (default: 0x80003100).",
    )
    parser.add_argument(
        "--target-range-end",
        type=parse_int,
        default=0x80300000,
        help="End of the target DOL search range (default: 0x80300000).",
    )
    parser.add_argument(
        "--path-contains",
        action="append",
        default=[],
        help="Reference split path substring filter. Defaults to SDK-oriented filters.",
    )
    parser.add_argument("--all-splits", action="store_true", help="Disable default SDK-oriented path filters.")
    parser.add_argument("--only-unassigned", action="store_true", help="Only scan target windows outside current splits.")
    parser.add_argument("--discover-functions", action="store_true", help="Score individual reference functions.")
    parser.add_argument("--min-score", type=float, default=0.90, help="Minimum hit score as a 0-1 value.")
    parser.add_argument("--min-functions", type=int, default=1, help="Minimum functions per reference window.")
    parser.add_argument("--min-span", type=parse_int, default=0x20, help="Minimum reference text span.")
    parser.add_argument("--min-function-size", type=parse_int, default=0x20, help="Minimum function size in function mode.")
    parser.add_argument("--coarse-limit", type=int, default=30, help="Cheap shortlist size per reference window.")
    parser.add_argument("--limit-per-reference", type=int, default=3, help="Candidate target windows kept per reference.")
    parser.add_argument("--hit-limit", type=int, default=200, help="Maximum total hits to score.")
    parser.add_argument("--top-hits", type=int, default=20, help="Number of strongest hits to print.")
    return parser


@lru_cache(maxsize=None)
def target_text_splits(version: str):
    return tuple(load_target_text_splits(version))


def split_owner(version: str, start: int, end: int) -> str:
    owners = [
        split.path
        for split in target_text_splits(version)
        if not (split.end <= start or split.start >= end)
    ]
    if not owners:
        return "unassigned"
    if len(owners) == 1:
        return owners[0]
    return "crosses:" + ",".join(owners)


def main() -> int:
    args = make_parser().parse_args()
    references = args.reference or [parse_reference_spec(value) for value in DEFAULT_REFERENCES]
    path_filters = tuple(args.path_contains) if args.all_splits else tuple(args.path_contains) or DEFAULT_SDK_FILTERS

    raw_references = []
    for spec in references:
        if args.discover_functions:
            raw_references.extend(
                collect_reference_raw_functions(
                    spec,
                    path_filters,
                    min_function_size=args.min_function_size,
                )
            )
        else:
            raw_references.extend(
                collect_reference_raw_windows(
                    spec,
                    path_filters,
                    min_functions=args.min_functions,
                    min_span=args.min_span,
                    min_largest_function=0,
                    min_average_function_size=0,
                )
            )

    if not raw_references:
        raise SystemExit("No reference windows matched the requested filters")

    hits = discover_reference_hits(
        version=args.version,
        dol_path=target_dol_path_for_version(args.version),
        references=raw_references,
        range_start=args.target_range_start,
        range_end=args.target_range_end,
        min_score=args.min_score,
        limit=args.hit_limit,
        limit_per_reference=args.limit_per_reference,
        only_unassigned=args.only_unassigned,
        coarse_limit=args.coarse_limit,
        min_functions=1 if args.discover_functions else args.min_functions,
        min_span=max(args.min_span, args.min_function_size) if args.discover_functions else args.min_span,
        min_largest_function=args.min_function_size if args.discover_functions else 0,
        min_average_function_size=0,
    )

    stats: dict[str, DonorStats] = defaultdict(DonorStats)
    for hit in hits:
        stat = stats[hit.reference.game]
        stat.hits += 1
        stat.source_likely += 1 if verdict_for_hit(hit) == "source-likely" else 0
        stat.exact_sizes += hit.exact_size_matches
        stat.compared_functions += hit.compared_function_count
        stat.bytes += hit.target.span
        stat.score_sum += hit.overall_score

    print(
        f"scoreboard: refs={len(references)} windows={len(raw_references)} hits={len(hits)} "
        f"range=0x{args.target_range_start:08X}-0x{args.target_range_end:08X} "
        f"min-score={args.min_score * 100:.2f}"
    )
    if args.only_unassigned:
        print("mode=unassigned-only")

    print("donors:")
    for label, stat in sorted(
        stats.items(),
        key=lambda item: (-item[1].source_likely, -item[1].hits, -item[1].bytes, item[0]),
    ):
        exact_ratio = 0.0
        if stat.compared_functions:
            exact_ratio = stat.exact_sizes / stat.compared_functions
        print(
            f"  {label}: hits={stat.hits} source-likely={stat.source_likely} "
            f"bytes=0x{stat.bytes:X} avg={stat.average_score * 100:.2f} "
            f"exact-funcs={stat.exact_sizes}/{stat.compared_functions} ({exact_ratio * 100:.1f}%)"
        )

    print("top hits:")
    for index, hit in enumerate(hits[: args.top_hits], 1):
        owner = split_owner(args.version, hit.target.start, hit.target.end)
        print(
            f"  {index:2d}. score={hit.overall_score * 100:.2f} {verdict_for_hit(hit)} "
            f"target=0x{hit.target.start:08X}-0x{hit.target.end:08X} owner={owner}"
        )
        print(f"      ref={hit.reference.game} {hit.reference.source_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
