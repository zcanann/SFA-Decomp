#!/usr/bin/env python3
"""Triage donor SDK units that are not claimed by the current target config."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from sdk_dol_match import (
    RawWindow,
    ReferenceSpec,
    describe_target_split_overlap,
    discover_reference_hits,
    parse_int,
    select_reference_window,
    sparse_reference_source_matches,
    sparse_verdict_for_cluster,
    target_dol_path_for_version,
    verdict_for_hit,
)
from sdk_reference_inventory import (
    RefSpec,
    build_inventory,
    canonicalize_sdk_path,
    load_configured_objects,
    load_target_splits,
    parse_refspec,
    source_exists,
)
from sdk_sparse_sweep import DEFAULT_CORRIDOR_GAP, target_search_ranges


DEFAULT_REFERENCES = (
    "animal_crossing:GAFE01_00",
    "final_fantasy_crystal_chronicles:GCCE01",
    "marioparty4:GMPE01_00",
    "metroid_prime:GM8E01_00",
    "pikmin:GPIE01_00",
    "pikmin2:GPVE01",
    "super_mario_strikers:G4QE01",
    "super_mario_sunshine:GMSJ01",
    "twilight_princess:GZ2E01",
    "wind_waker:GZLE01",
)


@dataclass(frozen=True)
class Candidate:
    path: str
    refs: tuple[str, ...]
    ref_count: int
    min_span: int
    max_span: int
    min_funcs: int
    max_funcs: int
    source_exists: bool
    configured: bool
    active: bool
    covered: bool


@dataclass(frozen=True)
class Evidence:
    whole_score: float | None = None
    whole_verdict: str | None = None
    whole_range: tuple[int, int] | None = None
    whole_ownership: str | None = None
    sparse_score: float | None = None
    sparse_verdict: str | None = None
    sparse_range: tuple[int, int] | None = None
    sparse_coverage_bytes: float | None = None
    sparse_coverage_funcs: float | None = None
    sparse_average: float | None = None
    sparse_ownership: str | None = None
    reference: str | None = None
    note: str | None = None


def sdk_report_count(version: str) -> tuple[int, int] | None:
    report_path = Path("build") / version / "report.json"
    if not report_path.is_file():
        return None
    report = json.loads(report_path.read_text())
    sdk_units = [
        unit
        for unit in report.get("units", [])
        if "sdk" in unit.get("metadata", {}).get("progress_categories", [])
    ]
    return len(sdk_units), sum(1 for unit in sdk_units if unit.get("metadata", {}).get("complete"))


def load_active_objects(version: str) -> set[str]:
    config_path = Path("build") / version / "config.json"
    if not config_path.is_file():
        return set()
    config = json.loads(config_path.read_text())
    return {unit.get("name", "").replace("\\", "/") for unit in config.get("units", [])}


def reference_spec_for_label(label: str) -> ReferenceSpec:
    project, config = label.split(":", 1)
    return ReferenceSpec(project=project, config=config)


def reference_window_to_raw(window) -> RawWindow:
    return RawWindow(
        source_path=window.source_path,
        game=window.game,
        start=window.start,
        end=window.end,
        function_defs=tuple((fn.start, fn.end, fn.name) for fn in window.functions),
    )


def build_candidates(
    version: str,
    references: list[RefSpec],
    min_refs: int,
    max_span: int | None,
    include_covered: bool,
    require_source: bool,
    path_filters: tuple[str, ...],
) -> list[Candidate]:
    _target_splits, target_canonical = load_target_splits(version)
    _configured_objects, configured_canonical = load_configured_objects()
    active_objects = load_active_objects(version)
    inventory = build_inventory(references)
    candidates: list[Candidate] = []

    for path, per_ref in inventory.items():
        canonical_path = canonicalize_sdk_path(path)
        refs = tuple(sorted(per_ref))
        if len(refs) < min_refs:
            continue
        if not include_covered and canonical_path in target_canonical:
            continue
        if path_filters and not all(needle.lower() in canonical_path.lower() for needle in path_filters):
            continue

        sizes = [unit.text_size for unit in per_ref.values()]
        funcs = [unit.text_funcs for unit in per_ref.values()]
        observed_max_span = max(sizes)
        if max_span is not None and observed_max_span > max_span:
            continue

        has_source = source_exists(canonical_path)
        if require_source and not has_source:
            continue

        candidates.append(
            Candidate(
                path=canonical_path,
                refs=refs,
                ref_count=len(refs),
                min_span=min(sizes),
                max_span=observed_max_span,
                min_funcs=min(funcs),
                max_funcs=max(funcs),
                source_exists=has_source,
                configured=canonical_path in configured_canonical,
                active=canonical_path in active_objects,
                covered=canonical_path in target_canonical,
            )
        )

    candidates.sort(
        key=lambda candidate: (
            -candidate.ref_count,
            candidate.max_funcs == 1,
            -candidate.max_span,
            not candidate.source_exists,
            candidate.path,
        )
    )
    return candidates


def select_first_reference_window(candidate: Candidate) -> tuple[str, object] | None:
    for label in candidate.refs:
        spec = reference_spec_for_label(label)
        try:
            return label, select_reference_window(spec, candidate.path)
        except (FileNotFoundError, SystemExit):
            continue
    return None


def best_whole_window_evidence(
    version: str,
    dol_path: Path,
    raw_window: RawWindow,
    search_ranges: list[tuple[int, int]],
    min_score: float,
    coarse_limit: int,
) -> tuple[object, tuple[int, int]] | tuple[None, None]:
    best = None
    best_range = None
    for start, end in search_ranges:
        hits = discover_reference_hits(
            version=version,
            dol_path=dol_path,
            references=[raw_window],
            range_start=start,
            range_end=end,
            min_score=min_score,
            limit=1,
            limit_per_reference=1,
            only_unassigned=False,
            coarse_limit=coarse_limit,
            min_functions=2,
            min_span=0x40,
            min_largest_function=0x20,
            min_average_function_size=0,
        )
        if not hits:
            continue
        if best is None or hits[0].overall_score > best.overall_score:
            best = hits[0]
            best_range = (start, end)
    return best, best_range


def audit_candidate(args: argparse.Namespace, dol_path: Path, candidate: Candidate) -> Evidence:
    search_ranges = target_search_ranges(args.version, candidate.path, args.corridor_gap)
    if not search_ranges:
        return Evidence(note="no-corridor")

    selected = select_first_reference_window(candidate)
    if selected is None:
        return Evidence(note="no-matcher-ready-reference")
    reference_label, reference_window = selected
    raw_window = reference_window_to_raw(reference_window)

    whole_hit = None
    whole_range = None
    if candidate.max_funcs >= 2 and candidate.max_span >= args.min_whole_span:
        whole_hit, whole_range = best_whole_window_evidence(
            version=args.version,
            dol_path=dol_path,
            raw_window=raw_window,
            search_ranges=search_ranges,
            min_score=args.min_whole_score,
            coarse_limit=args.coarse_limit,
        )

    sparse_best = None
    sparse_range = None
    if candidate.max_span <= args.max_sparse_span:
        for start, end in search_ranges:
            clusters = sparse_reference_source_matches(
                version=args.version,
                dol_path=dol_path,
                reference_window=reference_window,
                target_range_start=start,
                target_range_end=end,
                only_unassigned=False,
                coarse_limit=args.sparse_coarse_limit,
                limit_per_reference=args.limit_per_reference,
                limit=1,
                min_function_size=args.min_function_size,
                min_anchor_score=args.min_anchor_score,
                cluster_gap=args.cluster_gap,
            )
            if not clusters:
                continue
            if sparse_best is None or clusters[0].overall_score > sparse_best.overall_score:
                sparse_best = clusters[0]
                sparse_range = (start, end)

    return Evidence(
        whole_score=whole_hit.overall_score if whole_hit else None,
        whole_verdict=verdict_for_hit(whole_hit) if whole_hit else None,
        whole_range=(whole_hit.target.start, whole_hit.target.end) if whole_hit else None,
        whole_ownership=describe_target_split_overlap(args.version, whole_hit.target.start, whole_hit.target.end)
        if whole_hit
        else None,
        sparse_score=sparse_best.overall_score if sparse_best else None,
        sparse_verdict=sparse_verdict_for_cluster(sparse_best) if sparse_best else None,
        sparse_range=(sparse_best.start, sparse_best.end) if sparse_best else None,
        sparse_coverage_bytes=sparse_best.coverage_bytes_ratio if sparse_best else None,
        sparse_coverage_funcs=sparse_best.coverage_function_ratio if sparse_best else None,
        sparse_average=sparse_best.average_score if sparse_best else None,
        sparse_ownership=describe_target_split_overlap(args.version, sparse_best.start, sparse_best.end)
        if sparse_best
        else None,
        reference=reference_label,
    )


def classify(candidate: Candidate, evidence: Evidence) -> str:
    if evidence.whole_score is not None and evidence.whole_score >= 0.88:
        return "claim-candidate"
    if (
        evidence.sparse_score is not None
        and evidence.sparse_score >= 0.82
        and (evidence.sparse_coverage_bytes or 0.0) >= 0.60
        and candidate.max_funcs > 1
    ):
        return "split-inspect"
    if candidate.max_span <= 0x40 and evidence.sparse_score is not None:
        return "tiny-shape-mirage"
    if candidate.configured and not candidate.active and evidence.whole_score is None and evidence.sparse_score is None:
        return "configured-inactive"
    if evidence.note is not None:
        return evidence.note
    if evidence.whole_score is None and evidence.sparse_score is None:
        return "no-target-evidence"
    return "weak-evidence"


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:5.1f}%"


def range_text(value: tuple[int, int] | None) -> str:
    return "none" if value is None else f"0x{value[0]:08X}-0x{value[1]:08X}"


def print_candidate(candidate: Candidate, evidence: Evidence | None = None) -> None:
    if evidence is None:
        print(
            f"path={candidate.path} refs={candidate.ref_count} "
            f"span=0x{candidate.min_span:X}-0x{candidate.max_span:X} "
            f"funcs={candidate.min_funcs}-{candidate.max_funcs} "
            f"src={'yes' if candidate.source_exists else 'no'} "
            f"cfg={'yes' if candidate.configured else 'no'} "
            f"active={'yes' if candidate.active else 'no'} "
            f"covered={'yes' if candidate.covered else 'no'}"
        )
        print(f"  refs={','.join(candidate.refs)}")
        return

    print(
        f"{classify(candidate, evidence):18s} "
        f"path={candidate.path} refs={candidate.ref_count} "
        f"span=0x{candidate.min_span:X}-0x{candidate.max_span:X} "
        f"funcs={candidate.min_funcs}-{candidate.max_funcs} "
        f"src={'yes' if candidate.source_exists else 'no'} "
        f"cfg={'yes' if candidate.configured else 'no'} "
        f"active={'yes' if candidate.active else 'no'} "
        f"ref={evidence.reference or 'none'}"
    )
    print(
        f"  whole score={pct(evidence.whole_score)} {evidence.whole_verdict or 'none'} "
        f"target={range_text(evidence.whole_range)}"
    )
    if evidence.whole_ownership:
        print(f"    {evidence.whole_ownership}")
    print(
        f"  sparse score={pct(evidence.sparse_score)} {evidence.sparse_verdict or 'none'} "
        f"target={range_text(evidence.sparse_range)} "
        f"cover-bytes={pct(evidence.sparse_coverage_bytes)} "
        f"cover-funcs={pct(evidence.sparse_coverage_funcs)} avg={pct(evidence.sparse_average)}"
    )
    if evidence.sparse_ownership:
        print(f"    {evidence.sparse_ownership}")
    if evidence.note:
        print(f"  note={evidence.note}")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rank donor SDK units that are missing or only weakly claimed in the current target."
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument(
        "--reference",
        type=parse_refspec,
        action="append",
        help="Reference project and config in project:config form. Defaults to matcher-ready local references.",
    )
    parser.add_argument("--min-refs", type=int, default=2, help="Minimum donor projects containing the unit")
    parser.add_argument("--max-span", type=parse_int, default=0x1800, help="Maximum observed donor .text span")
    parser.add_argument("--limit", type=int, default=40, help="Maximum inventory rows to consider")
    parser.add_argument("--probe-limit", type=int, default=20, help="Maximum rows to run target signature probes for")
    parser.add_argument("--include-covered", action="store_true", help="Include units already covered by target splits")
    parser.add_argument("--require-source", action="store_true", help="Only include units with local src/ files")
    parser.add_argument("--path-contains", action="append", default=[], help="Case-insensitive path filter")
    parser.add_argument("--inventory-only", action="store_true", help="Only print inventory rows; do not run probes")
    parser.add_argument("--corridor-gap", type=parse_int, default=DEFAULT_CORRIDOR_GAP)
    parser.add_argument("--cluster-gap", type=parse_int, default=0x200)
    parser.add_argument("--min-function-size", type=parse_int, default=0x20)
    parser.add_argument("--min-anchor-score", type=float, default=0.60)
    parser.add_argument("--limit-per-reference", type=int, default=4)
    parser.add_argument("--coarse-limit", type=int, default=6)
    parser.add_argument("--sparse-coarse-limit", type=int, default=4)
    parser.add_argument("--min-whole-score", type=float, default=0.70)
    parser.add_argument("--min-whole-span", type=parse_int, default=0x80)
    parser.add_argument("--max-sparse-span", type=parse_int, default=0x1800)
    return parser


def main() -> int:
    args = make_parser().parse_args()
    references = args.reference or [parse_refspec(value) for value in DEFAULT_REFERENCES]

    sdk_count = sdk_report_count(args.version)
    if sdk_count is not None:
        print(f"configured-sdk-units={sdk_count[0]} complete={sdk_count[1]} version={args.version}")

    candidates = build_candidates(
        version=args.version,
        references=references,
        min_refs=args.min_refs,
        max_span=args.max_span,
        include_covered=args.include_covered,
        require_source=args.require_source,
        path_filters=tuple(args.path_contains),
    )[: args.limit]

    print(
        f"donor-missing-candidates={len(candidates)} "
        f"refs={len(references)} min-refs={args.min_refs} max-span=0x{args.max_span:X}"
    )
    if not candidates:
        return 0

    if args.inventory_only:
        for candidate in candidates:
            print_candidate(candidate)
        return 0

    dol_path = target_dol_path_for_version(args.version)
    for index, candidate in enumerate(candidates):
        if index >= args.probe_limit:
            print_candidate(candidate)
            continue
        evidence = audit_candidate(args, dol_path, candidate)
        print_candidate(candidate, evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
