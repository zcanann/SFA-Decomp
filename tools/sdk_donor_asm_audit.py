#!/usr/bin/env python3
"""Compare active SDK inline-asm usage against donor source files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from sdk_dol_match import (
    SDK_ROOTS,
    collect_reference_raw_windows,
    discover_reference_hits,
    load_target_text_splits,
    normalize_path,
    parse_reference_spec,
    target_dol_path_for_version,
    verdict_for_hit,
)


ROOT = Path(__file__).resolve().parents[1]
ASM_RE = re.compile(r"\b(?:asm|ASM)\b|__asm|GLOBAL_ASM|#pragma\s+asm")
DEFAULT_REFERENCES = (
    "animal_crossing",
    "final_fantasy_crystal_chronicles",
    "marioparty4",
    "metroid_prime",
    "pikmin",
    "pikmin2",
    "super_mario_strikers",
    "super_mario_sunshine",
    "twilight_princess",
    "wind_waker",
)
DEFAULT_SIGNATURE_REFERENCES = (
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
class DonorSource:
    project: str
    path: Path
    asm_count: int
    state: str | None


@dataclass(frozen=True)
class SignatureSummary:
    verdict: str
    score: float
    target_start: int
    target_end: int
    owner: str
    owner_matches: bool
    reference: str
    exact_size_matches: int
    compared_function_count: int


def asm_count(path: Path) -> int:
    return len(ASM_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))


def active_sdk_sources(version: str) -> list[Path]:
    config_path = ROOT / "build" / version / "config.json"
    if not config_path.is_file():
        raise SystemExit(f"Missing build config: {config_path}")
    config = json.loads(config_path.read_text())
    sources: list[Path] = []
    for unit in config.get("units", []):
        name = unit.get("name", "").replace("\\", "/")
        if not name.startswith(("dolphin/", "Runtime.PPCEABI.H/")):
            continue
        path = ROOT / "src" / name
        if path.suffix in {".c", ".cpp", ".cp"} and path.is_file():
            sources.append(path)
    return sorted(sources)


@lru_cache(maxsize=None)
def donor_object_states(project: str) -> dict[str, str]:
    configure_path = ROOT / "reference_projects" / project / "configure.py"
    if not configure_path.is_file():
        return {}
    text = configure_path.read_text(encoding="utf-8", errors="ignore")
    states: dict[str, str] = {}
    for match in re.finditer(r"Object\(\s*([^,\n]+),\s*\"([^\"]+)\"", text):
        state = match.group(1).strip()
        rel = normalize_path(match.group(2))
        states[rel] = state
    return states


def is_matching_state(state: str | None) -> bool:
    return state == "Matching" or (state is not None and state.startswith("MatchingFor"))


def normalize_source_rel(rel: str) -> str:
    normalized = normalize_path(rel)
    if normalized.startswith(("dolphin/", "Runtime.PPCEABI.H/")):
        return normalized

    parts = rel.replace("\\", "/").split("/")
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part == "dolphin" and index + 1 < len(parts):
            return normalize_path("/".join(parts[index:]))
        if parts[index] in SDK_ROOTS and index + 1 < len(parts):
            return normalize_path("/".join(parts[index:]))
    return normalized


def donor_source_index(projects: tuple[str, ...]) -> dict[str, list[DonorSource]]:
    index: dict[str, list[DonorSource]] = {}
    for project in projects:
        root = ROOT / "reference_projects" / project
        src_root = root / "src"
        if not src_root.is_dir():
            continue
        object_states = donor_object_states(project)
        for path in src_root.rglob("*"):
            if path.suffix not in {".c", ".cpp", ".cp"}:
                continue
            rel = path.relative_to(src_root).as_posix()
            normalized = normalize_source_rel(rel)
            if not normalized.startswith(("dolphin/", "Runtime.PPCEABI.H/")):
                continue
            index.setdefault(normalized, []).append(
                DonorSource(
                    project=project,
                    path=path,
                    asm_count=asm_count(path),
                    state=object_states.get(normalized),
                )
            )
    return index


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


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


def signature_summary(rel: str, args: argparse.Namespace) -> SignatureSummary | None:
    references = args.signature_reference or [
        parse_reference_spec(value) for value in DEFAULT_SIGNATURE_REFERENCES
    ]
    raw_references = []
    for spec in references:
        for reference in collect_reference_raw_windows(
            spec,
            (rel,),
            min_functions=args.signature_min_functions,
            min_span=args.signature_min_span,
        ):
            if (
                (args.signature_only_matching_donor or args.only_matching_donor)
                and not is_matching_state(donor_object_states(spec.project).get(normalize_path(reference.source_path)))
            ):
                continue
            raw_references.append(reference)
    if not raw_references:
        return None

    hits = discover_reference_hits(
        version=args.version,
        dol_path=target_dol_path_for_version(args.version),
        references=raw_references,
        range_start=args.signature_range_start,
        range_end=args.signature_range_end,
        min_score=args.signature_min_score,
        limit=1,
        limit_per_reference=1,
        only_unassigned=False,
        coarse_limit=args.signature_coarse_limit,
        min_functions=args.signature_min_functions,
        min_span=args.signature_min_span,
        min_largest_function=0,
        min_average_function_size=0,
    )
    if not hits:
        return None

    hit = hits[0]
    owner = split_owner(args.version, hit.target.start, hit.target.end)
    return SignatureSummary(
        verdict=verdict_for_hit(hit),
        score=hit.overall_score,
        target_start=hit.target.start,
        target_end=hit.target.end,
        owner=owner,
        owner_matches=rel in owner,
        reference=f"{hit.reference.game} {hit.reference.source_path}",
        exact_size_matches=hit.exact_size_matches,
        compared_function_count=hit.compared_function_count,
    )


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument(
        "--reference-project",
        action="append",
        help="Reference project directory under reference_projects/. Defaults to common SDK donors.",
    )
    parser.add_argument("--path-contains", action="append", default=[], help="Case-insensitive source filter")
    parser.add_argument("--only-clean-donor", action="store_true", help="Only print rows with a donor asm_count of zero")
    parser.add_argument("--only-matching-donor", action="store_true", help="Only consider donors marked Matching/MatchingFor")
    parser.add_argument("--only-with-donor", action="store_true", help="Suppress active asm files with no donor source")
    parser.add_argument("--show-signatures", action="store_true", help="Annotate each row with the best DOL signature hit")
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help="Only print rows whose best donor signature has a target hit. Implies --show-signatures.",
    )
    parser.add_argument(
        "--require-owner-match",
        action="store_true",
        help="Only print rows whose best donor signature lands in the same target split owner. Implies --require-signature.",
    )
    parser.add_argument(
        "--signature-reference",
        action="append",
        type=parse_reference_spec,
        help="Reference project/config for signature annotations in project:config form.",
    )
    parser.add_argument("--signature-min-score", type=float, default=0.70)
    parser.add_argument("--signature-only-matching-donor", action="store_true")
    parser.add_argument("--signature-min-functions", type=int, default=2)
    parser.add_argument("--signature-min-span", type=lambda value: int(value, 0), default=0x20)
    parser.add_argument("--signature-range-start", type=lambda value: int(value, 0), default=0x80003100)
    parser.add_argument("--signature-range-end", type=lambda value: int(value, 0), default=0x80300000)
    parser.add_argument("--signature-coarse-limit", type=int, default=30)
    parser.add_argument("--limit", type=int, default=100)
    return parser


def main() -> int:
    args = make_parser().parse_args()
    if args.require_owner_match:
        args.require_signature = True
    if args.require_signature:
        args.show_signatures = True
    projects = tuple(args.reference_project or DEFAULT_REFERENCES)
    donor_index = donor_source_index(projects)
    filters = tuple(value.lower() for value in args.path_contains)

    rows = []
    for source in active_sdk_sources(args.version):
        rel = source.relative_to(ROOT / "src").as_posix()
        if filters and not all(value in rel.lower() for value in filters):
            continue
        local_asm = asm_count(source)
        if local_asm == 0:
            continue
        donors = tuple(sorted(donor_index.get(rel, ()), key=lambda donor: (donor.asm_count, donor.project)))
        if args.only_matching_donor:
            donors = tuple(donor for donor in donors if is_matching_state(donor.state))
        if args.only_with_donor and not donors:
            continue
        if args.only_clean_donor and not any(donor.asm_count == 0 for donor in donors):
            continue
        min_donor_asm = min((donor.asm_count for donor in donors), default=None)
        rows.append((min_donor_asm is None, min_donor_asm if min_donor_asm is not None else 9999, -local_asm, rel, local_asm, donors))

    rows.sort()
    output_rows = []
    for row in rows:
        signature = signature_summary(row[3], args) if args.show_signatures else None
        if args.require_signature and signature is None:
            continue
        if args.require_owner_match and signature is not None and not signature.owner_matches:
            continue
        output_rows.append((row, signature))

    print(f"active-sdk-asm-sources={len(output_rows)} donor-projects={len(projects)} version={args.version}")
    for row, signature in output_rows[: args.limit]:
        _no_donor, min_donor_asm, _neg_local_asm, rel, local_asm, donors = row
        donor_label = "none"
        if donors:
            donor_label = ", ".join(
                f"{donor.project}:{donor.asm_count}:{donor.state or '?'}" for donor in donors[:5]
            )
            if len(donors) > 5:
                donor_label += f", ... ({len(donors)} total)"
        if donors and min_donor_asm == 0:
            status = "clean-donor"
        elif donors:
            status = "asm-common"
        else:
            status = "no-donor-source"
        print(f"{status:16s} local-asm={local_asm:2d} min-donor-asm={min_donor_asm if donors else 'n/a'} path={rel}")
        print(f"  donors={donor_label}")
        if donors:
            print(f"  best={relative(donors[0].path)}")
        if args.show_signatures:
            if signature is None:
                print("  signature=none")
            else:
                print(
                    f"  signature={signature.verdict} score={signature.score * 100:.2f} "
                    f"target=0x{signature.target_start:08X}-0x{signature.target_end:08X} "
                    f"owner={signature.owner} owner-match={'yes' if signature.owner_matches else 'no'} "
                    f"exact={signature.exact_size_matches}/"
                    f"{signature.compared_function_count}"
                )
                print(f"  signature-ref={signature.reference}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
