#!/usr/bin/env python3
"""Audit configured NonMatching SDK objects against matching donor signatures."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from sdk_dol_match import (
    collect_reference_raw_windows,
    discover_reference_hits,
    load_target_text_splits,
    normalize_path,
    parse_reference_spec,
    target_dol_path_for_version,
    verdict_for_hit,
)
from sdk_donor_asm_audit import donor_object_states, is_matching_state
from sdk_linkage_candidates import SDK_PREFIXES, has_active_unit, object_blocks


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCES = (
    "animal_crossing:GAFE01_00",
    "final_fantasy_crystal_chronicles:GCCE01",
    "final_fantasy_crystal_chronicles:GCCP01",
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
class ConfigObject:
    path: str
    progress_category: str | None


def parse_nonmatching_sdk_objects(include_game_classified: bool) -> list[ConfigObject]:
    text = (ROOT / "configure.py").read_text()
    objects: list[ConfigObject] = []
    for block in object_blocks(text):
        match = re.search(r'Object\(\s*NonMatching\s*,\s*"([^"]+)"', block, re.DOTALL)
        if not match:
            continue
        path = match.group(1)
        if not path.startswith(SDK_PREFIXES):
            continue
        category_match = re.search(r'progress_category\s*=\s*"([^"]+)"', block)
        category = category_match.group(1) if category_match else None
        if category == "game" and not include_game_classified:
            continue
        objects.append(ConfigObject(path=path, progress_category=category))
    return objects


def split_owner(version: str, start: int, end: int) -> str:
    owners = [
        split.path
        for split in load_target_text_splits(version)
        if not (split.end <= start or split.start >= end)
    ]
    if not owners:
        return "unassigned"
    if len(owners) == 1:
        return owners[0]
    return "crosses:" + ",".join(owners)


def has_configured_split(version: str, path: str) -> bool:
    return any(split.path == path.replace("\\", "/") for split in load_target_text_splits(version))


def matching_reference_windows(path: str, references) -> list:
    windows = []
    for spec in references:
        state = donor_object_states(spec.project).get(normalize_path(path))
        for window in collect_reference_raw_windows(spec, (path,), min_functions=1, min_span=0x4):
            window_state = donor_object_states(spec.project).get(normalize_path(window.source_path), state)
            if not is_matching_state(window_state):
                continue
            windows.append(window)
    return windows


def reference_span(window) -> int:
    return window.end - window.start


def display_verdict(version: str, path: str, hit, donor_windows: list) -> str:
    owner = split_owner(version, hit.target.start, hit.target.end)
    max_span = max((reference_span(window) for window in donor_windows), default=0)
    if max_span <= 0x40 and path not in owner:
        return "tiny-shape-mirage"
    return verdict_for_hit(hit)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--reference", action="append", type=parse_reference_spec)
    parser.add_argument("--include-game-classified", action="store_true")
    parser.add_argument("--min-score", type=float, default=0.70)
    parser.add_argument("--only-owner-match", action="store_true")
    parser.add_argument("--hide-no-hit", action="store_true")
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--target-range-start", type=lambda value: int(value, 0), default=0x80003100)
    parser.add_argument("--target-range-end", type=lambda value: int(value, 0), default=0x80300000)
    return parser


def main() -> int:
    args = make_parser().parse_args()
    references = args.reference or [parse_reference_spec(value) for value in DEFAULT_REFERENCES]
    rows = []
    for obj in parse_nonmatching_sdk_objects(args.include_game_classified):
        path = obj.path.replace("\\", "/")
        canonical_path = normalize_path(path)
        windows = matching_reference_windows(path, references)
        hits = []
        if windows:
            hits = discover_reference_hits(
                version=args.version,
                dol_path=target_dol_path_for_version(args.version),
                references=windows,
                range_start=args.target_range_start,
                range_end=args.target_range_end,
                min_score=args.min_score,
                limit=1,
                limit_per_reference=1,
                only_unassigned=False,
                coarse_limit=30,
                min_functions=1,
                min_span=0x4,
                min_largest_function=0,
                min_average_function_size=0,
            )
        hit = hits[0] if hits else None
        if hit is None:
            if args.hide_no_hit:
                continue
        elif args.only_owner_match and path not in split_owner(args.version, hit.target.start, hit.target.end):
            continue
        rows.append((obj, path, canonical_path, len(windows), hit))

    rows.sort(
        key=lambda row: (
            row[4] is not None,
            row[4].overall_score if row[4] else -1.0,
            row[3],
            row[1],
        ),
        reverse=True,
    )

    print(f"nonmatching-sdk-objects={len(rows)} version={args.version}")
    for obj, path, canonical_path, donor_windows, hit in rows[: args.limit]:
        active = has_active_unit(args.version, obj.path)
        split = has_configured_split(args.version, path)
        category = obj.progress_category or "sdk"
        if hit is None:
            print(
                f"no-hit          active={'yes' if active else 'no '} split={'yes' if split else 'no '} "
                f"donors={donor_windows:2d} category={category:4s} path={path}"
            )
            continue
        owner = split_owner(args.version, hit.target.start, hit.target.end)
        owner_matches = path in owner
        alias_note = "" if canonical_path == path else f" canonical={canonical_path}"
        print(
            f"{display_verdict(args.version, path, hit, windows):17s} score={hit.overall_score * 100:6.2f} "
            f"active={'yes' if active else 'no '} split={'yes' if split else 'no '} "
            f"owner-match={'yes' if owner_matches else 'no '} donors={donor_windows:2d} "
            f"category={category:4s} path={path}{alias_note}"
        )
        print(
            f"  target=0x{hit.target.start:08X}-0x{hit.target.end:08X} owner={owner} "
            f"exact={hit.exact_size_matches}/{hit.compared_function_count}"
        )
        print(f"  ref={hit.reference.game} {hit.reference.source_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
