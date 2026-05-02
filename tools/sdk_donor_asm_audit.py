#!/usr/bin/env python3
"""Compare active SDK inline-asm usage against donor source files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from sdk_dol_match import normalize_path


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


@dataclass(frozen=True)
class DonorSource:
    project: str
    path: Path
    asm_count: int


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


def donor_source_index(projects: tuple[str, ...]) -> dict[str, list[DonorSource]]:
    index: dict[str, list[DonorSource]] = {}
    for project in projects:
        root = ROOT / "reference_projects" / project
        src_root = root / "src"
        if not src_root.is_dir():
            continue
        for path in src_root.rglob("*"):
            if path.suffix not in {".c", ".cpp", ".cp"}:
                continue
            rel = path.relative_to(src_root).as_posix()
            normalized = normalize_path(rel)
            if not normalized.startswith(("dolphin/", "Runtime.PPCEABI.H/")):
                continue
            index.setdefault(normalized, []).append(
                DonorSource(project=project, path=path, asm_count=asm_count(path))
            )
    return index


def relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


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
    parser.add_argument("--only-with-donor", action="store_true", help="Suppress active asm files with no donor source")
    parser.add_argument("--limit", type=int, default=100)
    return parser


def main() -> int:
    args = make_parser().parse_args()
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
        if args.only_with_donor and not donors:
            continue
        if args.only_clean_donor and not any(donor.asm_count == 0 for donor in donors):
            continue
        min_donor_asm = min((donor.asm_count for donor in donors), default=None)
        rows.append((min_donor_asm is None, min_donor_asm if min_donor_asm is not None else 9999, -local_asm, rel, local_asm, donors))

    rows.sort()
    print(f"active-sdk-asm-sources={len(rows)} donor-projects={len(projects)} version={args.version}")
    for _no_donor, min_donor_asm, _neg_local_asm, rel, local_asm, donors in rows[: args.limit]:
        donor_label = "none"
        if donors:
            donor_label = ", ".join(f"{donor.project}:{donor.asm_count}" for donor in donors[:5])
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
