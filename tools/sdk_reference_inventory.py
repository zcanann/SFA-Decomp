#!/usr/bin/env python3
"""List SDK-oriented split paths present in reference projects and compare them against GSAE01."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "GSAE01"
SDK_ROOTS = {
    "TRK_MINNOW_DOLPHIN",
    "OdemuExi2",
    "ai",
    "amcExi2",
    "amcnotstub",
    "amcstubs",
    "ar",
    "ax",
    "axfx",
    "base",
    "card",
    "db",
    "dsp",
    "dvd",
    "exi",
    "gx",
    "hio",
    "mcc",
    "mix",
    "mtx",
    "odenotstub",
    "os",
    "pad",
    "si",
    "thp",
    "vi",
}
TEXT_RE = re.compile(r"\s*\.text\s+start:(0x[0-9A-Fa-f]+)\s+end:(0x[0-9A-Fa-f]+)")
CANONICAL_EXTENSIONS = {".c", ".cpp", ".cp", ".cxx"}
CONFIG_OBJECT_EXTENSIONS = "c|cpp|cp|cxx|s|S"
PATH_ALIASES = {
    "dolphin/dvd/dvdfatal.c": "dolphin/dvd/dvdFatal.c",
    "dolphin/pad/PadClamp.c": "dolphin/pad/Padclamp.c",
    "dolphin/pad/pad.c": "dolphin/pad/Pad.c",
    "dolphin/pad/padclamp.c": "dolphin/pad/Padclamp.c",
    "dolphin/mtx/mtx44vec.c": "dolphin/mtx/mtxvec.c",
}


@dataclass(frozen=True)
class RefSpec:
    project: str
    config: str

    @property
    def label(self) -> str:
        return f"{self.project}:{self.config}"

    @property
    def splits_path(self) -> Path:
        return ROOT / "reference_projects" / self.project / "config" / self.config / "splits.txt"


@dataclass
class RefUnit:
    path: str
    text_size: int = 0
    text_funcs: int = 0


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_refspec(value: str) -> RefSpec:
    if ":" not in value:
        raise argparse.ArgumentTypeError("reference must be in project:config form")
    project, config = value.split(":", 1)
    spec = RefSpec(project=project, config=config)
    if not spec.splits_path.exists():
        raise argparse.ArgumentTypeError(f"reference splits not found: {spec.splits_path}")
    return spec


def normalize_sdk_path(raw_path: str) -> str | None:
    path = raw_path.replace("\\", "/")
    for prefix in ("SDK/", "Dolphin/", "dolphin/"):
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    if "/" not in path:
        return None
    root, rest = path.split("/", 1)
    if root not in SDK_ROOTS:
        return None
    if root == "TRK_MINNOW_DOLPHIN":
        # Some references keep MetroTRK's original deep directory layout,
        # but our imported TRK sources are flattened by translation unit.
        rest = Path(rest).name
    return f"dolphin/{root}/{rest}"


def split_header_path(line: str) -> str | None:
    if not line or line.startswith((" ", "\t")) or ":" not in line:
        return None
    return line.split(":", 1)[0]


def canonicalize_sdk_path(path: str) -> str:
    sdk_path = Path(path)
    if sdk_path.suffix.lower() in CANONICAL_EXTENSIONS:
        sdk_path = sdk_path.with_suffix(".c")
    return PATH_ALIASES.get(sdk_path.as_posix(), sdk_path.as_posix())


def load_target_splits(version: str) -> tuple[set[str], set[str]]:
    splits_path = ROOT / "config" / version / "splits.txt"
    exact_paths: set[str] = set()
    canonical_paths: set[str] = set()
    for line in splits_path.read_text().splitlines():
        path = split_header_path(line)
        if path is not None:
            exact_paths.add(path)
            canonical_paths.add(canonicalize_sdk_path(path))
    return exact_paths, canonical_paths


def load_configured_objects() -> tuple[set[str], set[str]]:
    configure_path = ROOT / "configure.py"
    exact_paths: set[str] = set()
    canonical_paths: set[str] = set()
    for match in re.finditer(
        rf'Object\([^\n]*?,\s*"([^"]+\.(?:{CONFIG_OBJECT_EXTENSIONS}))"\)',
        configure_path.read_text(),
    ):
        path = match.group(1)
        exact_paths.add(path)
        canonical_paths.add(canonicalize_sdk_path(path))
    return exact_paths, canonical_paths


def source_exists(path: str) -> bool:
    rel = path.removeprefix("dolphin/")
    candidate = ROOT / "src" / "dolphin" / Path(rel)
    return candidate.exists()


def iter_reference_units(spec: RefSpec) -> Iterable[RefUnit]:
    current_path: str | None = None
    current_unit: RefUnit | None = None

    for line in spec.splits_path.read_text().splitlines():
        header_path = split_header_path(line)
        if header_path is not None:
            if current_unit and current_unit.text_funcs > 0:
                yield current_unit
            current_path = normalize_sdk_path(header_path)
            current_unit = RefUnit(path=current_path) if current_path else None
            continue

        if current_unit is None:
            continue

        match = TEXT_RE.match(line)
        if not match:
            continue

        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        current_unit.text_size += end - start
        current_unit.text_funcs += 1

    if current_unit and current_unit.text_funcs > 0:
        yield current_unit


def build_inventory(specs: list[RefSpec]) -> dict[str, dict[str, RefUnit]]:
    inventory: dict[str, dict[str, RefUnit]] = defaultdict(dict)
    for spec in specs:
        for unit in iter_reference_units(spec):
            inventory[unit.path][spec.label] = unit
    return inventory


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory SDK-style reference split paths across one or more reference projects "
            "and compare them against current GSAE01 split ownership."
        )
    )
    parser.add_argument(
        "-v",
        "--version",
        default=DEFAULT_VERSION,
        help=f"Target version used for current split ownership (default: {DEFAULT_VERSION})",
    )
    parser.add_argument(
        "--reference",
        type=parse_refspec,
        action="append",
        required=True,
        help="Reference project and config in project:config form. Can be repeated.",
    )
    parser.add_argument(
        "--min-refs",
        type=int,
        default=1,
        help="Minimum number of reference projects that must contain a path (default: 1)",
    )
    parser.add_argument(
        "--max-span",
        type=parse_int,
        default=None,
        help="Only show files whose largest observed total .text size is <= this value",
    )
    parser.add_argument(
        "--path-contains",
        action="append",
        default=[],
        help="Case-insensitive substring filter applied to the normalized target path",
    )
    parser.add_argument(
        "--show-present",
        action="store_true",
        help="Include files already claimed in the current target splits",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of rows to print (default: 100)",
    )
    return parser


def main() -> int:
    args = make_parser().parse_args()
    target_splits, target_canonical = load_target_splits(args.version)
    configured_objects, configured_canonical = load_configured_objects()
    inventory = build_inventory(args.reference)
    path_filters = [needle.lower() for needle in args.path_contains]

    rows = []
    for path, per_ref in inventory.items():
        ref_count = len(per_ref)
        canonical_path = canonicalize_sdk_path(path)
        if ref_count < args.min_refs:
            continue
        if not args.show_present and canonical_path in target_canonical:
            continue
        if path_filters and not all(needle in path.lower() for needle in path_filters):
            continue

        sizes = [unit.text_size for unit in per_ref.values()]
        funcs = [unit.text_funcs for unit in per_ref.values()]
        max_span = max(sizes)
        if args.max_span is not None and max_span > args.max_span:
            continue

        rows.append(
            (
                -ref_count,
                max_span,
                path,
                {
                    "path": path,
                    "refs": sorted(per_ref),
                    "ref_count": ref_count,
                    "min_span": min(sizes),
                    "max_span": max_span,
                    "min_funcs": min(funcs),
                    "max_funcs": max(funcs),
                    "present": path in target_splits,
                    "covered": canonical_path in target_canonical,
                    "configured": path in configured_objects,
                    "configured_covered": canonical_path in configured_canonical,
                    "source_exists": source_exists(path),
                },
            )
        )

    rows.sort()
    for _, _, _, row in rows[: args.limit]:
        if row["present"]:
            status = "present"
        elif row["covered"]:
            status = "covered"
        else:
            status = "missing"
        source_flag = "yes" if row["source_exists"] else "no"
        if row["configured"]:
            config_flag = "exact"
        elif row["configured_covered"]:
            config_flag = "covered"
        else:
            config_flag = "no"
        refs = ",".join(row["refs"])
        print(
            f"refs={row['ref_count']} text=0x{row['min_span']:X}-0x{row['max_span']:X} "
            f"funcs={row['min_funcs']}-{row['max_funcs']} status={status} src={source_flag} cfg={config_flag} "
            f"path={row['path']} refs:{refs}"
        )

    if not rows:
        print("no matching SDK reference paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
