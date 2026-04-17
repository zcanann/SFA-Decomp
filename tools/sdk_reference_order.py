#!/usr/bin/env python3
"""Analyze SDK split ordering and adjacency patterns across reference projects."""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
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
CANONICAL_EXTENSIONS = {".c", ".cpp", ".cp", ".cxx", ".s", ".S"}
PATH_ALIASES = {
    "dolphin/dvd/dvdfatal.c": "dolphin/dvd/dvdFatal.c",
    "dolphin/pad/PadClamp.c": "dolphin/pad/Padclamp.c",
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


def parse_refspec(value: str) -> RefSpec:
    if ":" not in value:
        raise argparse.ArgumentTypeError("reference must be in project:config form")
    project, config = value.split(":", 1)
    spec = RefSpec(project=project, config=config)
    if not spec.splits_path.is_file():
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
        rest = Path(rest).name
    return f"dolphin/{root}/{rest}"


def canonicalize_sdk_path(path: str) -> str:
    sdk_path = Path(path)
    if sdk_path.suffix in CANONICAL_EXTENSIONS:
        sdk_path = sdk_path.with_suffix(sdk_path.suffix.lower())
        if sdk_path.suffix.lower() in {".cpp", ".cp", ".cxx"}:
            sdk_path = sdk_path.with_suffix(".c")
    return PATH_ALIASES.get(sdk_path.as_posix(), sdk_path.as_posix())


def iter_reference_text_order(spec: RefSpec) -> Iterable[str]:
    current_path: str | None = None
    saw_text = False
    for line in spec.splits_path.read_text().splitlines():
        if line and not line.startswith(" ") and line.endswith(":"):
            if current_path is not None and saw_text:
                yield current_path
            current_path = normalize_sdk_path(line[:-1])
            if current_path is not None:
                current_path = canonicalize_sdk_path(current_path)
            saw_text = False
            continue

        if current_path is None:
            continue
        if TEXT_RE.match(line):
            saw_text = True

    if current_path is not None and saw_text:
        yield current_path


def build_reference_orders(specs: list[RefSpec]) -> dict[str, tuple[str, ...]]:
    return {spec.label: tuple(iter_reference_text_order(spec)) for spec in specs}


def build_immediate_adjacency(
    orders: dict[str, tuple[str, ...]],
) -> tuple[Counter[tuple[str, str]], dict[str, set[str]]]:
    adjacency: Counter[tuple[str, str]] = Counter()
    path_refs: dict[str, set[str]] = defaultdict(set)
    for ref, ordered_paths in orders.items():
        for path in ordered_paths:
            path_refs[path].add(ref)
        for left, right in zip(ordered_paths, ordered_paths[1:]):
            adjacency[(left, right)] += 1
    return adjacency, path_refs


def ordered_neighbors_for_path(
    orders: dict[str, tuple[str, ...]],
    path: str,
) -> tuple[Counter[str], Counter[str], dict[str, tuple[str | None, str | None]]]:
    prev_counter: Counter[str] = Counter()
    next_counter: Counter[str] = Counter()
    per_ref: dict[str, tuple[str | None, str | None]] = {}
    for ref, ordered_paths in orders.items():
        try:
            index = ordered_paths.index(path)
        except ValueError:
            continue
        previous = ordered_paths[index - 1] if index > 0 else None
        following = ordered_paths[index + 1] if index + 1 < len(ordered_paths) else None
        per_ref[ref] = (previous, following)
        if previous is not None:
            prev_counter[previous] += 1
        if following is not None:
            next_counter[following] += 1
    return prev_counter, next_counter, per_ref


def format_counter(counter: Counter[str], refs_total: int) -> list[str]:
    lines: list[str] = []
    for path, count in counter.most_common():
        lines.append(f"  {count:>2}/{refs_total} {path}")
    if not lines:
        lines.append("  none")
    return lines


def build_consensus_chains(
    adjacency: Counter[tuple[str, str]],
    path_refs: dict[str, set[str]],
    min_refs: int,
    path_filters: list[str],
    limit: int,
) -> list[tuple[int, int, str, str]]:
    rows: list[tuple[int, int, str, str]] = []
    for (left, right), count in adjacency.items():
        if count < min_refs:
            continue
        if path_filters and not all(
            needle in left.lower() or needle in right.lower() for needle in path_filters
        ):
            continue
        shared_refs = len(path_refs[left] & path_refs[right])
        rows.append((count, shared_refs, left, right))
    rows.sort(key=lambda item: (-item[0], -item[1], item[0], item[2], item[3]))
    return rows[:limit]


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze SDK split adjacency and file-order patterns across reference projects."
    )
    parser.add_argument(
        "--reference",
        type=parse_refspec,
        action="append",
        required=True,
        help="Reference project and config in project:config form. Can be repeated.",
    )
    parser.add_argument(
        "--path",
        help="Show per-reference previous/next neighbor data for one normalized SDK path.",
    )
    parser.add_argument(
        "--path-contains",
        action="append",
        default=[],
        help="Case-insensitive substring filter applied to paths in chain listings.",
    )
    parser.add_argument(
        "--min-refs",
        type=int,
        default=2,
        help="Minimum number of reference projects that must share an immediate adjacency.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=40,
        help="Maximum rows to print in chain mode (default: 40).",
    )
    return parser


def main() -> int:
    args = make_parser().parse_args()
    orders = build_reference_orders(args.reference)
    adjacency, path_refs = build_immediate_adjacency(orders)
    path_filters = [needle.lower() for needle in args.path_contains]

    if args.path:
        path = canonicalize_sdk_path(args.path)
        prev_counter, next_counter, per_ref = ordered_neighbors_for_path(orders, path)
        refs_total = len(per_ref)
        print(f"path: {path}")
        print(f"refs-present: {refs_total}/{len(args.reference)}")
        print("previous-neighbors:")
        for line in format_counter(prev_counter, refs_total):
            print(line)
        print("next-neighbors:")
        for line in format_counter(next_counter, refs_total):
            print(line)
        print("per-reference:")
        if not per_ref:
            print("  none")
            return 0
        for ref, (previous, following) in sorted(per_ref.items()):
            prev_text = previous if previous is not None else "<start>"
            next_text = following if following is not None else "<end>"
            print(f"  {ref}: prev={prev_text} next={next_text}")
        return 0

    rows = build_consensus_chains(
        adjacency=adjacency,
        path_refs=path_refs,
        min_refs=args.min_refs,
        path_filters=path_filters,
        limit=args.limit,
    )
    print(f"consensus-adjacencies: refs>={args.min_refs}")
    if not rows:
        print("  none")
        return 0
    for count, shared_refs, left, right in rows:
        print(f"  {count:>2}/{shared_refs} {left} -> {right}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
