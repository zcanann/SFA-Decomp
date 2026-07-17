#!/usr/bin/env python3
"""Rank near-matching functions by the kinds of remaining instruction diffs.

The normal report gives one percentage, but a 99.9% function with a real
branch/opcode mismatch is usually more actionable than one containing only a
register permutation or anonymous-constant relocation identity.  This tool
runs one-shot objdiff over the highest-matching incomplete units and summarizes
those categories into a compact worklist.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def object_paths(version: str, source_path: str) -> tuple[Path, Path] | None:
    source = Path(source_path)
    try:
        relative = source.relative_to("src").with_suffix(".o")
    except ValueError:
        return None
    target = ROOT / "build" / version / "obj" / relative
    base = ROOT / "build" / version / "src" / relative
    if not target.exists() or not base.exists():
        return None
    return target, base


def classify(instruction: dict) -> str | None:
    kind = instruction.get("diff_kind")
    if kind is None:
        return None
    item = instruction.get("instruction") or {}
    relocation = item.get("relocation")
    if relocation is not None and relocation.get("type_name") == "R_PPC_NONE":
        return "local_reloc"
    if kind != "DIFF_ARG_MISMATCH":
        return kind.removeprefix("DIFF_").lower()

    if relocation is not None:
        return "reloc_arg"
    return "arg"


def load_unit_diff(tool: Path, target: Path, base: Path) -> dict:
    result = subprocess.run(
        [
            str(tool),
            "diff",
            "-1",
            str(target),
            "-2",
            str(base),
            "-o",
            "-",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--min-match", type=float, default=95.0)
    parser.add_argument(
        "--unit-limit",
        type=int,
        default=60,
        help="number of highest-matching incomplete units to inspect",
    )
    parser.add_argument("--top", type=int, default=80)
    parser.add_argument(
        "--include-reloc-only",
        action="store_true",
        help="include functions whose differences are only relocation arguments",
    )
    args = parser.parse_args()

    report_path = ROOT / "build" / args.version / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    candidates: list[tuple[float, dict]] = []
    for unit in report["units"]:
        functions = unit.get("functions", [])
        incomplete = [
            function
            for function in functions
            if args.min_match <= function.get("fuzzy_match_percent", 0) < 100
        ]
        if not incomplete:
            continue
        best = max(function["fuzzy_match_percent"] for function in incomplete)
        candidates.append((best, unit))
    candidates.sort(reverse=True, key=lambda item: item[0])

    tool = ROOT / "tools" / "objdiff-cli.exe"
    rows: list[tuple[int, float, str, str, Counter[str]]] = []
    for _, unit in candidates[: args.unit_limit]:
        source_path = unit.get("metadata", {}).get("source_path", "")
        paths = object_paths(args.version, source_path)
        if paths is None:
            continue
        diff = load_unit_diff(tool, *paths)
        for symbol in diff["left"].get("symbols", []):
            match = symbol.get("match_percent")
            if match is None or not args.min_match <= match < 100:
                continue
            counts = Counter(
                category
                for instruction in symbol.get("instructions", [])
                if (category := classify(instruction)) is not None
            )
            substantive = sum(
                count
                for category, count in counts.items()
                if category not in {"arg", "reloc_arg", "local_reloc"}
            )
            if not args.include_reloc_only and substantive == 0 and counts["arg"] == 0:
                continue
            rows.append(
                (substantive, float(match), source_path, symbol["name"], counts)
            )

    rows.sort(key=lambda row: (-row[0], -row[1], row[2], row[3]))
    for substantive, match, source, symbol, counts in rows[: args.top]:
        summary = ", ".join(
            f"{category}={count}" for category, count in sorted(counts.items())
        )
        print(
            f"{match:9.5f}% structural={substantive:3d}  "
            f"{source}::{symbol}  [{summary}]"
        )


if __name__ == "__main__":
    main()
