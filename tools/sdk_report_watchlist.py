#!/usr/bin/env python3
"""Summarize high-signal SDK candidates from build/GSAE01/report.json."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def get_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show exact-report SDK files that are still unlinked, plus top near-miss SDK files."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("build/GSAE01/report.json"),
        help="Path to the progress report JSON.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of near-miss files to print.",
    )
    parser.add_argument(
        "--probe-exact",
        action="store_true",
        help="Run sdk_import_probe.py for exact-report SDK files that are still not linked.",
    )
    parser.add_argument(
        "--probe-near",
        action="store_true",
        help="Run sdk_import_probe.py for near-miss SDK files and summarize split/boundary drift clues.",
    )
    return parser


@dataclass
class ProbeSummary:
    sections: list[str]
    best_cluster: str
    assigned_split: str
    best_exact_hypothesis: str
    likely_boundary_drift: bool


def is_sdk(unit: dict) -> bool:
    return "sdk" in unit.get("metadata", {}).get("progress_categories", [])


def format_misses(unit: dict) -> str:
    misses = [
        f"{fn['name']}={fn.get('fuzzy_match_percent', 100.0):.3f}"
        for fn in unit.get("functions", [])
        if fn.get("fuzzy_match_percent", 100.0) != 100.0
    ]
    return ", ".join(misses[:5])


def unit_name_to_source_path(unit_name: str) -> Path | None:
    if not unit_name.startswith("main/"):
        return None

    base = Path("src") / unit_name.removeprefix("main/")
    for candidate in (base.with_suffix(".c"), base.with_suffix(".s"), base):
        if candidate.exists():
            return candidate
    return None


def parse_probe(source_path: Path) -> ProbeSummary | str:
    try:
        result = subprocess.run(
            [sys.executable, "tools/sdk_import_probe.py", str(source_path), "--show-assigned"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return f"probe failed ({exc.returncode})"

    sections: list[str] = []
    best_cluster = ""
    assigned_split = ""
    best_exact_hypothesis = ""
    likely_boundary_drift = False
    in_sections = False
    in_assigned_split = False
    in_start_hypotheses = False

    for line in result.stdout.splitlines():
        if line.startswith("sections:"):
            in_sections = True
            continue
        if line.startswith("assigned split:"):
            in_assigned_split = True
            in_start_hypotheses = False
            continue
        if line.startswith("start hypotheses:"):
            in_start_hypotheses = True
            in_assigned_split = False
            continue
        if in_sections:
            if not line.startswith("  ."):
                in_sections = False
            else:
                section_match = re.match(r"\s+(\.\S+)\s+(0x[0-9A-Fa-f]+)", line)
                if section_match:
                    sections.append(f"{section_match.group(1)}={section_match.group(2)}")
                continue
        if in_assigned_split and not assigned_split:
            assigned_match = re.match(
                r"\s+(0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+.*?delta=[+-]0x[0-9A-Fa-f]+.*?func-matches=\d+/\d+.*)",
                line,
            )
            if assigned_match:
                assigned_split = " ".join(assigned_match.group(1).split())
                continue
        if in_start_hypotheses and not best_exact_hypothesis:
            hypothesis_match = re.match(
                r"\s+(0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+.*?exact-size=(\d+).*?boundary-conflicts=(\d+).*)",
                line,
            )
            if hypothesis_match and hypothesis_match.group(2) != "0":
                best_exact_hypothesis = " ".join(hypothesis_match.group(1).split())
                likely_boundary_drift = "delta=" in assigned_split and not assigned_split.startswith(
                    best_exact_hypothesis.split()[0]
                )
                continue
        if not best_cluster and re.match(r"\s+0x[0-9A-Fa-f]+-0x[0-9A-Fa-f]+", line):
            best_cluster = " ".join(line.split())

    return ProbeSummary(
        sections=sections,
        best_cluster=best_cluster,
        assigned_split=assigned_split,
        best_exact_hypothesis=best_exact_hypothesis,
        likely_boundary_drift=likely_boundary_drift,
    )


def summarize_probe(source_path: Path, *, include_near: bool = False) -> str:
    parsed = parse_probe(source_path)
    if isinstance(parsed, str):
        return parsed

    summary_parts = []
    if parsed.sections:
        summary_parts.append("sections " + " ".join(parsed.sections))
    if parsed.assigned_split:
        summary_parts.append("assigned " + parsed.assigned_split)
    if include_near and parsed.best_exact_hypothesis:
        summary_parts.append("best-exact " + parsed.best_exact_hypothesis)
        if parsed.likely_boundary_drift:
            summary_parts.append("likely boundary drift")
    elif parsed.best_cluster:
        summary_parts.append("best " + parsed.best_cluster)
    return "; ".join(summary_parts) if summary_parts else "probe produced no summary"


def main() -> int:
    args = get_argparser().parse_args()
    data = json.loads(args.report.read_text())
    sdk_units = [unit for unit in data["units"] if is_sdk(unit)]

    exact_unlinked = []
    near_misses = []

    for unit in sdk_units:
        measures = unit["measures"]
        complete = unit.get("metadata", {}).get("complete", False)
        matched_code = measures.get("matched_code_percent", 0.0)
        matched_funcs = measures.get("matched_functions_percent", 0.0)
        fuzzy = measures.get("fuzzy_match_percent", 0.0)
        entry = (matched_code, matched_funcs, fuzzy, unit)

        if not complete and matched_code == 100.0 and matched_funcs == 100.0:
            exact_unlinked.append(entry)
        elif not complete:
            near_misses.append(entry)

    exact_unlinked.sort(key=lambda row: row[:3], reverse=True)
    near_misses.sort(key=lambda row: row[:3], reverse=True)

    print("Exact-report SDK files still not linked:")
    if exact_unlinked:
        for _, _, _, unit in exact_unlinked:
            print(f"  {unit['name']}")
            if args.probe_exact:
                source_path = unit_name_to_source_path(unit["name"])
                if source_path is None:
                    print("    probe: no source path found")
                else:
                    print(f"    probe: {summarize_probe(source_path)}")
    else:
        print("  (none)")

    print()
    print(f"Top {min(args.limit, len(near_misses))} SDK near-miss files:")
    for matched_code, matched_funcs, fuzzy, unit in near_misses[: args.limit]:
        miss_summary = format_misses(unit)
        print(
            f"  {unit['name']}: code={matched_code:.2f}% funcs={matched_funcs:.2f}% fuzzy={fuzzy:.3f}"
        )
        if miss_summary:
            print(f"    misses: {miss_summary}")
        if args.probe_near:
            source_path = unit_name_to_source_path(unit["name"])
            if source_path is None:
                print("    probe: no source path found")
            else:
                print(f"    probe: {summarize_probe(source_path, include_near=True)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
