#!/usr/bin/env python3
"""Focused progress probe for dlls/objects/196_Tricky/tricky.c.

This wraps the checks that matter while iterating on Tricky:
  * build the source object
  * print the unit fuzzy rows for non-exact functions
  * print the current .sdata2 content report
  * optionally summarize strucdiff counts for named functions
  * optionally run ndiff for named functions
  * optionally verify allocated sections with the diagnostic game link
  * optionally compare bytes, layouts, and relocations with a previous object
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import unitfuzzy
import strucdiff as structural_diff
from tricky_object_compare import compare_objects, comparison_summary, read_object

ROOT = Path(__file__).resolve().parents[1]
UNIT = "dlls/objects/196_Tricky/tricky.c"
REPORT_UNIT = "main/dlls/objects/196_Tricky/tricky"
OBJ_TARGET = "build/GSAE01/src/dlls/objects/196_Tricky/tricky.o"


def run(args: list[str], *, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        print_command_output("failed command", " ".join(args))
        print_command_output("failed output", proc.stdout)
        proc.check_returncode()
    return proc


def print_command_output(title: str, output: str) -> None:
    print(f"\n== {title}")
    if output.strip():
        print(output.rstrip())
    else:
        print("(no output)")


def build() -> None:
    out = run(["ninja", OBJ_TARGET], timeout=30).stdout
    print_command_output("build", out)


def nonexact_functions(report: dict) -> list[dict]:
    functions = report.get("functions") or []
    return sorted(
        (function for function in functions if float(function.get("fuzzy_match_percent") or 0.0) < 100.0),
        key=lambda function: float(function.get("fuzzy_match_percent") or 0.0),
    )


def unit_rows() -> list[str]:
    report = unitfuzzy.measure(unitfuzzy.find_unit("GSAE01", UNIT), "GSAE01")
    functions = nonexact_functions(report)
    rows = [f"{report['name']}  fuzzy={report['measures']['fuzzy_match_percent']:.5f}"]
    for function in functions:
        percent = float(function.get("fuzzy_match_percent") or 0.0)
        rows.append(f"  {percent:8.3f}  {function['size']:>6}B  {function['name']}")
    print_command_output("unit fuzzy", "\n".join(rows))
    return [function["name"] for function in functions]


def pool() -> None:
    proc = run([sys.executable, "tools/pool_content_check.py", "--sections", ".sdata2", UNIT], check=False)
    print_command_output("sdata2", proc.stdout)


def ndiff(functions: list[str]) -> None:
    for func in functions:
        proc = run([sys.executable, "tools/ndiff.py", UNIT, func], check=False)
        tail = "\n".join(proc.stdout.splitlines()[-20:])
        print_command_output(f"ndiff {func}", tail)


def strucdiff(functions: list[str]) -> None:
    rows: list[str] = []
    for func in functions:
        differences, _, _, target_count, source_count = structural_diff.analyse(REPORT_UNIT, func)
        if target_count == 0 and source_count == 0:
            raise RuntimeError(f"function absent from both objects: {func}")
        structure = sum(marker in "M+-" for marker, _, _ in differences)
        recolour = sum(marker == "r" for marker, _, _ in differences)
        rows.append(f"{func}: target {target_count} / ours {source_count} ; STRUC {structure} ; recolour {recolour}")
    print_command_output("strucdiff", "\n".join(rows))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true", help="skip rebuilding tricky.o")
    ap.add_argument("--struc", nargs="*", default=[], help="functions to summarize with tools/strucdiff.py")
    ap.add_argument("--all-struc", action="store_true", help="run strucdiff for the current non-exact functions")
    ap.add_argument("--ndiff", nargs="*", default=[], help="functions to run through tools/ndiff.py")
    ap.add_argument("--all-ndiff", action="store_true", help="run ndiff for the current non-exact functions")
    ap.add_argument("--link", action="store_true", help="run the diagnostic game link and allocated-section comparison")
    ap.add_argument("--baseline-object", type=Path,
                    help="compare with this object, read before building (may be the current output path)")
    ap.add_argument("--object-details", action="store_true", help="print the full baseline comparison as JSON")
    args = ap.parse_args()
    if args.object_details and args.baseline_object is None:
        ap.error("--object-details requires --baseline-object")

    baseline = read_object(args.baseline_object) if args.baseline_object is not None else None
    if not args.no_build:
        build()
    if baseline is not None:
        changes = compare_objects(baseline, read_object(ROOT / OBJ_TARGET))
        report = json.dumps(changes, indent=2) if args.object_details else comparison_summary(changes)
        print_command_output("object comparison (not a retail match verdict)", report)
    nonexact = unit_rows()
    pool()
    struc_funcs = list(args.struc)
    if args.all_struc:
        struc_funcs.extend(nonexact)
    if struc_funcs:
        strucdiff(list(dict.fromkeys(struc_funcs)))
    funcs = list(args.ndiff)
    if args.all_ndiff:
        funcs.extend(nonexact)
    if funcs:
        ndiff(list(dict.fromkeys(funcs)))
    if args.link:
        print_command_output("diagnostic link", run([sys.executable, "tools/tricky_link_probe.py"]).stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
