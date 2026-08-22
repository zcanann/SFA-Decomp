#!/usr/bin/env python3
"""Focused progress probe for dlls/objects/196_Tricky/tricky.c.

This wraps the checks that matter while iterating on Tricky:
  * build the source object
  * print the unit fuzzy rows for non-exact functions
  * print the current .sdata2 content report
  * optionally run ndiff for named functions
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = "dlls/objects/196_Tricky/tricky.c"
OBJ_TARGET = "build/GSAE01/src/dlls/objects/196_Tricky/tricky.o"
NONEXACT = (
    "trickyFindReachableRouteIndex",
    "moveTricky",
    "tricky_updateBallRoll",
    "trickyUpdateMovementState",
    "trickyGuard",
)


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def print_command_output(title: str, output: str) -> None:
    print(f"\n== {title}")
    if output.strip():
        print(output.rstrip())
    else:
        print("(no output)")


def build() -> None:
    out = run(["ninja", OBJ_TARGET]).stdout
    print_command_output("build", out)


def unit_rows() -> None:
    out = run(["python", "tools/unitfuzzy.py", UNIT, "--all"]).stdout
    rows: list[str] = []
    for line in out.splitlines():
        if "fuzzy=" in line:
            rows.append(line)
            continue
        m = re.match(r"\s*([0-9.]+)\s+\d+B\s+(\S+)", line)
        if m and (float(m.group(1)) < 100.0 or m.group(2) in NONEXACT):
            rows.append(line)
    print_command_output("unit fuzzy", "\n".join(rows))


def pool() -> None:
    proc = run(["python", "tools/pool_content_check.py", "--sections", ".sdata2", UNIT], check=False)
    print_command_output("sdata2", proc.stdout)


def ndiff(functions: list[str]) -> None:
    for func in functions:
        proc = run(["python", "tools/ndiff.py", UNIT, func], check=False)
        tail = "\n".join(proc.stdout.splitlines()[-20:])
        print_command_output(f"ndiff {func}", tail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true", help="skip rebuilding tricky.o")
    ap.add_argument("--ndiff", nargs="*", default=[], help="functions to run through tools/ndiff.py")
    ap.add_argument("--all-ndiff", action="store_true", help="run ndiff for the known non-exact functions")
    args = ap.parse_args()

    if not args.no_build:
        build()
    unit_rows()
    pool()
    funcs = list(args.ndiff)
    if args.all_ndiff:
        funcs.extend(NONEXACT)
    if funcs:
        ndiff(funcs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
