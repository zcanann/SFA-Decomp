from __future__ import annotations

import argparse
import difflib
import json
import subprocess
from pathlib import Path


def load_units(config_path: Path) -> list[dict]:
    with config_path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data["units"]


def resolve_unit(units: list[dict], query: str) -> dict:
    normalized = query.replace("\\", "/")
    matches = []
    for unit in units:
        name = unit["name"].replace("\\", "/")
        obj = unit["object"].replace("\\", "/")
        if normalized in {name, obj, Path(name).name, Path(obj).name}:
            matches.append(unit)

    if not matches:
        raise SystemExit(f"Unit not found: {query}")
    if len(matches) > 1:
        options = ", ".join(unit["name"] for unit in matches)
        raise SystemExit(f"Ambiguous unit '{query}': {options}")
    return matches[0]


def objdump_symbol(objdump_path: Path, object_path: Path, symbol: str) -> list[str]:
    command = [
        str(objdump_path),
        "-drz",
        f"--disassemble={symbol}",
        str(object_path),
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.splitlines()


def strip_preamble(lines: list[str]) -> list[str]:
    start = 0
    for index, line in enumerate(lines):
        if line.startswith("Disassembly of section"):
            start = index + 1
            break
    return lines[start:]


def print_block(title: str, lines: list[str]) -> None:
    print(f"===== {title} =====")
    for line in lines:
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show target/current objdump for a single function symbol."
    )
    parser.add_argument("unit", help="Unit name from build/<version>/config.json")
    parser.add_argument("symbol", help="Function symbol to disassemble")
    parser.add_argument(
        "-v",
        "--version",
        default="GSAE01",
        help="Build version directory under build/ (default: GSAE01)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Also print a unified diff between target and current output",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    config_path = repo_root / "build" / args.version / "config.json"
    if not config_path.is_file():
        raise SystemExit(f"Missing config: {config_path}")

    objdump_path = repo_root / "build" / "binutils" / "powerpc-eabi-objdump.exe"
    if not objdump_path.is_file():
        raise SystemExit(f"Missing objdump: {objdump_path}")

    unit = resolve_unit(load_units(config_path), args.unit)
    target_object = repo_root / Path(unit["object"])
    current_object = repo_root / Path(unit["object"].replace(f"build/{args.version}/obj/", f"build/{args.version}/src/"))

    if not target_object.is_file():
        raise SystemExit(f"Missing target object: {target_object}")
    if not current_object.is_file():
        raise SystemExit(f"Missing current object: {current_object}")

    target_lines = strip_preamble(objdump_symbol(objdump_path, target_object, args.symbol))
    current_lines = strip_preamble(objdump_symbol(objdump_path, current_object, args.symbol))

    print_block(f"target {target_object.relative_to(repo_root)}", target_lines)
    print()
    print_block(f"current {current_object.relative_to(repo_root)}", current_lines)

    if args.diff:
        print()
        print("===== diff =====")
        for line in difflib.unified_diff(
            target_lines,
            current_lines,
            fromfile="target",
            tofile="current",
            lineterm="",
        ):
            print(line)


if __name__ == "__main__":
    main()
