#!/usr/bin/env python3
"""Rank near-match functions where aligned fuzzy scoring is misleading.

This complements per_function_match.py. The existing score is intentionally
simple: instruction N must equal instruction N. That makes it easy to miss
functions that are nearly identical except for one inserted instruction near
the top. This report adds a SequenceMatcher score so those candidates float up.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
from pathlib import Path

OBJDUMP_CANDIDATES = [
    "build/binutils/powerpc-eabi-objdump",
    "powerpc-eabi-objdump",
]


def find_objdump() -> str:
    for candidate in OBJDUMP_CANDIDATES:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, check=True)
            return candidate
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    raise SystemExit("powerpc-eabi-objdump not found")


def normalize_instruction(instr: str) -> str:
    instr = re.sub(r"<[^>]+>", "", instr)
    instr = re.sub(r"0x[0-9a-f]+", "0x?", instr)
    parts = instr.split(None, 1)
    if parts and parts[0].startswith("b") and len(parts) > 1:
        instr = parts[0] + " " + re.sub(r"\b[0-9a-f]+\b", "0x?", parts[1])
    return instr


def disasm_symbols(objdump: str, obj: Path) -> dict[str, list[str]]:
    out = subprocess.run([objdump, "-drz", str(obj)], capture_output=True, text=True, check=True).stdout
    syms: dict[str, list[str]] = {}
    cur: list[str] | None = None
    sym_re = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
    instr_re = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+(.*)$")
    for line in out.splitlines():
        sym_match = sym_re.match(line)
        if sym_match:
            cur = []
            syms[sym_match.group(1)] = cur
            continue
        if cur is None:
            continue
        instr_match = instr_re.match(line)
        if instr_match:
            cur.append(normalize_instruction(instr_match.group(1).strip()))
    return syms


def aligned_score(target: list[str], current: list[str]) -> float:
    if not target and not current:
        return 100.0
    compared = min(len(target), len(current))
    if compared == 0:
        return 0.0
    same = sum(1 for i in range(compared) if target[i] == current[i])
    return same / max(len(target), len(current)) * 100.0


def sequence_score(target: list[str], current: list[str]) -> float:
    if not target and not current:
        return 100.0
    matcher = difflib.SequenceMatcher(a=target, b=current, autojunk=False)
    same = sum(size for _, _, size in matcher.get_matching_blocks())
    return same / max(len(target), len(current)) * 100.0


def resolve_unit(version: str, unit_name: str) -> tuple[Path, Path]:
    config_path = Path("build") / version / "config.json"
    config = json.loads(config_path.read_text())
    unit = next(
        (u for u in config["units"] if unit_name in (u["name"], u.get("object", ""))),
        None,
    )
    if unit is None:
        raise SystemExit(f"Unit not found: {unit_name}")
    target = Path(unit["object"])
    current = Path(target.as_posix().replace("/obj/", "/src/"))
    if not current.exists():
        raise SystemExit(f"Current object missing: {current}")
    return target, current


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("unit")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--min-size", type=int, default=64)
    parser.add_argument("--min-sequence", type=float, default=75.0)
    parser.add_argument("--max-aligned", type=float, default=80.0)
    args = parser.parse_args()

    target_obj, current_obj = resolve_unit(args.version, args.unit)
    objdump = find_objdump()
    target_syms = disasm_symbols(objdump, target_obj)
    current_syms = disasm_symbols(objdump, current_obj)

    rows = []
    for sym, target_instrs in target_syms.items():
        current_instrs = current_syms.get(sym, [])
        size = len(target_instrs) * 4
        if size < args.min_size:
            continue
        aligned = aligned_score(target_instrs, current_instrs)
        sequence = sequence_score(target_instrs, current_instrs)
        if sequence >= args.min_sequence and aligned <= args.max_aligned:
            rows.append((sequence - aligned, sequence, aligned, size, sym))

    rows.sort(reverse=True)
    print(f"{'sym':<40} {'sz':>6} {'aligned':>8} {'seq':>8} {'gap':>8}")
    for gap, sequence, aligned, size, sym in rows:
        print(f"{sym:<40} {size:>6} {aligned:>8.1f} {sequence:>8.1f} {gap:>8.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
