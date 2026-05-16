#!/usr/bin/env python3
"""Compute per-function fuzzy match percent for a unit by parsing objdump.

Usage: python3 tools/per_function_match.py <unit> [-v VERSION]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

OBJDUMP_CANDIDATES = [
    "build/binutils/powerpc-eabi-objdump",
    "/home/jack/code/SFA-Decomp/build/binutils/powerpc-eabi-objdump",
    "powerpc-eabi-objdump",
]


def find_objdump() -> str:
    for c in OBJDUMP_CANDIDATES:
        try:
            subprocess.run([c, "--version"], capture_output=True, check=True)
            return c
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    raise SystemExit("powerpc-eabi-objdump not found")


def disasm_symbols(objdump: str, obj: Path) -> dict[str, list[tuple[str, str]]]:
    """Return {symbol: [(addr, instr_norm), ...]} parsed from objdump.

    instr_norm strips the encoding bytes and branch/relocation addresses.
    """
    out = subprocess.run(
        [objdump, "-drz", str(obj)], capture_output=True, text=True, check=True
    ).stdout
    syms: dict[str, list[tuple[str, str]]] = {}
    cur: list[tuple[str, str]] | None = None
    sym_re = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
    instr_re = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+(.*)$")
    for line in out.splitlines():
        m = sym_re.match(line)
        if m:
            cur = []
            syms[m.group(1)] = cur
            continue
        if cur is None:
            continue
        m = instr_re.match(line)
        if m:
            addr = m.group(1)
            instr = m.group(3).strip()
            # Normalise branch targets which look like "0x1c <foo+0x1c>"
            instr = re.sub(r"<[^>]+>", "", instr)
            instr = re.sub(r"0x[0-9a-f]+", "0x?", instr)
            # objdump prints local branch targets as bare hex offsets. Those
            # offsets change whenever earlier code in the object shifts, even
            # when the branch instruction is semantically identical.
            parts = instr.split(None, 1)
            if parts and parts[0].startswith("b") and len(parts) > 1:
                instr = parts[0] + " " + re.sub(r"\b[0-9a-f]+\b", "0x?", parts[1])
            cur.append((addr, instr))
    return syms


def fuzzy_match(a: list[tuple[str, str]], b: list[tuple[str, str]]) -> float:
    """Crude per-function score: fraction of aligned instr that match."""
    if not a and not b:
        return 100.0
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    same = 0
    for i in range(n):
        if a[i][1] == b[i][1]:
            same += 1
    score = same / max(len(a), len(b)) * 100.0
    return score


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("unit")
    p.add_argument("-v", "--version", default="GSAE01")
    p.add_argument("--min-size", type=int, default=0)
    args = p.parse_args()

    cfg = Path(f"build/{args.version}/config.json")
    data = json.loads(cfg.read_text())
    unit = next(
        (u for u in data["units"] if args.unit in (u["name"], u.get("object", ""))),
        None,
    )
    if unit is None:
        print(f"Unit not found: {args.unit}", file=sys.stderr)
        return 1
    target = Path(unit["object"])
    base = target.with_name(target.name).as_posix().replace("/obj/", "/src/")
    base = Path(base)
    if not base.exists():
        print(f"Base obj missing: {base}", file=sys.stderr)
        return 1
    objdump = find_objdump()
    tgt = disasm_symbols(objdump, target)
    cur = disasm_symbols(objdump, base)
    rows = []
    for sym, ti in tgt.items():
        ci = cur.get(sym, [])
        sz = len(ti) * 4
        if sz < args.min_size:
            continue
        score = fuzzy_match(ti, ci)
        rows.append((sym, sz, score))
    rows.sort(key=lambda r: (r[2], -r[1]))
    print(f"{'sym':<40} {'sz':>6} {'pct':>6}")
    for sym, sz, sc in rows:
        print(f"{sym:<40} {sz:>6} {sc:>6.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
