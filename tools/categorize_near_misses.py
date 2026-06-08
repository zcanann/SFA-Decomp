#!/usr/bin/env python3
"""Bucket near-matched functions by their first assembly-diff symptom.

This is intentionally heuristic. It is meant to find high-yield families of
residuals to sweep, not to prove the exact source fix for every function.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
OBJDUMP = REPO / "build/binutils/powerpc-eabi-objdump.exe"
if not OBJDUMP.exists():
    OBJDUMP = REPO / "build/binutils/powerpc-eabi-objdump"

INSN_RE = re.compile(
    r"^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+){4})\s+([A-Za-z0-9_.]+)\s*(.*)$"
)
REG_RE = re.compile(r"\b[rf](?:[0-9]|[12][0-9]|3[01])\b")
STACK_RE = re.compile(r"\b-?\d+\(r1\)")
IMM_RE = re.compile(r"(?<![A-Za-z_])(?:-?\d+|0x[0-9a-fA-F]+)(?![A-Za-z_])")
BRANCH_TARGET_RE = re.compile(r"^[0-9a-fA-F]+\s+(<[^>]+>)$")


@dataclass(frozen=True)
class Insn:
    raw: str
    bytes: str
    mnemonic: str
    operands: str


@dataclass(frozen=True)
class Candidate:
    pct: float
    size: int
    unit: str
    symbol: str
    source_path: str


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def source_to_config_units(config: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for unit in config["units"]:
        name = unit["name"].replace("\\", "/")
        if name.endswith(".c"):
            out[f"src/{name}"] = unit
    return out


def candidates(report: dict, min_pct: float, max_pct: float, max_size: int) -> list[Candidate]:
    rows: list[Candidate] = []
    for unit in report["units"]:
        meta = unit.get("metadata", {})
        source_path = meta.get("source_path")
        if not source_path or meta.get("auto_generated"):
            continue
        for fn in unit.get("functions", []):
            pct = fn.get("fuzzy_match_percent")
            size = int(fn.get("size") or 0)
            if pct is None or pct >= 100.0 or pct < min_pct or pct > max_pct:
                continue
            if max_size and size > max_size:
                continue
            rows.append(Candidate(pct, size, unit["name"], fn["name"], source_path))
    rows.sort(key=lambda row: (100.0 - row.pct, row.size, row.unit, row.symbol))
    return rows


def objdump_symbol(object_path: Path, symbol: str) -> list[Insn]:
    proc = subprocess.run(
        [str(OBJDUMP), "-drz", f"--disassemble={symbol}", str(object_path)],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    insns: list[Insn] = []
    for line in proc.stdout.splitlines():
        match = INSN_RE.match(line)
        if match:
            insns.append(
                Insn(
                    raw=line.strip(),
                    bytes=" ".join(match.group(1).split()),
                    mnemonic=match.group(2),
                    operands=match.group(3).strip(),
                )
            )
    return insns


def first_diffs(target: list[Insn], current: list[Insn], limit: int) -> list[tuple[Insn | None, Insn | None]]:
    out: list[tuple[Insn | None, Insn | None]] = []
    max_len = max(len(target), len(current))
    for i in range(max_len):
        t = target[i] if i < len(target) else None
        c = current[i] if i < len(current) else None
        if t is None or c is None:
            same = False
        else:
            same = (t.bytes, t.mnemonic, normalize_operands(t.operands)) == (
                c.bytes,
                c.mnemonic,
                normalize_operands(c.operands),
            )
        if not same:
            out.append((t, c))
            if len(out) >= limit:
                break
    return out


def normalize_operands(operands: str) -> str:
    match = BRANCH_TARGET_RE.match(operands)
    if match:
        return match.group(1)
    return operands


def regs_only_changed(a: str, b: str) -> bool:
    return REG_RE.sub("R", a) == REG_RE.sub("R", b) and a != b


def immediates_only_changed(a: str, b: str) -> bool:
    return IMM_RE.sub("N", a) == IMM_RE.sub("N", b) and a != b


def branch_mnemonic(mnemonic: str) -> bool:
    return mnemonic.startswith("b") or mnemonic in {"bdnz", "bdz"}


def classify(diffs: list[tuple[Insn | None, Insn | None]]) -> str:
    if not diffs:
        return "unknown/no parsed diff"
    pairs = [(t, c) for t, c in diffs if t is not None and c is not None]
    if not pairs:
        return "size/symbol boundary drift"

    first_t, first_c = pairs[0]
    first4 = pairs[:4]

    if any(STACK_RE.search(t.operands) and STACK_RE.search(c.operands) for t, c in first4):
        return "stack local layout / temp-slot order"

    if first_t.mnemonic == first_c.mnemonic and branch_mnemonic(first_t.mnemonic):
        return "branch target / block layout"

    if (
        len(pairs) >= 2
        and first_t.mnemonic.startswith("cmp")
        and first_c.mnemonic.startswith("cmp")
        and branch_mnemonic(pairs[1][0].mnemonic)
        and branch_mnemonic(pairs[1][1].mnemonic)
    ):
        return "loop bound or compare sense"

    if first_t.mnemonic.startswith("cmp") and first_c.mnemonic.startswith("cmp"):
        return "compare width/immediate/sign"

    if first_t.mnemonic == first_c.mnemonic and first_t.mnemonic in {"addi", "addis", "li"}:
        if immediates_only_changed(first_t.operands, first_c.operands):
            return "off-by-one/immediate constant"

    if first_t.mnemonic == first_c.mnemonic and first_t.mnemonic.startswith("f"):
        if regs_only_changed(first_t.operands, first_c.operands):
            if first_t.mnemonic in {"fadds", "fmuls"}:
                return "FP operand order / constant ownership"
            return "FP register coloring"

    if first_t.mnemonic == first_c.mnemonic and regs_only_changed(first_t.operands, first_c.operands):
        return "GPR register coloring / value spelling"

    if any(t.mnemonic == c.mnemonic and regs_only_changed(t.operands, c.operands) for t, c in first4):
        return "register coloring cascade"

    if first_t.mnemonic != first_c.mnemonic and (
        branch_mnemonic(first_t.mnemonic) or branch_mnemonic(first_c.mnemonic)
    ):
        return "branch sense / control-flow shape"

    if first_t.mnemonic == first_c.mnemonic and immediates_only_changed(first_t.operands, first_c.operands):
        return "immediate/displacement constant"

    return "mixed structural/codegen drift"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="GSAE01")
    parser.add_argument("--min-pct", type=float, default=99.9)
    parser.add_argument("--max-pct", type=float, default=99.999999)
    parser.add_argument("--max-size", type=int, default=5000)
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--diff-limit", type=int, default=4)
    parser.add_argument("--examples", type=int, default=5)
    args = parser.parse_args()

    build = REPO / "build" / args.version
    report = load_json(build / "report.json")
    config = load_json(build / "config.json")
    by_source = source_to_config_units(config)

    counts: Counter[str] = Counter()
    bytes_by_cat: Counter[str] = Counter()
    unit_counts: dict[str, Counter[str]] = defaultdict(Counter)
    unit_bytes: dict[str, Counter[str]] = defaultdict(Counter)
    examples: dict[str, list[tuple[Candidate, list[tuple[Insn | None, Insn | None]]]]] = defaultdict(list)
    errors: list[tuple[Candidate, str]] = []

    rows = candidates(report, args.min_pct, args.max_pct, args.max_size)[: args.limit]
    for row in rows:
        unit_cfg = by_source.get(row.source_path)
        if unit_cfg is None:
            errors.append((row, "no config unit for source_path"))
            continue
        target_obj = REPO / unit_cfg["object"]
        current_obj = REPO / unit_cfg["object"].replace(
            f"build/{args.version}/obj/", f"build/{args.version}/src/"
        )
        try:
            diffs = first_diffs(
                objdump_symbol(target_obj, row.symbol),
                objdump_symbol(current_obj, row.symbol),
                args.diff_limit,
            )
        except Exception as exc:  # noqa: BLE001 - report and keep sweeping
            errors.append((row, str(exc).splitlines()[0]))
            continue
        cat = classify(diffs)
        counts[cat] += 1
        bytes_by_cat[cat] += row.size
        unit_counts[row.source_path][cat] += 1
        unit_bytes[row.source_path][cat] += row.size
        if len(examples[cat]) < args.examples:
            examples[cat].append((row, diffs))

    print(
        f"Analyzed {sum(counts.values())}/{len(rows)} candidates "
        f"({args.min_pct} <= pct < 100, size <= {args.max_size}, limit {args.limit})"
    )
    if errors:
        print(f"Errors: {len(errors)}")
        for row, err in errors[:8]:
            print(f"  {row.unit}/{row.symbol}: {err}")
    print()
    print("Category summary:")
    for cat, count in counts.most_common():
        print(f"  {count:3} funcs  {bytes_by_cat[cat]:7} bytes  {cat}")

    print()
    print("Top source files by partial-function count:")
    unit_rows = []
    for source_path, counter in unit_counts.items():
        total = sum(counter.values())
        total_bytes = sum(unit_bytes[source_path].values())
        top_cat, top_count = counter.most_common(1)[0]
        unit_rows.append((total, total_bytes, top_count, top_cat, source_path, counter))
    unit_rows.sort(reverse=True)
    for total, total_bytes, top_count, top_cat, source_path, counter in unit_rows[:25]:
        second = ""
        if len(counter) > 1:
            cat2, count2 = counter.most_common(2)[1]
            second = f"; next {count2} {cat2}"
        print(
            f"  {total:3} funcs  {total_bytes:7} bytes  "
            f"dominant {top_count:3} {top_cat}{second}  {source_path}"
        )

    print()
    print("Examples:")
    for cat, count in counts.most_common():
        print(f"\n## {cat} ({count})")
        for row, diffs in examples[cat]:
            print(f"- {row.pct:.5f}% {row.size}B {row.unit}/{row.symbol}")
            for t, c in diffs[:2]:
                if t is None or c is None:
                    print(f"    T: {t.raw if t else '<missing>'}")
                    print(f"    C: {c.raw if c else '<missing>'}")
                else:
                    print(f"    T: {t.mnemonic:8} {t.operands}")
                    print(f"    C: {c.mnemonic:8} {c.operands}")


if __name__ == "__main__":
    main()
