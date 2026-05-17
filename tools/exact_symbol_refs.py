#!/usr/bin/env python3
"""Find raw FUN_ references that have named symbols at the same address."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SYMBOL_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*) = \.text:0x([0-9A-Fa-f]{8}); // type:function"
)
FUN_RE = re.compile(r"\bFUN_([0-9A-Fa-f]{8})\b")
AUTO_NAME_RE = re.compile(r"^(FUN|fn|lbl|__|_)")


DEFAULT_SKIP = {
    # Known noisy or duplicated/boundary-sensitive hits.
    "8007e77c",
    "801101dc",
    "801847e8",
    "801d1e24",
    "801d80f4",
    "801feb30",
    "80247f54",
}


def load_symbols(symbols_path: Path) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for line in symbols_path.read_text().splitlines():
        match = SYMBOL_RE.match(line)
        if match is None:
            continue
        name, address = match.groups()
        if not AUTO_NAME_RE.match(name):
            symbols[address.lower()] = name
    return symbols


def classify_line(stripped: str) -> str:
    if stripped.startswith("extern "):
        return "extern"
    if stripped.startswith("*") or stripped.startswith("//") or stripped.startswith("Function:"):
        return "comment"
    if re.search(r"\b(?:void|int|uint|undefined\d*|double|float|char|bool)\s+FUN_[0-9A-Fa-f]{8}\b", stripped):
        return "definition"
    return "live"


def iter_refs(root: Path, symbols: dict[str, str], include_autos: bool, skip: set[str]):
    for path in root.rglob("*.c"):
        rel = path.as_posix()
        if not include_autos and "unknown/autos" in rel:
            continue
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            if "FUN_" not in line:
                continue
            stripped = line.strip()
            kind = classify_line(stripped)
            if kind == "comment":
                continue
            for match in FUN_RE.finditer(line):
                address = match.group(1).lower()
                name = symbols.get(address)
                if name is None or address in skip or re.search(rf"\b{re.escape(name)}\b", text):
                    continue
                yield kind, name, f"FUN_{address}", path, lineno, stripped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"))
    parser.add_argument("--root", type=Path, default=Path("src/main"))
    parser.add_argument(
        "--kind",
        choices=("all", "extern", "definition", "live"),
        default="all",
        help="filter by reference kind",
    )
    parser.add_argument("--include-autos", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="maximum rows to print; 0 means unlimited")
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="extra lowercase hex address or FUN_ address to suppress; repeatable",
    )
    args = parser.parse_args()

    symbols = load_symbols(args.symbols)
    skip = set(DEFAULT_SKIP)
    skip.update(item.lower().removeprefix("fun_") for item in args.skip)

    count = 0
    for kind, name, fun, path, lineno, line in iter_refs(args.root, symbols, args.include_autos, skip):
        if args.kind != "all" and kind != args.kind:
            continue
        print(f"{kind:10} {name:32} {fun} {path}:{lineno}: {line[:180]}")
        count += 1
        if args.limit and count >= args.limit:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
