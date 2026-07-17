#!/usr/bin/env python3
"""Inventory manually placed data and rank candidates for natural recovery.

Section attributes are sometimes useful while an object boundary is unknown,
but they hide whether a definition has the right ownership and qualifiers.
This report keeps those bridges visible and shows whether each object appears
to be written, which is the first useful distinction when replacing a forced
small-data or read-only-data placement with plausible source.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = {".c", ".cc", ".cp", ".cpp", ".h", ".hpp"}
DECLARATION = re.compile(
    r'__declspec\s*\(\s*section\s+"(?P<section>[^"]+)"\s*\)'
    r"(?P<tail>[^;{}]*?\b(?P<symbol>[A-Za-z_]\w*)\s*(?:\[[^;]*?\])?\s*=)",
    re.DOTALL,
)


@dataclass(frozen=True)
class Override:
    path: Path
    line: int
    section: str
    symbol: str
    declaration: str


def source_files(include_sdk: bool) -> list[Path]:
    files = []
    for path in (ROOT / "src").rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if not include_sdk and (
            relative.startswith("src/dolphin/")
            or relative.startswith("src/Runtime.PPCEABI.H/")
        ):
            continue
        files.append(path)
    return sorted(files)


def find_overrides(files: list[Path]) -> list[Override]:
    overrides = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in DECLARATION.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            declaration = " ".join(match.group(0).split())
            overrides.append(
                Override(
                    path.relative_to(ROOT),
                    line,
                    match.group("section"),
                    match.group("symbol"),
                    declaration,
                )
            )
    return overrides


def usage_index(texts: dict[Path, str]) -> tuple[Counter[str], Counter[str]]:
    references: Counter[str] = Counter()
    writes: Counter[str] = Counter()
    token = re.compile(r"\b[A-Za-z_]\w*\b")
    assignment = re.compile(
        r"\b(?P<symbol>[A-Za-z_]\w*)\b\s*(?:\[[^\]]*\]\s*)?"
        r"(?:\+\+|--|[+\-*/%&|^]?=(?!=))"
    )
    prefix_update = re.compile(r"(?:\+\+|--)\s*\b(?P<symbol>[A-Za-z_]\w*)\b")
    for text in texts.values():
        references.update(token.findall(text))
        writes.update(match.group("symbol") for match in assignment.finditer(text))
        writes.update(match.group("symbol") for match in prefix_update.finditer(text))
    return references, writes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--section", help="only show one section, such as .rodata")
    parser.add_argument("--include-sdk", action="store_true")
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="only show objects with no apparent post-initialization writes",
    )
    args = parser.parse_args()

    files = source_files(args.include_sdk)
    texts = {
        path: path.read_text(encoding="utf-8", errors="replace") for path in files
    }
    references_by_symbol, writes_by_symbol = usage_index(texts)
    rows = []
    for override in find_overrides(files):
        if args.section and override.section != args.section:
            continue
        references = max(0, references_by_symbol[override.symbol] - 1)
        writes = max(0, writes_by_symbol[override.symbol] - 1)
        if args.read_only and writes:
            continue
        rows.append((writes, override.section, override.path.as_posix(), override, references))

    rows.sort(key=lambda row: (row[0], row[1], row[2], row[3].line))
    for writes, _, _, override, references in rows:
        state = "no-writes" if writes == 0 else f"writes={writes}"
        print(
            f"{override.path.as_posix()}:{override.line}: "
            f"{override.section:8} {override.symbol:40} "
            f"refs={references:<4} {state}"
        )


if __name__ == "__main__":
    main()
