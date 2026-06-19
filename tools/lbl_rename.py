#!/usr/bin/env python3
"""Apply lbl_ -> semantic-name renames across symbols.txt and src/.

Usage:
  lbl_rename.py apply mapping.json      # apply renames (mapping: {old: new})
  lbl_rename.py check mapping.json      # validate only (collisions / missing)

A rename is safe for match% because dtk re-extracts the target object from
symbols.txt on the next build, so both sides of the objdiff get renamed.
Word-boundary substitution keeps `lbl_ABCD` from clobbering `lbl_ABCDEF`.

SJIS-bearing source files are read/written as bytes to avoid corruption.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYMS = ROOT / "config/GSAE01/symbols.txt"
SRC = ROOT / "src"

NAME_RE = re.compile(r"^[A-Za-z_]\w*$")


def existing_symbol_names() -> set[str]:
    names = set()
    for line in SYMS.read_text().splitlines():
        m = re.match(r"^(\S+)\s*=\s*", line)
        if m:
            names.add(m.group(1))
    return names


def validate(mapping: dict[str, str]) -> list[str]:
    errs = []
    existing = existing_symbol_names()
    seen_new = {}
    for old, new in mapping.items():
        if not NAME_RE.match(new):
            errs.append(f"invalid name: {new}")
        if old == new:
            errs.append(f"no-op rename: {old}")
        if new in existing and new not in mapping:
            errs.append(f"collision with existing symbol: {new}")
        if new in seen_new:
            errs.append(f"duplicate target name {new} (from {old} and {seen_new[new]})")
        seen_new[new] = old
        if old not in existing:
            errs.append(f"old symbol not in symbols.txt: {old}")
    return errs


def apply(mapping: dict[str, str]) -> dict:
    # Build one combined regex of all olds for a single pass per file.
    olds = sorted(mapping, key=len, reverse=True)
    pat = re.compile(r"\b(" + "|".join(re.escape(o) for o in olds) + r")\b")
    repl = lambda m: mapping[m.group(1)]

    stats = {"symbols": 0, "files": 0, "refs": 0}

    # symbols.txt
    data = SYMS.read_bytes()
    text = data.decode("utf-8")
    new_text, n = pat.subn(repl, text)
    if n:
        SYMS.write_bytes(new_text.encode("utf-8"))
        stats["symbols"] = n

    # source tree (bytes for SJIS safety)
    for f in list(SRC.rglob("*.c")) + list(SRC.rglob("*.h")):
        raw = f.read_bytes()
        try:
            txt = raw.decode("utf-8")
            enc = "utf-8"
        except UnicodeDecodeError:
            txt = raw.decode("latin-1")
            enc = "latin-1"
        new_txt, n = pat.subn(repl, txt)
        if n:
            f.write_bytes(new_txt.encode(enc))
            stats["files"] += 1
            stats["refs"] += n
    return stats


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("apply", "check"):
        print(__doc__)
        sys.exit(2)
    mapping = json.loads(Path(sys.argv[2]).read_text())
    errs = validate(mapping)
    if errs:
        print("VALIDATION ERRORS:")
        for e in errs:
            print("  " + e)
        sys.exit(1)
    if sys.argv[1] == "check":
        print(f"OK: {len(mapping)} renames valid")
        return
    stats = apply(mapping)
    print(f"applied {len(mapping)} renames: {stats}")


if __name__ == "__main__":
    main()
