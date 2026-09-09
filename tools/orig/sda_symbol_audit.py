#!/usr/bin/env python3
"""Audit regional small-data identities using retail r13-relative instructions.

Names, zero-filled bytes and objdiff's normalized relocations are not address
evidence. Globally unique functions and identical sequences between two unique
functions supply the operand pairs. Conflicts remain visible instead of voting.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from version_progress import (
    load_splits, retail_sda_base, sda_reference_pairs as reference_pairs,
    parse_function_symbols, parse_symbol_spans, projected_symbol_name,
    read_dol_range, verified_dol,
)


def load_version(version):
    root = Path("config") / version
    dol = verified_dol(Path("orig") / version / "sys/main.dol", root / "config.yml")
    text = (root / "symbols.txt").read_text()
    _, splits = load_splits(root / "splits.txt")
    return dol, parse_function_symbols(text), parse_symbol_spans(text), splits


def audit(source_version, target_version):
    source, source_functions, source_spans, source_splits = load_version(source_version)
    target, target_functions, target_spans, target_splits = load_version(target_version)
    refs = reference_pairs(source, source_functions, target, target_functions)
    target_names = defaultdict(list)
    for section in ("sdata", "sbss"):
        for span in target_spans.get(section, ()):
            target_names[span.name].append(span)
    rows = []
    for section in ("sdata", "sbss"):
        for span in source_spans.get(section, ()):
            targets = refs.get(span.start, {})
            owners = [s.unit for s in source_splits
                      if s.section == section and s.start <= span.start < s.end]
            configured = [s for s in target_names.get(span.name, []) if s.section == section]
            if not configured and len(targets) == 1:
                configured = [s for s in target_names.get(
                    projected_symbol_name(span.name, next(iter(targets))), []) if s.section == section]
            if len(configured) > 1 and owners:
                configured = [candidate for candidate in configured if any(
                    s.unit in owners and s.section == section and s.start <= candidate.start < s.end
                    for s in target_splits)]
            address = configured[0].start if len(configured) == 1 else None
            status = ("unanchored" if not targets else "conflicting" if len(targets) != 1
                      else "exact" if address == next(iter(targets)) else "mismapped")
            rows.append({
                "section": section, "symbol": span.name, "source_address": span.start,
                "source_size": span.size, "configured_target_address": address,
                "owners": owners,
                "status": status,
                "targets": [{"address": a, "references": witnesses}
                            for a, witnesses in sorted(targets.items())],
            })
            if section == "sdata" and len(targets) == 1:
                try:
                    rows[-1]["initialized_bytes_equal"] = (
                        read_dol_range(source, span.start, span.size)
                        == read_dol_range(target, next(iter(targets)), span.size)
                    )
                except ValueError:
                    # A move into zero storage is an identity/layout question,
                    # not permission to read unrelated file bytes as its value.
                    rows[-1]["initialized_bytes_equal"] = None
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--source", default="GSAE01")
    parser.add_argument("--section", choices=("sdata", "sbss"))
    parser.add_argument("--unit", action="append", help="Limit to an EN source path; repeatable")
    parser.add_argument("--all", action="store_true", help="Include exact and unanchored symbols")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        rows = audit(args.source, args.target)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    if args.unit:
        rows = [r for r in rows if set(args.unit).intersection(r["owners"])]
    if args.section:
        rows = [r for r in rows if r["section"] == args.section]
    counts = Counter(r["status"] for r in rows)
    print(", ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)
    if not args.all:
        rows = [r for r in rows if r["status"] in {"mismapped", "conflicting"}]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            target = row["configured_target_address"]
            configured = f"0x{target:08X}" if target is not None else "absent"
            actual = ", ".join(f"0x{t['address']:08X} ({len(t['references'])} refs)" for t in row["targets"])
            initializer = (f"; raw initialized bytes equal={row['initialized_bytes_equal']}"
                           if "initialized_bytes_equal" in row else "")
            print(f"{row['symbol']}: {row['status']}; configured={configured}; retail={actual}{initializer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
