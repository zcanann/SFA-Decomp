#!/usr/bin/env python3
"""Audit regional resource identities against the retail registry's slot pointers.

This is read-only evidence for symbol/split review, not an automatic ownership
projection. A following registry pointer bounds a comparison, not a whole TU.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from version_progress import (
    load_splits,
    parse_function_symbols,
    parse_symbol_spans,
    read_dol_range,
    unique_function_matches,
    verified_dol,
)


def load_version(version: str):
    root = Path("config") / version
    dol = verified_dol(Path("orig") / version / "sys/main.dol", root / "config.yml")
    text = (root / "symbols.txt").read_text()
    spans = parse_symbol_spans(text)
    symbols = {s.name: s for entries in spans.values() for s in entries}
    registry = symbols["gResourceDescriptors"]
    if registry.section != "data" or registry.size % 4:
        raise ValueError("Resource registry must be a word-aligned .data symbol")
    pointers = struct.unpack(
        f">{registry.size // 4}I", read_dol_range(dol, registry.start, registry.size)
    )
    _, splits = load_splits(root / "splits.txt")
    return dol, text, symbols, pointers, splits


def audit(source_version: str, target_version: str) -> list[dict]:
    source, source_text, source_symbols, source_ptrs, source_splits = load_version(source_version)
    target, target_text, target_symbols, target_ptrs, target_splits = load_version(target_version)
    if len(source_ptrs) != len(target_ptrs):
        raise ValueError("Registry lengths differ; slot correspondence requires a new audit")
    functions = unique_function_matches(
        source, parse_function_symbols(source_text), target, parse_function_symbols(target_text)
    )
    source_at = {s.start: s for s in source_symbols.values() if s.section not in {"text", "init", "bss", "sbss", "sbss2"}}
    target_at = {s.start: s for s in target_symbols.values() if s.section not in {"text", "init", "bss", "sbss", "sbss2"}}
    target_addresses = sorted(set(target_ptrs) - {0})
    rows = []
    for slot, (source_address, target_address) in enumerate(zip(source_ptrs, target_ptrs)):
        if not source_address and not target_address:
            continue
        symbol = source_at.get(source_address)
        expected = target_symbols.get(symbol.name) if symbol else None
        current = target_at.get(target_address)
        row = {
            "slot": slot,
            "source_address": f"0x{source_address:08X}",
            "target_address": f"0x{target_address:08X}",
            "source_symbol": symbol.name if symbol else None,
            "configured_target_address": f"0x{expected.start:08X}" if expected else None,
            "target_symbol_at_pointer": current.name if current else None,
            "source_size": symbol.size if symbol else None,
            "target_configured_size": expected.size if expected else None,
            "source_owners": [s.unit for s in source_splits if s.section not in {"text", "init", "bss", "sbss", "sbss2"}
                              and s.start <= source_address < s.end],
            "target_owners_at_pointer": [s.unit for s in target_splits if s.section not in {"text", "init", "bss", "sbss", "sbss2"}
                                         and s.start <= target_address < s.end],
            "identity_mismatch": expected is None or expected.start != target_address,
        }
        if symbol and target_address:
            # Never read through the next registered object just to fit an EN size.
            index = bisect.bisect_right(target_addresses, target_address)
            available = (target_addresses[index] - target_address
                         if index < len(target_addresses) else symbol.size)
            size = min(symbol.size, available)
            row["source_extent_crosses_next_target_entry"] = available < symbol.size
            row["compared_bytes"] = size
            if size % 4:
                raise ValueError(f"Slot {slot} has a non-word-aligned comparison extent")
            a = struct.unpack(f">{size // 4}I", read_dol_range(source, source_address, size))
            b = struct.unpack(f">{size // 4}I", read_dol_range(target, target_address, size))
            unmatched = []
            callbacks = 0
            for offset, (left, right) in enumerate(zip(a, b)):
                function = functions.get(left)
                if function is not None and function.address == right:
                    callbacks += 1
                elif left != right:
                    unmatched.append({"offset": offset * 4, "source": f"0x{left:08X}",
                                      "target": f"0x{right:08X}"})
            row["verified_function_pointers"] = callbacks
            row["unresolved_words"] = unmatched
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--source", default="GSAE01")
    parser.add_argument("--slots", help="Comma-separated decimal registry slots")
    parser.add_argument("--all", action="store_true", help="Include entries without detected discrepancies")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        selected = {int(s) for s in args.slots.split(",")} if args.slots else None
        rows = audit(args.source, args.target)
    except (ValueError, KeyError, OSError) as error:
        parser.error(str(error))
    rows = [r for r in rows if (selected is None or r["slot"] in selected)
            and (args.all or selected is not None or r["identity_mismatch"]
                 or r.get("source_extent_crosses_next_target_entry") or r.get("unresolved_words"))]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['slot']:3}: {row['source_symbol']} -> {row['target_address']} "
                  f"(configured {row['configured_target_address']}); "
                  f"callbacks={row.get('verified_function_pointers', 0)}, "
                  f"unresolved={len(row.get('unresolved_words', []))}, "
                  f"extent crosses next entry={row.get('source_extent_crosses_next_target_entry', False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
