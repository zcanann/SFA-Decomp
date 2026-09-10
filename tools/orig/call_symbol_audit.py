#!/usr/bin/env python3
"""Find regional function identities from independently matched direct callers.

Read-only evidence: names never establish caller correspondence. Candidates need
two distinct globally unique callers, consistent destinations in both directions,
known function boundaries, and equal normalized callee bodies. Inspect the retail
operands and containing TU before applying a name or claiming a source match.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from orig.sda_symbol_audit import load_version
from version_progress import CODE_SECTIONS, function_signature, read_dol_range


def call_destination(word, address):
    if word >> 26 != 18 or not word & 1:
        return None
    displacement = word & 0x03FFFFFC
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return (displacement if word & 2 else address + displacement) & 0xFFFFFFFF


def call_candidates(source, source_functions, target, target_functions):
    signatures = []
    by_address = []
    for dol, functions in ((source, source_functions), (target, target_functions)):
        groups = defaultdict(list)
        addresses = {}
        for function in functions:
            if function.section not in CODE_SECTIONS:
                continue
            signature = (function.section, function_signature(dol, function))
            groups[signature].append(function)
            addresses[function.address] = (function, signature)
        signatures.append(groups)
        by_address.append(addresses)
    evidence = defaultdict(lambda: defaultdict(list))
    reverse = defaultdict(set)
    for signature, functions in signatures[0].items():
        targets = signatures[1].get(signature, ())
        if len(functions) != 1 or len(targets) != 1:
            continue
        a, b = functions[0], targets[0]
        left = struct.unpack(f">{a.size // 4}I", read_dol_range(source, a.address, a.size))
        right = struct.unpack(f">{b.size // 4}I", read_dol_range(target, b.address, b.size))
        for index, (x, y) in enumerate(zip(left, right)):
            source_site, target_site = a.address + index * 4, b.address + index * 4
            source_address = call_destination(x, source_site)
            target_address = call_destination(y, target_site)
            if source_address is None or target_address is None:
                continue
            # Keep unknown/interior destinations in the conflict evidence too.
            reverse[target_address].add(source_address)
            evidence[source_address][target_address].append({
                "source_function": a.name, "target_function": b.name,
                "source_caller": a.address, "target_caller": b.address,
                "source_instruction": source_site, "target_instruction": target_site,
            })
    rows = []
    for address, targets in sorted(evidence.items()):
        if address not in by_address[0]:
            continue
        function, signature = by_address[0][address]
        destination = next(iter(targets)) if len(targets) == 1 else None
        candidate = by_address[1].get(destination)
        if len(targets) != 1:
            status = "conflicting-targets"
        elif len(reverse[destination]) != 1:
            status = "shared-target"
        elif candidate is None:
            status = "missing-target-boundary"
        elif candidate[1] != signature:
            status = "changed-callee"
        elif len({r["source_caller"] for r in targets[destination]}) < 2:
            status = "single-caller"
        else:
            status = "exact-name" if candidate[0].name == function.name else "candidate"
        rows.append({
            "source": function.name, "source_address": address, "size": function.size,
            "target": candidate[0].name if candidate else None,
            "target_address": destination, "status": status,
            "targets": [{"address": a, "references": refs} for a, refs in sorted(targets.items())],
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--source", default="GSAE01")
    parser.add_argument("--symbol", action="append", help="Limit to an EN function name; repeatable")
    parser.add_argument("--all", action="store_true", help="Include rejected and already named candidates")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        source, source_functions, *_ = load_version(args.source)
        target, target_functions, *_ = load_version(args.target)
        rows = call_candidates(source, source_functions, target, target_functions)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.symbol:
        rows = [r for r in rows if r["source"] in args.symbol]
    counts = Counter(r["status"] for r in rows)
    print(", ".join(f"{key}={value}" for key, value in sorted(counts.items())), file=sys.stderr)
    if not args.all:
        rows = [r for r in rows if r["status"] == "candidate"]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            destinations = ", ".join(f"0x{t['address']:08X} ({len(t['references'])} calls)"
                                     for t in row["targets"])
            print(f"{row['source']}: {row['status']}; retail={destinations}; name={row['target']}")


if __name__ == "__main__":
    main()
