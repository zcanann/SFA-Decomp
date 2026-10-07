#!/usr/bin/env python3
"""Audit variable-width joint bindings in a retail OBJECTS.bin (read-only)."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from tools.orig.dll_catalog import load_object_offsets


def audit(version: str, include_records: bool = False) -> dict:
    files = ROOT / "orig" / version / "files"
    data = (files / "OBJECTS.bin").read_bytes()
    offsets = load_object_offsets(files / "OBJECTS.tab")
    records, duplicates, errors = [], [], []
    model_counts, tags = Counter(), Counter()
    missing = 0
    for definition, (start, end) in enumerate(zip(offsets, offsets[1:])):
        if not 0 <= start <= end <= len(data) or end - start < 0x9C:
            errors.append({"definition": definition, "error": "invalid object extent"})
            continue
        models, count = data[start + 0x55], data[start + 0x5A]
        if count == 0:
            continue
        relative = struct.unpack_from(">I", data, start + 0x10)[0]
        if relative < 0x9C or relative + count * (models + 1) > end - start or models > 127:
            errors.append({"definition": definition, "error": "binding span exceeds object or invalid model count"})
            continue
        name = data[start + 0x91:start + 0x9C].split(b"\0")[0].decode("ascii", "replace")
        rows = [list(data[start + relative + row * (models + 1):
                          start + relative + (row + 1) * (models + 1)]) for row in range(count)]
        seen = Counter(row[0] for row in rows)
        if any(n > 1 for n in seen.values()):
            duplicates.append({"definition": definition, "name": name,
                               "tags": {tag: n for tag, n in seen.items() if n > 1}})
        model_counts[models] += 1
        tags.update(row[0] for row in rows)
        missing += sum(row[1:].count(255) for row in rows)
        records.append({"definition": definition, "name": name, "model_count": models,
                        "binding_count": count, "offset": relative, "rows": rows})
    result = {
        "version": version,
        "objects_sha256": hashlib.sha256(data).hexdigest(),
        "offsets_sha256": hashlib.sha256((files / "OBJECTS.tab").read_bytes()).hexdigest(),
        "definitions": len(offsets) - 1,
        "definitions_with_bindings": len(records),
        "binding_records": sum(record["binding_count"] for record in records),
        "model_counts": dict(sorted(model_counts.items())),
        "tags": dict(sorted(tags.items())),
        "missing_model_joints": missing,
        "duplicate_tags": duplicates,
        "errors": errors,
    }
    if include_records:
        result["records"] = records
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", default="GSAE01")
    parser.add_argument("--include-records", action="store_true")
    args = parser.parse_args()
    try:
        result = audit(args.version, args.include_records)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))
    return bool(result["errors"])


if __name__ == "__main__":
    raise SystemExit(main())
