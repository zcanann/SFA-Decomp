"""Audit EN Tricky route-link direction bits without repairing retail anomalies.

The romlist loader registers object ID 110 as RomCurveDef. Bit i at +0x1B
selects backward traversal of link i at +0x1C; Tricky's route.reverse and
RomCurve_getAdjacentWindow establish the direction. Reciprocal retail links
usually have opposite bits, but this is evidence, not a universal invariant.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import struct

try:
    from .romlist_params import decompress_zlb
except ImportError:
    from romlist_params import decompress_zlb


@dataclass(frozen=True)
class Curve:
    romlist: str
    offset: int
    size: int
    ident: int
    kind: int
    subtype: int
    backward_mask: int
    links: tuple[int, ...]


def parse_curves(data: bytes, romlist: str) -> list[Curve]:
    curves = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 0x18:
            raise ValueError(f"truncated placement header: {romlist}+0x{offset:X}")
        object_id, words = struct.unpack_from(">HB", data, offset)
        size = words * 4
        if size < 0x18 or offset + size > len(data):
            raise ValueError(f"invalid placement size: {romlist}+0x{offset:X}: {size}")
        if object_id == 110:
            if size < 0x2C:
                raise ValueError(f"truncated curve links: {romlist}+0x{offset:X}")
            ident = struct.unpack_from(">I", data, offset + 0x14)[0]
            kind, subtype, mask = struct.unpack_from(">BBB", data, offset + 0x19)
            links = struct.unpack_from(">4i", data, offset + 0x1C)
            curves.append(Curve(romlist, offset, size, ident, kind, subtype, mask, links))
        offset += size
    return curves


def collect_curves(files_root: Path) -> list[Curve]:
    paths = sorted(files_root.glob("*.romlist.zlb"))
    if not paths:
        raise ValueError(f"no romlists found in {files_root}")
    return [curve for path in paths for curve in parse_curves(decompress_zlb(path), path.name)]


def location(curve: Curve) -> dict:
    return {"romlist": curve.romlist, "offset": f"0x{curve.offset:X}", "id": f"0x{curve.ident:X}"}


def audit_links(curves: list[Curve], curve_type: int = 0x24) -> dict:
    by_id = defaultdict(list)
    for curve in curves:
        by_id[curve.ident].append(curve)
    counts = Counter()
    anomalies = []
    for source in curves:
        if source.kind != curve_type:
            continue
        counts["nodes"] += 1
        for slot, link in enumerate(source.links):
            if link < 0:
                continue
            counts["links"] += 1
            candidates = by_id.get(link, [])
            local = [curve for curve in candidates if curve.romlist == source.romlist]
            candidates = local or candidates
            detail = {"source": location(source), "slot": slot, "target_id": f"0x{link:X}",
                      "backward": bool(source.backward_mask & (1 << slot))}
            if len(candidates) != 1:
                status = "missing_target" if not candidates else "ambiguous_target"
                detail["candidates"] = [location(curve) for curve in candidates]
            else:
                target = candidates[0]
                counts["local_target" if local else "external_target"] += 1
                reverse_slots = [i for i, ident in enumerate(target.links) if ident == source.ident]
                detail["target"] = location(target)
                detail["reciprocal_slots"] = reverse_slots
                if len(reverse_slots) != 1:
                    status = "nonreciprocal" if not reverse_slots else "duplicate_reciprocal"
                else:
                    reverse_slot = reverse_slots[0]
                    target_bit = bool(target.backward_mask & (1 << reverse_slot))
                    detail["target_backward"] = target_bit
                    status = "opposite_bits" if detail["backward"] != target_bit else "same_bits"
            counts[status] += 1
            if status != "opposite_bits":
                anomalies.append({"status": status, **detail})
    return {"curve_type": f"0x{curve_type:X}", "all_curve_nodes": len(curves),
            "record_sizes": dict(sorted(Counter(curve.size for curve in curves).items())),
            "counts": dict(sorted(counts.items())), "anomalies": anomalies}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files-root", type=Path, required=True,
                        help="extracted EN GSAE01 files directory")
    parser.add_argument("--curve-type", type=lambda value: int(value, 0), default=0x24)
    args = parser.parse_args()
    print(json.dumps(audit_links(collect_curves(args.files_root), args.curve_type), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
