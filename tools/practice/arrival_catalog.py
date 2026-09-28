"""Build conservative, map-wide object-group defaults from audited EN entry paths.

Only the listed boundary planes without game-bit gates are accepted. This is not a nearest-
trigger heuristic: interior rooms, toggles, story bits and map acts are excluded.
Positive entry requirements are merged; unspecified groups keep their saved state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

from build import ROOT, sections, symbols, u32
from warp_catalog import read_assets


# destination map, source romlist, placement index (zero based), crossing leg,
# expected enabled groups. Expectations make asset/index drift fail closed.
BOUNDARIES = [
    (4, "linkf", 171, 1, (1, 2)),
    (7, "linke", 82, -1, (4,)),
    (10, "linkb", 107, 1, (0,)),  # LinkB shares Snowhorn's group bank.
    (14, "linkg", 52, 1, (1,)),
    (16, "fortress", 222, -1, (10, 11, 12)),
    (18, "linke", 58, 1, (0,)),
    (18, "linkf", 32, -1, (25,)),
    (27, "snowmines2", 11, 1, (0,)),
    (29, "capeclaw", 479, 1, (1, 4)),
    (43, "linki", 19, 1, (0, 1, 2, 10)),
    (50, "linkj", 25, 1, (20,)),
    (56, "linkb", 107, 1, (0,)),
    (68, "snowmines", 459, 1, (1,)),
    (70, "linkf", 32, -1, (30,)),
    (70, "linkf", 57, 1, (31,)),
    (71, "linkg", 1, 1, (3,)),
    (71, "linkg", 2, 1, (13,)),
    (71, "linkg", 6, 1, (0, 5, 10)),
    (71, "linkg", 65, 1, (31,)),
    (72, "linkh", 26, 1, (1, 31)),
    (72, "linkh", 135, 1, (3,)),
    (74, "linki", 20, -1, (0,)),
]

# Positive requirements from retail setup code; intentionally omit its story
# changes and whole-bank clears, which would reset existing progress.
SETUP = [
    (7, (0, 2, 3, 5, 10), "gplayNewGame: initial Thorntail groups"),
    (29, (0, 31), "gplayNewGame: initial Cape Claw groups"),
    (19, (0, 22), "ARWArwing sequence event 5, course map 59: DIM landing"),
    (12, (0,), "ARWArwing sequence event 5, course map 60: Fortress landing"),
    (13, (0, 1, 5, 10, 11), "ARWArwing sequence event 5, course map 61: City landing"),
    (2, (15, 16), "ARWArwing sequence event 5, course map 62: Dragon Rock landing"),
]


def generate(iso, output, report):
    dol, assets = read_assets(iso, ("OBJECTS.tab", "OBJECTS.bin", "OBJINDEX.bin"))
    address = symbols()["gSaveGameMapObjGroupBits"][0]
    offset = next(off + address - base for _, off, base, size in sections(dol)
                  if base <= address and address + 240 <= base + size)
    banks = struct.unpack_from(">120H", dol, offset)
    assert all(banks[mid] == 0 for mid in (38, 58, 59, 60, 61, 62))  # Flight maps have no group bank.
    names = [assets["MAPINFO.bin"][i * 32:i * 32 + 28].split(b"\0")[0].decode("ascii")
             for i in range(117)]
    romlist_maps = {}
    address = symbols()["sMapFileNameTable"][0]
    offset = next(off + address - base for _, off, base, size in sections(dol)
                  if base <= address < base + size)
    for mid in range(117):
        ptr = u32(dol, offset + mid * 4)
        at = next(off + ptr - base for _, off, base, size in sections(dol) if base <= ptr < base + size)
        romlist_maps[dol[at:dol.index(0, at)].decode("ascii")] = mid
    records = {}
    for romlist in {entry[1] for entry in BOUNDARIES}:
        packed = assets[romlist + ".romlist.zlb"]
        assert packed[:8] == b"ZLB\0\0\0\0\1"
        data = zlib.decompress(packed[16:16 + u32(packed, 12)])
        assert len(data) == u32(packed, 8)
        pos, records[romlist] = 0, []
        while pos < len(data):
            size = data[pos + 2] * 4
            assert size >= 24 and pos + size <= len(data)
            records[romlist].append(data[pos:pos + size])
            pos += size

    masks, evidence = {}, []
    for mid, romlist, index, leg, expected in BOUNDARIES:
        record = records[romlist][index]
        oid = struct.unpack_from(">h", record)[0]
        assert oid >= 0
        canonical = struct.unpack_from(">h", assets["OBJINDEX.bin"], oid * 2)[0]
        assert canonical >= 0
        objoff = u32(assets["OBJECTS.tab"], canonical * 4)
        assert assets["OBJECTS.bin"][objoff + 0x91:objoff + 0x98] == b"TrigPln"
        assert len(record) >= 0x50 and record[0x43] == 0  # Player-target plane.
        assert record[0x48:0x50] == b"\xff" * 8  # No progress-dependent gate.
        groups, commands = set(), []
        for at in range(0x18, 0x38, 4):
            condition, opcode, p1, p2 = record[at:at + 4]
            if not condition & (1 if leg > 0 else 2):
                continue
            if opcode == 0x13:
                target, group = romlist_maps[romlist], (p1 << 8) | p2
            elif opcode == 0x1a:
                target, group = p2, p1
            else:
                continue
            if banks[mid] and banks[target] == banks[mid]:
                assert group < 32
                groups.add(group)
                commands.append(record[at:at + 4].hex())
        assert groups == set(expected), (mid, romlist, index, groups, expected)
        masks[mid] = masks.get(mid, 0) | sum(1 << bit for bit in groups)
        evidence.append(dict(map=mid, source=f"{romlist}#{index}", leg=leg,
                             groups=sorted(groups), commands=commands,
                             excluded_act_bytes=[record[3], record[5]],
                             resident_group=record[6] if record[4] & 0x10 else None,
                             romlist_sha256=hashlib.sha256(assets[romlist + ".romlist.zlb"]).hexdigest()))
    for mid, groups, source in SETUP:
        assert banks[mid]
        masks[mid] = masks.get(mid, 0) | sum(1 << bit for bit in groups)
        evidence.append(dict(map=mid, source=source, groups=list(groups)))

    lines = ["/* Generated by tools/practice/arrival_catalog.py; see docs/practice_arrival_groups.md. */",
             "#ifndef PRACTICE_ARRIVAL_CATALOG_H", "#define PRACTICE_ARRIVAL_CATALOG_H", "#ifdef SFA_PRACTICE",
             '#include "global.h"',
             "typedef struct PracticeArrivalGroups { int map; u32 enable; } PracticeArrivalGroups;",
             "static const PracticeArrivalGroups practiceArrivalGroups[] = {"]
    lines += [f"    {{{mid}, 0x{mask:08X}u}}, /* {names[mid]} */" for mid, mask in sorted(masks.items())]
    lines += ["};", "#endif", "#endif", ""]
    output.write_text("\n".join(lines))
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(dict(defaults=[dict(map=mid, name=names[mid], enable=f"{mask:08X}")
                                               for mid, mask in sorted(masks.items())], evidence=evidence), indent=2) + "\n")
    print(f"Generated {len(masks)} map arrival defaults; {len(BOUNDARIES)} verified boundary legs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "include/practice/arrival_catalog.h")
    parser.add_argument("--report", type=Path, default=ROOT / "build/practice/arrival-catalog.json")
    args = parser.parse_args()
    generate(args.iso, args.output, args.report)
