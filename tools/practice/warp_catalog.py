"""Derive practice destinations from the verified EN disc, without extracting assets.

WARPTAB entries are grouped using the same occupied-cell / ascending-map-ID
lookup as mapCoordsToId. Maps without one get a clearly marked, unverified
placed-object position, never an invented 'retail spawn'. Object-only maps and
unplaced maps remain listed but cannot be warped to as standalone destinations.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import zlib

from build import ROOT, read_iso, sections, symbols, u32


def read_assets(iso, extra_names=()):
    dol, _ = read_iso(iso)
    assets = {}
    with iso.open("rb") as stream:
        header = stream.read(0x440)
        stream.seek(u32(header, 0x424))
        fst = stream.read(u32(header, 0x428))
        count = u32(fst, 8)
        for i in range(1, count):
            name, offset, size = struct.unpack_from(">III", fst, i * 12)
            if name >> 24:
                continue
            start = count * 12 + (name & 0xffffff)
            name = fst[start:fst.index(0, start)].decode("ascii")
            if (name in ("MAPINFO.bin", "MAPS.bin", "MAPS.tab", "globalma.bin", "WARPTAB.bin")
                    or name in extra_names or name.endswith(".romlist.zlb")):
                stream.seek(offset)
                assets[name] = stream.read(size)
    return dol, assets


def catalog(iso):
    dol, assets = read_assets(iso)

    def dol_offset(address):
        return next(off + address - base for _, off, base, size in sections(dol) if base <= address < base + size)

    records = assets["MAPINFO.bin"]
    assert len(records) == 117 * 32 and len(assets["WARPTAB.bin"]) == 128 * 16
    names_offset = dol_offset(symbols()["sMapFileNameTable"][0])
    maps, grids = [], {}
    for mid in range(117):
        name = records[mid * 32:mid * 32 + 28].split(b"\0")[0].decode("ascii")
        kind = records[mid * 32 + 28]
        category = (7 if kind == 1 else 6 if name.startswith("ZNot Used") or mid in (1, 5, 9, 26, 63)
                    else 2 if mid in (31, 32, 33, 34, 39) else 3 if mid in (28, 40, 44, 48)
                    else 4 if name.startswith("Link") else 5 if kind == 4 else 1)
        ptr = dol_offset(u32(dol, names_offset + mid * 4))
        romlist = dol[ptr:dol.index(0, ptr)].decode("ascii")
        maps.append(dict(id=mid, name=name, category=category, romlist=romlist, spawns=[]))
    for offset in range(0, len(assets["globalma.bin"]), 12):
        gx, gz, layer, mid, _, _ = struct.unpack_from(">6h", assets["globalma.bin"], offset)
        if mid < 0:
            break
        info, cells = struct.unpack_from(">2I", assets["MAPS.tab"], mid * 28)
        sx, sz, ox, oz = struct.unpack_from(">4h", assets["MAPS.bin"], info)
        assert 0 < sx * sz <= 4096
        occupied = [((u32(assets["MAPS.bin"], cells + n * 4) >> 23) & 255) != 255 for n in range(sx * sz)]
        grids[mid] = (gx - ox, gz - oz, sx, sz, layer, occupied, gx, gz)

    def resolve(x, z, layer):
        x, z = math.floor(x / 640), math.floor(z / 640)
        for mid, (left, top, sx, sz, ml, cells, _, _) in sorted(grids.items()):
            if ml == layer and 0 <= x - left < sx and 0 <= z - top < sz and cells[(z - top) * sx + x - left]:
                return mid
        return -1

    for idx in range(128):
        x, y, z, layer, angle = struct.unpack_from(">3f2h", assets["WARPTAB.bin"], idx * 16)
        mid = resolve(x, z, layer)
        if mid >= 0 and (x or y or z):
            maps[mid]["spawns"].append(dict(x=x, y=y, z=z, layer=layer, angle=angle & 255, warp=idx))

    for mid, grid in grids.items():
        if maps[mid]["spawns"]:
            continue
        left, top, sx, sz, layer, cells, gx, gz = grid
        packed = assets[maps[mid]["romlist"] + ".romlist.zlb"]
        assert packed[:4] == b"ZLB\0"
        data = zlib.decompress(packed[16:16 + u32(packed, 12)])
        assert len(data) == u32(packed, 8)
        offset, candidates = 0, []
        while offset < len(data):
            size = data[offset + 2] * 4
            assert size >= 24 and offset + size <= len(data)
            x, y, z = struct.unpack_from(">3f", data, offset + 8)
            x, z = x + gx * 640, z + gz * 640
            if all(math.isfinite(v) for v in (x, y, z)) and resolve(x, z, layer) == mid:
                # Pick a central placed object, and lift above its placement.
                # This is a starting point for manual adjustment, not a floor probe.
                distance = (x - (left + sx / 2) * 640) ** 2 + (z - (top + sz / 2) * 640) ** 2
                candidates.append((distance, x, y + 50, z))
            offset += size
        if candidates:
            _, x, y, z = min(candidates)
            maps[mid]["spawns"].append(dict(x=x, y=y, z=z, layer=layer, angle=0, warp=-1))
        else:
            # Empty legacy maps: choose an occupied cell; Y must be adjusted.
            valid = [(n, left + n % sx, top + n // sx) for n, cell in enumerate(cells) if cell]
            for _, x, z in valid:
                x, z = x * 640 + 320, z * 640 + 320
                if resolve(x, z, layer) == mid:
                    maps[mid]["spawns"].append(dict(x=x, y=0, z=z, layer=layer, angle=0, warp=-2))
                    break
    # User-provided DIM Bottom arrival, replacing the estimated object position.
    # Keep its verified world-map layer and custom-arrival semantics.
    destination = maps[27]["spawns"][0]
    assert destination["warp"] == -1 and destination["layer"] == -2
    destination.update(x=-8974.73438, y=-1627.60266, z=17620.2559)
    assert resolve(destination["x"], destination["z"], destination["layer"]) == 27
    # Curated Cape Claw arrivals, in menu order. Preserve the original shrine's
    # arrival ID/facing while lowering it beneath the destructible rock.
    shrine = maps[29]["spawns"][0]
    assert len(maps[29]["spawns"]) == 1 and shrine["warp"] == 53
    shrine.update(name="Mana Shrine", y=-1668)
    def cape_spawn(name, x, y, z):
        return dict(name=name, x=x, y=y, z=z, layer=shrine["layer"], angle=0, warp=-1)
    maps[29]["spawns"] = [
        cape_spawn("Entrance", 1413.41162, -1206.3031, -4200.09863),
        cape_spawn("Link Door", 2872.06055, -1401.93994, -4406.44971),
        shrine,
        cape_spawn("Gas Chamber", 3754.10693, -1464.93994, -3452.88184),
        cape_spawn("Cannon", 3299.2041, -1579.93994, -2635.34961),
    ]
    for destination in maps[29]["spawns"]:
        assert resolve(destination["x"], destination["z"], destination["layer"]) == 29
    return maps, {name: hashlib.sha256(data).hexdigest() for name, data in assets.items() if not name.endswith(".romlist.zlb")}


def generate(iso, output):
    maps, hashes = catalog(iso)
    lines = ["/* Generated by tools/practice/warp_catalog.py from verified EN v1.0 assets.",
             " * Categories, friendly names, curated positions and fallbacks are practice policy. */",
             "#ifndef PRACTICE_WARP_CATALOG_H", "#define PRACTICE_WARP_CATALOG_H", "#ifdef SFA_PRACTICE",
             '#include "main/rcp_dolphin_api.h"',
             "typedef struct PracticeWarpSpawn { WarpDestination destination; s16 warp; const char* name; } PracticeWarpSpawn;",
             "typedef struct PracticeWarpMap { const char* name; u16 firstSpawn; u8 spawnCount; u8 category; } PracticeWarpMap;",
             "static const PracticeWarpSpawn practiceWarpSpawns[] = {"]
    first = 0
    for record in maps:
        record["first"] = first
        for p in record["spawns"]:
            xyz = ", ".join(f"{p[k]:.9f}f" for k in ("x", "y", "z"))
            name = json.dumps(p["name"].upper()) if p.get("name") else "NULL"
            lines.append(f'    {{{{{xyz}, {p["layer"]}, {p["angle"]}}}, {p["warp"]}, {name}}},')
            first += 1
    lines += ["};", "static const PracticeWarpMap practiceWarpMaps[] = {"]
    for m in maps:
        lines.append(f'    {{{json.dumps(m["name"].upper())}, {m["first"]}, {len(m["spawns"])}, {m["category"]}}}, /* {m["id"]} */')
    lines += ["};", "#endif", "#endif", ""]
    output.write_text("\n".join(lines))
    report = dict(maps=maps, asset_sha256=hashes)
    (ROOT / "build/practice/warp-catalog.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {len(maps)} maps, {first} destinations, {sum(bool(m['spawns']) for m in maps)} warpable maps")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "include/practice/warp_catalog.h")
    args = parser.parse_args()
    generate(args.iso, args.output)
