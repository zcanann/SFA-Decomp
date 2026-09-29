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

OVERWORLD_ORDER = (7, 8, 51, 23, 56, 10, 67, 69, 18, 70, 4, 71, 14, 72, 29, 73, 50, 21)
DUNGEON_ORDER = (19, 68, 27, 12, 16, 13, 2, 11)
BOSS_ORDER = (28, 43, 48, 44, 40)
OUTER_SPACE_ORDER = (41, 59, 60, 61, 62, 38)
SPECIAL_ORDER = (0, 65, 9, 51, 54, 66)
UNUSED_ORDER = (52, 26, 74)
LINKI_ORIGIN = 60  # Isolated practice placement, in 640-unit cells; not a retail location.
CATEGORY_NAMES = ("All Maps", "Overworld", "Dungeons", "Krazoa Shrines", "Bosses", "Outer Space",
                  "Special", "Unused", "Unused Broken", "Object Chunks")


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
    dol, assets = read_assets(iso, ("OBJECTS.tab", "OBJECTS.bin", "OBJINDEX.bin"))

    def dol_offset(address):
        return next(off + address - base for _, off, base, size in sections(dol) if base <= address < base + size)

    records = assets["MAPINFO.bin"]
    assert len(records) == 117 * 32 and len(assets["WARPTAB.bin"]) == 128 * 16
    names_offset = dol_offset(symbols()["sMapFileNameTable"][0])
    maps, grids = [], {}
    for mid in range(117):
        name = records[mid * 32:mid * 32 + 28].split(b"\0")[0].decode("ascii")
        kind = records[mid * 32 + 28]
        category = (9 if kind == 1 else 6 if mid in (0, 65, 9, 54, 66) else 7 if mid in UNUSED_ORDER
                    else 8 if name.startswith("ZNot Used") or mid in (1, 5, 22, 58, 63, 64)
                    else 2 if mid in DUNGEON_ORDER
                    else 3 if mid in (31, 32, 33, 34, 39) else 4 if mid in BOSS_ORDER
                    else 5 if mid in OUTER_SPACE_ORDER else 1)
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

    # Retail left LinkI unplaced, but preserved its blocks and object list.
    # Practice_InitMaps adds the equivalent slot in RAM without changing assets.
    assert 74 not in grids and maps[74]["romlist"] == "linki"
    info, cells = struct.unpack_from(">2I", assets["MAPS.tab"], 74 * 28)
    sx, sz, ox, oz = struct.unpack_from(">4h", assets["MAPS.bin"], info)
    assert (sx, sz, ox, oz) == (8, 7, 0, 1)
    occupied = [((u32(assets["MAPS.bin"], cells + n * 4) >> 23) & 255) != 255 for n in range(sx * sz)]
    assert sum(occupied) == 6
    left, top = LINKI_ORIGIN - ox, LINKI_ORIGIN - oz
    for x, z, w, h, layer, _, _, _ in grids.values():
        assert layer != 0 or left + sx <= x or x + w <= left or top + sz <= z or z + h <= top
    grids[74] = (left, top, sx, sz, 0, occupied, LINKI_ORIGIN, LINKI_ORIGIN)
    maps[74]["spawns"] = [dict(name="Entrance", x=LINKI_ORIGIN * 640 + 1650.5,
                              y=1228.0, z=LINKI_ORIGIN * 640 + 936.7509765625,
                              layer=0, angle=0, warp=-1, bank_map=12)]

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
    maps[0]["spawns"][0]["name"] = "Combat"
    for mid, name in zip(OUTER_SPACE_ORDER, ("Orbit (World Map)", "DarkIce Mines", "CloudRunner Fortress",
                                           "Walled City", "Dragon Rock", "Andross")):
        maps[mid]["name"] = name
    # SH_swapston sequence event 0xC enters WARPTAB 0x33: this is the retail
    # WarpStone maze, despite MAPINFO retaining the internal name MazeTest.
    assert maps[9]["romlist"] == "mazecave" and maps[9]["spawns"][0]["warp"] == 0x33
    maps[9]["name"] = "WarpStone Maze"
    maps[9]["category"] = 6
    maps[9]["spawns"][0]["name"] = "Entrance"
    dragon_rock = maps[2]["spawns"]
    assert len(dragon_rock) == 1 and dragon_rock[0]["warp"] == 121
    dragon_rock[0]["name"] = "Arwing Landing"
    for name, x, y, z in (
        ("Earth Walker Barrel", -16170.6943, -1406.93994, 13305.6621),
        ("High Top", -16116.4424, -1632.93994, 12628.3105),
        ("Post High Top", -17069.1855, -1632.93994, 9946.83105),
        ("CloudRunner", -16982.3438, -1647.93994, 8530.29395),
    ):
        destination = dict(name=name, x=x, y=y, z=z, layer=dragon_rock[0]["layer"],
                           angle=0, warp=-1, skip_dr_arrival=True)
        assert resolve(x, z, destination["layer"]) == 2
        dragon_rock.append(destination)
    # Per-arrival room requirements. Validate representative actors against the
    # disc; these are positive additions, never a reset of saved room/story state.
    room_members = {
        (2, 2): ((538, "DR_CageNoRo"), (564, "DR_CageCont")),
        (2, 12): ((628, "DR_CloudRun"),),
        (4, 3): ((510, "MagicCaveTo"), (502, "VFP_Block1")),
        (4, 6): ((587, "VFP_RoundDo"),),
        (4, 8): ((603, "VFP_lavasta"), (598, "LargeCrate")),
        (7, 7): ((817, "SH_thorntai"), (822, "DB_egg")),
        (7, 8): ((853, "MagicCaveTo"), (846, "LargeBasket")),
        (8, 25): ((35, "SH_whitemus"), (57, "fogControl")),
        (8, 31): ((153, "MagicCaveTo"), (102, "HitAnimator")),
        (10, 1): ((339, "MagicCaveTo"), (344, "GroundAnima")),
        (10, 3): ((538, "Transporter"), (537, "NW_Portcull")),
        (10, 4): ((550, "GuardClaw"),),
        (10, 5): ((588, "NW_mammothg"), (664, "NW_IcePriso")),
        (10, 7): ((722, "CmbSrcTPole"), (732, "CobwebCeili")),
        (10, 8): ((821, "CmbSrcTPole"), (829, "snowworm_ba")),
        (10, 12): ((854, "NW_mammothb"),),
        (11, 0): ((190, "CmbSrcTWall"), (182, "LargeCrate")),
        (11, 1): ((195, "WM_deaddino"), (196, "WM_deaddino")),
        (11, 3): ((227, "WM_Door1"), (231, "WM_PlanDoor"),
                  (232, "WM_deaddino"), (234, "WM_colrise")),
        (11, 5): ((367, "Transporter"), (368, "LargeCrate")),
        (11, 6): ((377, "CmbSrc"), (384, "sharpclawGr")),
        (11, 8): ((407, "FireHole"), (408, "FireHoleCon")),
        (11, 9): ((458, "Transporter"), (424, "WM_colrise")),
        (11, 10): ((470, "Landed_Arwi"), (474, "Transporter")),
        (11, 11): ((497, "WM_newcryst"), (503, "WndLiftS")),
        (12, 1): ((483, "TrigPln"), (484, "CFseqobject")),
        (12, 5): ((506, "KytesMum"), (536, "Fall_Ladder")),
        (12, 6): ((568, "CFseqobject"), (569, "GCRobotPatr")),
        (12, 7): ((580, "SC_Shrine_d"), (695, "CFLightWall")),
        (12, 8): ((714, "MagicPlant"), (715, "CFBrokenPil")),
        (12, 19): ((730, "SC_Shrine_d"), (735, "CFWindLift")),
        (12, 27): ((761, "SC_Shrine_d"), (796, "CFLightPill")),
        (13, 4): ((400, "WCTrexStatu"), (413, "WCAnimSunSt")),
        (14, 2): ((482, "SC_sequence"), (483, "SC_totembon")),
        (18, 5): ((554, "MMP_CraterF"), (557, "KaldachomMe")),
        (18, 8): ((659, "LargeBasket"), (679, "Transporter")),
        (19, 1): ((555, "DIMBridgeCo"), (561, "DIMSnowHorn")),
        (19, 3): ((615, "DIMIceWall"), (621, "DIMAlpineRo")),
        (19, 5): ((634, "DIMLever"), (637, "DIMBridgeCo")),
        (19, 6): ((644, "GroundAnima"), (645, "DIMAlpineRo")),
        (19, 7): ((663, "DIMCannon"), (665, "DIMBridgeCo")),
        (19, 8): ((676, "DIMDismount"),),
        (19, 9): ((683, "DIMGate"),),
        (19, 10): ((701, "DIMAlpineRo"), (707, "TreasureChe")),
        (19, 12): ((732, "DIMDismount"), (734, "DIMWoodDoor")),
        (19, 14): ((740, "IMSnowBike"),),
        (19, 16): ((764, "DIMWoodDoor"), (769, "DIMMagicBri")),
        (19, 18): ((795, "CannonClaw"),),
        (19, 20): ((802, "DIMHutDoor"), (803, "DIMHutDoor")),
        (19, 21): ((805, "DIMLogFire"), (814, "LargeCrate")),
        (28, 2): ((46, "DIM_BossGut"), (47, "WaveAnimato"), (54, "DIM_BossTon")),
    }
    for (mid, group), members in room_members.items():
        packed = assets[maps[mid]["romlist"] + ".romlist.zlb"]
        data = zlib.decompress(packed[16:16 + u32(packed, 12)])
        records, offset = [], 0
        while offset < len(data):
            size = data[offset + 2] * 4
            assert size >= 24 and offset + size <= len(data)
            records.append(data[offset:offset + size])
            offset += size
        for index, name in members:
            record = records[index]
            oid = struct.unpack_from(">h", record)[0]
            canonical = struct.unpack_from(">h", assets["OBJINDEX.bin"], oid * 2)[0]
            objoff = u32(assets["OBJECTS.tab"], canonical * 4)
            actual = assets["OBJECTS.bin"][objoff + 0x91:objoff + 0x9c].split(b"\0")[0].decode("ascii")
            assert actual == name, (mid, index, actual, name)
            assert record[4] & 0x10 and record[6] == group

    def room_spawn(mid, spawn, name, groups=(), bank_map=-1, act=0):
        assert all((mid, group) in room_members for group in groups)
        return dict(spawn, name=name, groups=sum(1 << group for group in groups), bank_map=bank_map, act=act)

    dragon_rock[4] = room_spawn(2, dragon_rock[4], "CloudRunner", (2, 12))
    temple = maps[4]["spawns"]
    assert [p["warp"] for p in temple] == [72, 81, 122, 123, 124]
    maps[4]["spawns"] = [
        room_spawn(4, temple[4], "Entrance"),
        room_spawn(4, temple[0], "Freeze Blast Exit", (3,)),
        room_spawn(4, temple[1], "Central Room Bot", (6, 8)),
        room_spawn(4, temple[2], "Central Room Top", (6, 8)),
        room_spawn(4, temple[3], "Spell Stone Room"),
    ]
    hollow = maps[7]["spawns"]
    assert [p["warp"] for p in hollow] == [3, 15, 52, 102, 108]
    maps[7]["spawns"] = [
        room_spawn(7, hollow[4], "Arwing"),
        room_spawn(7, hollow[0], "Egg Room", (7,)),
        room_spawn(7, hollow[1], "Warp Stone"),
        room_spawn(7, hollow[2], "Mana Shrine", (8,)),
        room_spawn(7, hollow[3], "Fire Blast"),
    ]
    maps[8]["name"] = "Thorntail Hollow - Well"
    well = maps[8]["spawns"]
    assert len(well) == 1 and well[0]["warp"] == 95
    maps[8]["spawns"] = [
        room_spawn(8, well[0], "Rocket Shrine", (31,), 8),
        room_spawn(8, dict(x=-6063.78467, y=-1378.93994, z=-1727.74219,
                          layer=-1, angle=0, warp=-1), "Lantern Well", (25,), 8),
    ]
    wastes = maps[10]["spawns"]
    assert [p["warp"] for p in wastes] == [66, 103]
    maps[10]["spawns"] = [
        room_spawn(10, wastes[1], "Mana Shrine", (1,)),
        room_spawn(10, wastes[0], "Krazoa 4 Shrine", (3,)),
        room_spawn(10, dict(x=-5006.61035, y=-769.940002, z=2251.30469,
                           layer=0, angle=0, warp=-1), "Garunde", (4, 5, 8, 12)),
        room_spawn(10, dict(x=-5783.62256, y=-834.940002, z=1350.67285,
                           layer=0, angle=0, warp=-1), "Post BribeClaw", (4, 7, 8), 67),
    ]
    palace = maps[11]["spawns"]
    assert [p["warp"] for p in palace] == [6, 32, 34, 40, 65, 78]
    # LinkALevControl_seqFn uses the same WARPTAB 34 for K3 and K4,
    # with different acts. Preserve those routes as distinct named presets.
    maps[11]["spawns"] = [
        room_spawn(11, palace[3], "Krazoa 1", (3,), act=1),
        room_spawn(11, palace[1], "Krazoa 2", (5, 6), act=2),
        room_spawn(11, palace[2], "Krazoa 3", (8, 9), act=3),
        room_spawn(11, palace[2], "Krazoa 4", (8, 9), act=4),
        room_spawn(11, palace[5], "Krazoa 5 Arwing", (10, 11), act=5),
        room_spawn(11, palace[4], "Krazoa 6", (10, 11), act=6),
        room_spawn(11, palace[0], "Krystal", (0, 1), act=1),
    ]
    fortress = maps[12]["spawns"]
    assert [p["warp"] for p in fortress] == [74, 99]
    maps[12]["spawns"] = [
        room_spawn(12, fortress[1], "Arwing Arrival"),
        room_spawn(12, fortress[0], "Race Ladder", (1,)),
        room_spawn(12, dict(x=1711.75391, y=1866.06006, z=-16725.6328,
                           layer=0, angle=0, warp=-1), "Post Jail", (6, 7), 16),
        room_spawn(12, dict(x=107.256348, y=2049.06006, z=-16931.1602,
                           layer=0, angle=0, warp=-1, cf_exterior=True), "Exterior", (19, 27)),
    ]
    for p in maps[12]["spawns"][1:]:
        p["skip_cf_arrival"] = True
    city = maps[13]["spawns"]
    assert [p["warp"] for p in city] == [19, 21, 70, 91, 120]
    maps[13]["spawns"] = [
        room_spawn(13, city[4], "Arwing Arrival"),
        room_spawn(13, city[0], "King Earth Walker Top"),
        room_spawn(13, dict(x=-16324.0811, y=-1122.93994, z=-13857.9746,
                           layer=0, angle=0, warp=-1), "King Earth Walker Bot"),
        room_spawn(13, city[1], "Mana Shrine"),
        room_spawn(13, city[2], "Upper Shrine Pad"),
        room_spawn(13, city[3], "King Red Eye Gate", (4,)),
        room_spawn(13, dict(x=-14271.3672, y=-1001.94, z=-12973.8633,
                           layer=0, angle=0, warp=-1), "Moon Temple", (4,)),
        room_spawn(13, dict(x=-18367.6523, y=-1001.94, z=-14556.7051,
                           layer=0, angle=0, warp=-1), "Sun Temple", (4,)),
        # Final water SpellStone placement selects act 2, not a map layer.
        # Share Upper Shrine Pad's position/facing; retain custom-warp semantics.
        room_spawn(13, dict(city[2], warp=-1), "Walled City 2", act=2),
    ]
    for p in maps[13]["spawns"][1:]:
        p["skip_wc_arrival"] = True
    village = maps[14]["spawns"]
    assert [p["warp"] for p in village] == [71, 80, 85]
    maps[14]["spawns"] = [
        dict(village[1], name="Intro Totem Area"),
        room_spawn(14, dict(village[1], lfv_totem=True), "Intro Totem Event", (2,), act=2),
        dict(village[0], name="Krazoa 3 Shrine"),
        dict(village[2], name="Scarab Well", x=-3342.94727, y=-895.940002, z=-1698.66504),
        dict(name="Chieftain", x=-319.42627, y=-968.518616, z=-960.953613,
             layer=0, angle=0, warp=-1),
    ]
    dungeon = maps[16]["spawns"]
    assert [p["warp"] for p in dungeon] == [0, 12]
    for p in dungeon:
        p["name"] = f'Entrance ({p["warp"]})'
    moon = maps[18]["spawns"]
    assert [p["warp"] for p in moon] == [16, 64]
    maps[18]["spawns"] = [
        room_spawn(18, moon[0], "Ground Quake Shrine"),
        room_spawn(18, dict(x=-12825.8311, y=-220.606461, z=-2201.03027,
                           layer=0, angle=0, warp=-1), "Meteor Event", (5,)),
        room_spawn(18, moon[1], "Krazoa 2 Shrine", (8,)),
        room_spawn(18, dict(x=-12220.2471, y=37.0600014, z=-4310.73633,
                           layer=0, angle=0, warp=-1), "Scarab Well", (8,)),
    ]
    mines = maps[19]["spawns"]
    assert len(mines) == 1 and mines[0]["warp"] == 119
    mines[0]["name"] = "Arwing Arrival"
    for name, x, y, z, groups in (
        ("Gate Entrance", -7468.39258, -1229.19495, 9575.22461, ()),
        ("End of Lava", -7792.62012, -1170.76294, 10578.2334, (1,)),
        ("Flame Mammoth", -8107.45459, -1251.93994, 12673.5801, (1, 5, 8)),
        ("Alpine 1", -8457.36621, -1311.93994, 13714.9141, (6, 8)),
        ("Alpine 2", -8680.41406, -1458.93994, 11013.4033, (3,)),
        ("Post Big Gate", -7708.66357, -1258.24097, 13558.5918, (7, 9, 18, 20)),
        ("Cannon", -8374.41016, -1005.94, 14447.2275, (7, 18)),
        ("Fire / Leap of Faith", -6573.54492, -1228.93994, 14728.7676, (16,)),
        ("Cog 3 / Mammoth 2", -7278.93896, -1041.93994, 15043.3613, (10,)),
        ("Post Blizzard", -10037.4512, -782.878357, 14736.7, (12, 21)),
        ("Bike", -9730.06348, -916.940002, 14331.4121, (12, 14, 21)),
    ):
        mines.append(room_spawn(19, dict(x=x, y=y, z=z, layer=0, angle=0, warp=-1), name, groups))
    ocean_bottom = maps[21]["spawns"]
    assert [p["warp"] for p in ocean_bottom] == [75, 76, 105, 113, 114]
    maps[21]["spawns"] = [
        dict(ocean_bottom[2], name="Entrance"),
        dict(ocean_bottom[0], name="Spell Stone 2 Warp"),
        dict(ocean_bottom[1], name="Spell Stone 4 Warp"),
        dict(ocean_bottom[3], name="Spell Stone Room (113)"),
        dict(ocean_bottom[4], name="Spell Stone Room (114)"),
    ]
    ice = maps[23]["spawns"]
    assert [p["warp"] for p in ice] == [2, 26]
    ice[0]["name"] = "Entrance"
    ice[1]["name"] = "Top"
    ice.append(dict(name="Hot Springs", x=760.802246, y=-69.0373917, z=2893.98633,
                    layer=0, angle=0, warp=-1))
    linkb = maps[56]["spawns"]
    assert len(linkb) == 1 and linkb[0]["warp"] == -1
    linkb[0].update(name="Tricky Puzzle", x=-145.717773, y=-41.2635803, z=2711.45166)
    for mid, x, y, z in (
        (67, -6308.38086, -648.940002, 314.400391),   # LinkC
        (68, -7912.86133, -1611.93994, 14536.9434),  # LinkD
        (69, -7994.76465, -997.711731, -949.294922), # LinkE
        (70, -14208.2217, -113.830719, -397.878906), # LinkF
        (71, -2739.07275, -1089.23462, -4844.75439), # LinkG
        (72, 935.213379, -994.940002, -2813.9043),   # LinkH
        (73, 3518.90137, -1503.93994, -5768.85645), # LinkJ
    ):
        link = maps[mid]["spawns"]
        assert len(link) == 1 and link[0]["warp"] == -1
        link[0].update(x=x, y=y, z=z)
    for mid in (4, 7, 8, 10, 11, 12, 13, 14, 16, 18, 19, 23, 56, 67, 68, 69, 70, 71, 72, 73):
        for p in maps[mid]["spawns"]:
            assert resolve(p["x"], p["z"], p["layer"]) == mid
    # Landed_Arwing's ending departure reuses WARPTAB 127 with Great Fox act 2.
    # The two GF_sequence placements are restricted to acts 1 and 2.
    greatfox = maps[65]["spawns"]
    assert len(greatfox) == 1 and greatfox[0]["warp"] == 127
    maps[65]["spawns"] = [dict(greatfox[0], name="Opening Briefing", act=1),
                          dict(greatfox[0], name="Ending / Credits", act=2)]
    # User-provided DIM Bottom arrival, replacing the estimated object position.
    # Keep its verified world-map layer and custom-arrival semantics.
    destination = maps[27]["spawns"][0]
    assert destination["warp"] == -1 and destination["layer"] == -2
    destination.update(name="Bike Entrance", x=-8974.73438, y=-1627.60266, z=17620.2559)
    for name, x, y, z in (("Waterfall Room", -10076.0898, -1948.52502, 17830.9336),
                          ("Cannon Bridge Switch", -7847.50977, -2225.93994, 16918.0762)):
        maps[27]["spawns"].append(dict(name=name, x=x, y=y, z=z, layer=destination["layer"], angle=0, warp=-1))
    maps[27]["spawns"].append(dict(name="Galdon Portal", x=-10003.6807, y=-2637.06641, z=16294.9297,
                                   layer=destination["layer"], angle=0, warp=-1))
    for destination in maps[27]["spawns"]:
        assert resolve(destination["x"], destination["z"], destination["layer"]) == 27
    galdon = maps[28]["spawns"]
    assert [p["warp"] for p in galdon] == [29, 30, 54, 92]
    maps[28]["spawns"] = [dict(galdon[3], name="Entrance"), room_spawn(28, galdon[1], "Gut", (2,)),
                          dict(galdon[0], name="Entrance (29)"), dict(galdon[2], name="Entrance (54)")]
    for mid, name in zip(BOSS_ORDER, ("Galdon", "CloudRunner Race", "King Red Eye", "Drakor", "Scales")):
        maps[mid]["name"] = "Boss " + name
    for m in maps:
        if m["category"] == 3 and m["spawns"]:
            m["spawns"][0]["name"] = "Entrance"
    for mid in (40, 43, 44):
        assert len(maps[mid]["spawns"]) == 1
        maps[mid]["spawns"][0]["name"] = "Entrance"
    assert [p["warp"] for p in maps[48]["spawns"]] == [90, 109]
    for p in maps[48]["spawns"]:
        p["name"] = f"Entrance ({p['warp']})"
    # Curated Cape Claw arrivals, in menu order. Preserve the original shrine's
    # arrival ID/facing with the user-selected shrine height.
    shrine = maps[29]["spawns"][0]
    assert len(maps[29]["spawns"]) == 1 and shrine["warp"] == 53
    shrine.update(name="Mana Shrine", y=-1638)
    def cape_spawn(name, x, y, z, angle=0, act=0):
        return dict(name=name, x=x, y=y, z=z, layer=shrine["layer"], angle=angle, warp=-1, act=act)
    maps[29]["spawns"] = [
        cape_spawn("Entrance", 1388.6582, -1204.9939, -4253.25928, angle=128),
        cape_spawn("Link Door", 2830, -1398, -4402),
        shrine,
        cape_spawn("Gas Chamber", 3754.10693, -1464.93994, -3452.88184),
        cape_spawn("Cannon", 3299.2041, -1579.93994, -2635.34961),
        cape_spawn("Cannon Act 3", 3299.2041, -1579.93994, -2635.34961, act=3),
        cape_spawn("Gas Room Switch", 3593.68945, -1398.93994, -4053.75293),
        cape_spawn("Disguise Door Act 2", 3358.5166, -1398.93994, -4058.07812, act=2),
        cape_spawn("High Top", 2652.26367, -1577.93994, -2211.13672),
    ]
    for destination in maps[29]["spawns"]:
        assert resolve(destination["x"], destination["z"], destination["layer"]) == 29
    race = maps[43]["spawns"]
    assert len(race) == 1 and race[0]["warp"] == 73
    race[0]["name"] = "Entrance"
    for mid in (51, 52):
        assert len(maps[mid]["spawns"]) == 1
        maps[mid]["spawns"][0]["name"] = "Entrance"
    # Retain the entrance first, followed by the tile puzzle and warp pad.
    assert [spawn["warp"] for spawn in maps[50]["spawns"]] == [104, 115]
    ocean = maps[50]["spawns"]
    maps[50]["spawns"] = [
        dict(ocean[1], name="Entrance"),
        dict(name="Tile Puzzle", x=3371.50684, y=-1620.93994, z=-8013.62842,
             layer=0, angle=0, warp=-1),
        dict(ocean[0], name="Warp Pad"),
    ]
    for destination in maps[50]["spawns"]:
        assert resolve(destination["x"], destination["z"], destination["layer"]) == 50
    # Magic Cave reuses one arrival point for different layouts/rewards and
    # return warps. Read the actual entrance contract rather than inventing it.
    cave_default = maps[54]["spawns"][0]
    assert len(maps[54]["spawns"]) == 1 and cave_default["warp"] == 87
    maps[54]["spawns"] = []
    for source, index, name in (
        (7, 484, "TTH: Fire Blaster"), (7, 853, "TTH: Magic Upgrade"),
        (7, 713, "TTH: Open Portal"), (8, 153, "TTH Well - Rocket"),
        (10, 339, "Snowhorn Wastes"), (29, 715, "Cape Claw"),
        (4, 510, "Volcano Force Point"), (18, 188, "Moon Mountain Pass"),
        (13, 364, "Walled City"),
    ):
        packed = assets[maps[source]["romlist"] + ".romlist.zlb"]
        data = zlib.decompress(packed[16:16 + u32(packed, 12)])
        offset = 0
        for _ in range(index):
            offset += data[offset + 2] * 4
        record = data[offset:offset + data[offset + 2] * 4]
        object_id = struct.unpack_from(">h", record)[0]
        canonical = struct.unpack_from(">h", assets["OBJINDEX.bin"], object_id * 2)[0]
        object_offset = u32(assets["OBJECTS.tab"], canonical * 4)
        assert assets["OBJECTS.bin"][object_offset + 0x91:object_offset + 0x9c] == b"MagicCaveTo"
        assert len(record) == 0x28 and record[31] == 54 and record[32] == 87
        assert record[26] < 6 and record[27] in (1, 2)
        maps[54]["spawns"].append(dict(cave_default, name=name, cave=dict(
            source=source, group=record[26], act=record[27], exit=record[33],
            entrance_group=record[6] if record[4] & 0x10 else 255,
            entrance_id=u32(record, 20))))
        # Exterior presets borrow the corresponding retail exit animation.
        # Negative cave IDs distinguish these from warps into the cave itself.
        exterior = [p for p in maps[source]["spawns"] if p["warp"] == record[33]]
        assert len(exterior) == 1, (source, record[33])
        exterior[0]["cave_exit"] = len(maps[54]["spawns"])
    # WarpStone's corridor shares a position; its act and controller select the
    # onward route. Palace variants normally depend on carried spirits.
    link_default = maps[66]["spawns"][0]
    assert len(maps[66]["spawns"]) == 1 and link_default["warp"] == 126
    maps[66]["spawns"] = [dict(link_default, name=name, link=route) for route, name in enumerate(
        ("To Ice Mountain", "To Krazoa Palace: K2", "To Krazoa Palace: K3",
         "To Krazoa Palace: K4", "Return to Thorntail Hollow"), 1)]
    # User testing found Duster Cave softlocks and Nik Test deadlocks. Keep
    # them discoverable, but remove their destinations so WARP NOW is blocked.
    for mid, romlist in ((55, "duster"), (64, "linklevel")):
        assert maps[mid]["romlist"] == romlist
        maps[mid]["name"] += " (Unavailable)"
        maps[mid]["spawns"] = []
    return maps, {name: hashlib.sha256(data).hexdigest() for name, data in assets.items() if not name.endswith(".romlist.zlb")}


def generate(iso, output):
    maps, hashes = catalog(iso)
    lines = ["/* Generated by tools/practice/warp_catalog.py from verified EN v1.0 assets.",
             " * Categories, friendly names, curated positions and fallbacks are practice policy. */",
             "#ifndef PRACTICE_WARP_CATALOG_H", "#define PRACTICE_WARP_CATALOG_H", "#ifdef SFA_PRACTICE",
             '#include "main/rcp_dolphin_api.h"',
             f"#define PRACTICE_LINKI_ORIGIN {LINKI_ORIGIN}",
             "#define PRACTICE_WARP_SKIP_DR_ARRIVAL 1u",
             "#define PRACTICE_WARP_SKIP_CF_ARRIVAL 2u",
             "#define PRACTICE_WARP_SKIP_WC_ARRIVAL 4u",
             "#define PRACTICE_WARP_CF_EXTERIOR 8u",
             "#define PRACTICE_WARP_LFV_TOTEM 16u",
             "typedef struct PracticeWarpSpawn { WarpDestination destination; s16 warp; s16 cave; const char* name; s8 link; s8 act; u8 flags; s8 bankMap; u32 groups; } PracticeWarpSpawn;",
             "typedef struct PracticeCaveArrival { u8 source; u8 group; u8 act; u8 exit; u32 entranceId; u8 entranceGroup; } PracticeCaveArrival;",
             "typedef struct PracticeWarpMap { const char* name; u16 firstSpawn; u8 spawnCount; u8 category; } PracticeWarpMap;",
             "static const PracticeWarpSpawn practiceWarpSpawns[] = {"]
    first, caves = 0, []
    for record in maps:
        record["first"] = first
        for p in record["spawns"]:
            assert 0 <= p.get("link", 0) <= 127 and 0 <= p.get("act", 0) <= 15
            assert -1 <= p.get("bank_map", -1) <= 116
            xyz = ", ".join(f"{p[k]:.9f}f" for k in ("x", "y", "z"))
            name = json.dumps(p["name"].upper()) if p.get("name") else "NULL"
            cave = -p.get("cave_exit", 0)
            if p.get("cave"):
                caves.append(p["cave"])
                cave = len(caves)
            flags = " | ".join(f"PRACTICE_WARP_SKIP_{area}_ARRIVAL" for area in ("DR", "CF", "WC")
                               if p.get(f"skip_{area.lower()}_arrival")) or "0"
            if p.get("cf_exterior"):
                flags += " | PRACTICE_WARP_CF_EXTERIOR"
            if p.get("lfv_totem"):
                flags += " | PRACTICE_WARP_LFV_TOTEM"
            lines.append(f'    {{{{{xyz}, {p["layer"]}, {p["angle"]}}}, {p["warp"]}, {cave}, {name}, {p.get("link", 0)}, {p.get("act", 0)}, {flags}, {p.get("bank_map", -1)}, 0x{p.get("groups", 0):08X}u}},')
            first += 1
    lines += ["};", "static const PracticeWarpMap practiceWarpMaps[] = {"]
    for m in maps:
        lines.append(f'    {{{json.dumps(m["name"].upper())}, {m["first"]}, {len(m["spawns"])}, {m["category"]}}}, /* {m["id"]} */')
    ordered_maps = OVERWORLD_ORDER + DUNGEON_ORDER + BOSS_ORDER + OUTER_SPACE_ORDER + SPECIAL_ORDER + UNUSED_ORDER
    priority = {}
    for mid in ordered_maps:
        priority.setdefault(mid, len(priority))
    order = sorted(range(len(maps)), key=lambda mid: (maps[mid]["category"], priority.get(mid, 117 + mid)))
    assert tuple(mid for mid in order if maps[mid]["category"] == 1) == OVERWORLD_ORDER
    categories, browse = [], []
    for category, name in enumerate(CATEGORY_NAMES):
        members = list(order if category == 0 else SPECIAL_ORDER if category == 6
                       else (mid for mid in order if maps[mid]["category"] == category))
        assert members and len(members) == len(set(members))
        categories.append(dict(name=name, first=len(browse), maps=members))
        browse.extend(members)
    assert set(browse) == set(range(117))
    lines += ["};", "static const u8 practiceWarpMapOrder[] = {",
              "    " + ", ".join(str(mid) for mid in browse), "};",
              "typedef struct PracticeWarpCategory { const char* name; u16 firstMap; u8 mapCount; } PracticeWarpCategory;",
              "static const PracticeWarpCategory warpCategories[] = {"]
    for category in categories:
        lines.append(f'    {{{json.dumps(category["name"].upper())}, {category["first"]}, {len(category["maps"])}}},')
    lines += ["};", "static const PracticeCaveArrival practiceCaveArrivals[] = {"]
    for c in caves:
        lines.append(f'    {{{c["source"]}, {c["group"]}, {c["act"]}, {c["exit"]}, 0x{c["entrance_id"]:08X}u, {c["entrance_group"]}}},')
    lines += ["};", "#endif", "#endif", ""]
    output.write_text("\n".join(lines))
    report = dict(maps=maps, map_order=order, categories=categories, asset_sha256=hashes)
    (ROOT / "build/practice/warp-catalog.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Generated {len(maps)} maps, {first} destinations, {sum(bool(m['spawns']) for m in maps)} warpable maps")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "include/practice/warp_catalog.h")
    args = parser.parse_args()
    generate(args.iso, args.output)
