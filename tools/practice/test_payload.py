"""Execute the compiled PPC payload with stubbed game/GX services.

Requires Unicorn (pip install --target build/practice/python unicorn==2.1.4).
These checks exercise real target instructions, not Dolphin or GPU emulation.
"""
import math
import re
import struct
import sys
import unittest

import gamebit_names
from build import ROOT, PAYLOAD_ADDRESS, PAYLOAD_LIMIT, compile_payload, make_patch, apply_dol, sections, symbols, tool_directory

OUT = ROOT / "build/practice"
sys.path.insert(0, str(OUT / "python"))
from unicorn import Uc, UC_ARCH_PPC, UC_MODE_PPC32, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_FPR0, UC_PPC_REG_MSR, UC_PPC_REG_LR, UC_PPC_REG_PC

GAMEBIT_NAMES = gamebit_names.names()


class Machine:
    def __init__(self, payload, exports, dol):
        self.payload = payload
        self.sym = exports
        self.uc = Uc(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN)
        self.uc.mem_map(0x80000000, 0x1800000)
        self.uc.mem_map(0xCC008000, 0x1000)
        self.uc.reg_write(UC_PPC_REG_MSR, 0x2000)
        for _, off, addr, size in sections(dol):
            self.uc.mem_write(addr, dol[off:off + size])
        self.uc.mem_write(PAYLOAD_ADDRESS, payload)
        self.player = 0x81000000
        self.state = self.player + 0x1000
        self.write(self.player + 0xB8, self.state)
        self.write(self.player + 0x1C, 100.0, "f")
        self.write(self.state + 0x1C0, -100000.0, "f")
        self.write(self.sym["timeDelta"], 1.0, "f")
        self.calls = []
        self.geometry = []
        self.current = None
        self.words = []
        self.stub = {}
        self.blocks = {}
        self.reports = []
        self.bit_edits = []
        self.uart = bytearray()
        self.exi_command = None
        for index in range(56):
            self.write(self.sym["gSfxObjectChannels"] + index * 0x38, 0xffffffff)
        retail = symbols()
        self.retail_stack_ranges = [(retail[name][0], sum(retail[name])) for name in (
            "isInBounds", "Obj_GetWorldPosition", "playerRefreshCollisionState",
            "curves_preparePointCollisionFrame", "curves_updateLocalPointTransforms", "setMatrixFromObjectPos",
            "Camera_UpdateForObject", "Obj_TransformWorldPointToLocal", "playerUpdateSurfaceResponse",
            "interpolate", "powfBitEstimate")]
        for name, (addr, _) in retail.items():
            if name.startswith("GX") or name in (
                "padUpdate", "Obj_GetPlayerObject", "OSSetArenaLo", "playerDoControls",
                "playerEnterDeepWater", "playerUpdateSurfaceResponse", "Camera_SetCurrentViewIndex",
                "Camera_UpdateProjection", "resetSomeGxFlags", "getScreenResolution", "mathSinf", "mathCosf", "fastFloorf",
                "fastCastS16ToFloat",
                "Matrix_TransformPoint", "mapGetBlockAtPos", "ObjList_GetObjects", "PSMTXInverse", "PSMTXMultVec",
                "Obj_TransformLocalPointToWorld", "mainGetBit", "ObjHits_IsObjectEnabled", "warpToMap",
                "mapReload", "mapLoadByCoords", "unlockLevel", "isSaveGameLoading", "getDataFileSize",
                "SaveGame_getPlayerStats", "getTrickyObject", "mainSetBits", "SaveGame_gplaySetAct",
                "SaveGame_gplaySetObjGroupStatus", "sprintf", "EXILock", "EXISelect", "EXIImm",
                "EXISync", "EXIDeselect", "EXIUnlock", "sndFXCtrl", "getHudHiddenFrameCount", "Sfx_UpdateObjectChannel3D",
                "playerUpdate", "playerDoHitDetection", "playerDie", "Obj_TransformWorldVectorToLocal",
                "playerRefreshCollisionState", "trackInvalidateDynamicSlotsForObject", "angleToVec2", "loadMapForCameraPos",
                "getCurMapLayer", "memcpy", "mmAlloc", "mm_free", "loadMapForCurrentSaveGame", "_saveGame",
                "MagicCaveTop_update", "objSetupObject", "SaveGame_getCurChar", "SaveGame_setCharacter",
                "SaveGame_getCurCharPos", "getSbGalleon", "ObjAnim_SetCurrentMove", "player_setState",
                "Camera_setFocus", "Camera_setMode", "SB_Galleon_onSeqFree", "getEnvfxActImmediately",
                "setDrawCloudsAndLights", "setDrawLights"):
                self.stub[addr] = name
        self.uc.hook_add(UC_HOOK_CODE, self.service)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.fifo, begin=0xCC008000, end=0xCC008003)

    def write(self, address, value, fmt="I"):
        self.uc.mem_write(address, struct.pack(">" + fmt, value))

    def read(self, address, fmt="I"):
        return struct.unpack(">" + fmt, self.uc.mem_read(address, struct.calcsize(fmt)))[0]

    def r(self, n):
        return self.uc.reg_read(UC_PPC_REG_0 + n)

    def row(self, label):
        for index in range(len(re.findall(r'\{"[^"\n]+",', (ROOT / "src/practice/practice.c").read_text().split("static const PracticeRow rows", 1)[1].split("static u8 enabled", 1)[0]))):
            address = self.read(self.sym["rows"] + index * 8)
            text = bytes(self.uc.mem_read(address, 64)).split(b"\0")[0].decode()
            if text == label:
                return index
        raise AssertionError(label)

    def toggle(self, label, value):
        self.write(self.sym["enabled"] + self.row(label), value, "B")

    def f(self, n):
        return struct.unpack(">d", struct.pack(">Q", self.uc.reg_read(UC_PPC_REG_FPR0 + n)))[0]

    def setf(self, n, f):
        self.uc.reg_write(UC_PPC_REG_FPR0 + n, struct.unpack(">Q", struct.pack(">d", f))[0])

    def service(self, uc, pc, size, unused):
        # Unicorn lacks Gekko paired singles. MWCC also saves/restores the upper
        # lanes beside ordinary stfd/lfd saves; this payload does no paired math.
        if (PAYLOAD_ADDRESS <= pc < PAYLOAD_ADDRESS + len(self.payload) or
                any(start <= pc < end for start, end in self.retail_stack_ranges)):
            instruction = self.read(pc)
            if instruction >> 26 in (56, 60):
                assert (instruction >> 16) & 31 == 1 and (instruction >> 12) & 15 == 0
                uc.reg_write(UC_PPC_REG_PC, pc + 4)
                return
        name = self.stub.get(pc)
        if not name:
            return
        if name == "Obj_GetPlayerObject":
            uc.reg_write(UC_PPC_REG_0 + 3, self.player)
        elif name == "fastFloorf":
            self.setf(1, math.floor(self.f(1)))
        elif name == "fastCastS16ToFloat":
            # This leaf uses Gekko psq_l quantization, unsupported by Unicorn.
            self.setf(1, float(self.read(self.r(3), "h")))
        elif name == "angleToVec2":
            angle = self.r(3) * math.pi / 32768
            self.write(self.r(4), math.sin(angle), "f")
            self.write(self.r(5), math.cos(angle), "f")
        elif name == "mainGetBit":
            uc.reg_write(UC_PPC_REG_0 + 3, self.bit_value(self.r(3)) if hasattr(self, "bit_table") else getattr(self, "gate_bit", 1))
        elif name == "mainSetBits":
            self.bit_edits.append((self.r(3), self.r(4)))
            self.set_bit(self.r(3), self.r(4))
        elif name == "MagicCaveTop_update" and self.bit_value(0x91e):
            self.set_bit(0x91e, 0)
        elif name == "isSaveGameLoading":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "save_loading", 0))
        elif name == "getDataFileSize":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "bit_table_size", 0x4000))
        elif name == "SaveGame_getPlayerStats":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "stats", 0))
        elif name == "SaveGame_getCurChar":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "character", 1))
        elif name == "SaveGame_setCharacter":
            self.character = self.r(3)
        elif name == "SaveGame_getCurCharPos":
            uc.reg_write(UC_PPC_REG_0 + 3, 0x8110b000 + self.character * 16)
        elif name == "getSbGalleon":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "ship", 0))
        elif name == "getTrickyObject":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "tricky", 0))
        elif name == "SaveGame_gplaySetAct":
            self.set_bit(self.read(self.sym["gSaveGameMapActBits"] + self.r(3) * 2, "H"), self.r(4))
        elif name == "SaveGame_gplaySetObjGroupStatus":
            gamebit = self.read(self.sym["gSaveGameMapObjGroupBits"] + self.r(3) * 2, "H")
            mask = 1 << self.r(4)
            value = self.bit_value(gamebit)
            value = value | mask if self.r(5) not in (0, 0xfffffffe) else value & ~mask
            self.set_bit(gamebit, value)
            for mid in range(120):
                if self.read(self.sym["gSaveGameMapObjGroupBits"] + mid * 2, "H") == gamebit:
                    self.write(self.sym["gMapObjGroupStatuses"] + mid * 4, value)
        elif name == "playerUpdate" and getattr(self, "spend_resources", False):
            self.write(self.stats, 1, "b")
            self.write(self.stats + 4, 0, "h")
        elif name == "Obj_TransformWorldVectorToLocal":
            # A rotated parent fixture: inverse yaw maps world X to local -Z.
            x, y, z = self.f(1), self.f(2), self.f(3)
            for reg, value in zip((3, 4, 5), (z, y, -x)):
                self.write(self.r(reg), value, "f")
        elif name == "getCurMapLayer":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "layer", 0) & 0xffffffff)
        elif name == "memcpy":
            uc.mem_write(self.r(3), bytes(uc.mem_read(self.r(4), self.r(5))))
        elif name == "mmAlloc":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "allocation", 0x81110000))
        elif name == "_saveGame":
            uc.reg_write(UC_PPC_REG_0 + 3, 0x35)
        elif name == "getHudHiddenFrameCount":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "hud_hidden", 0))
        elif name == "sprintf":
            fmt = bytes(uc.mem_read(self.r(4), 180)).split(b"\0")[0].decode()
            # EABI integer arguments use r3-r10; after destination/format, the
            # seventh printf value is passed at SP+8, not in r11.
            args = tuple(self.r(i) for i in range(5, 11)) + (self.read(self.r(1) + 8),)
            self.reports.append((fmt, args))
            values = iter(args)
            def format_arg(match):
                value = next(values)
                spec = match[0]
                if spec == "%s":
                    return bytes(uc.mem_read(value, 100)).split(b"\0")[0].decode()
                if spec.endswith("X"):
                    return format(value, spec[1:])
                if spec == "%d" and value >= 0x80000000:
                    value -= 0x100000000
                return str(value)
            message = re.sub(r"%[0-9]*[sudX]", format_arg, fmt).encode()
            uc.mem_write(self.r(3), message + b"\0")
            uc.reg_write(UC_PPC_REG_0 + 3, len(message))
        elif name in ("EXILock", "EXISelect", "EXISync", "EXIDeselect", "EXIUnlock", "EXIImm"):
            result = 1
            if name == "EXILock":
                result = not getattr(self, "exi_busy", False)
            elif name == "EXISelect":
                self.exi_command = None
            elif name == "EXIImm":
                if self.r(6) == 0:
                    self.write(self.r(4), getattr(self, "uart_queued", 0), "B")
                elif self.exi_command is None:
                    self.exi_command = self.read(self.r(4))
                elif self.exi_command == 0xa0010000:
                    self.uart.extend(uc.mem_read(self.r(4), self.r(5)))
            uc.reg_write(UC_PPC_REG_0 + 3, result)
        elif name == "ObjHits_IsObjectEnabled":
            uc.reg_write(UC_PPC_REG_0 + 3, 1)
        elif name == "warpToMap":
            self.write(self.sym["gWarpRequested"], 1, "B")
            self.write(self.sym["gPendingWarpIndex"], self.r(3), "h")
        elif name == "mapLoadByCoords":
            self.loaded_coordinates = (self.f(1), self.f(2), self.f(3), self.r(3))
            self.write(self.sym["gGameLoopPendingMapDataFileId"], 17)
        elif name == "loadMapForCameraPos":
            self.camera_load = (self.f(1), self.f(2), self.f(3))
        elif name == "getScreenResolution":
            uc.reg_write(UC_PPC_REG_0 + 3, (480 << 16) | 640)
        elif name == "GXBegin":
            self.current = (self.r(3), self.r(5), [])
            self.geometry.append(self.current)
            self.words = []
        elif name == "playerEnterDeepWater":
            self.write(self.state + 0x3F0, self.read(self.state + 0x3F0, "B") | 0x20, "B")
        elif name in ("mathSinf", "mathCosf"):
            self.setf(1, (math.sin if name == "mathSinf" else math.cos)(self.f(1)))
        elif name == "Matrix_TransformPoint":
            matrix = self.r(3)
            p = [self.f(1), self.f(2), self.f(3), 1.0]
            for axis in range(3):
                value = sum(self.read(matrix + (k * 4 + axis) * 4, "f") * p[k] for k in range(4))
                self.write(self.r(4 + axis), value, "f")
        elif name == "PSMTXInverse":
            # Trigger fixture is an orthonormal affine matrix; invert by transpose.
            a = struct.unpack(">12f", uc.mem_read(self.r(3), 48))
            inverse = []
            for i in range(3):
                row = [a[k * 4 + i] for k in range(3)]
                inverse.extend(row + [-sum(row[k] * a[k * 4 + 3] for k in range(3))])
            uc.mem_write(self.r(4), struct.pack(">12f", *inverse))
            uc.reg_write(UC_PPC_REG_0 + 3, 1)
        elif name == "PSMTXMultVec":
            a = struct.unpack(">12f", uc.mem_read(self.r(3), 48))
            p = list(struct.unpack(">3f", uc.mem_read(self.r(4), 12))) + [1]
            result = [sum(a[i * 4 + k] * p[k] for k in range(4)) for i in range(3)]
            uc.mem_write(self.r(5), struct.pack(">3f", *result))
        elif name == "mapGetBlockAtPos":
            uc.reg_write(UC_PPC_REG_0 + 3, self.blocks.get((self.r(3), self.r(4), self.r(5)), 0))
        elif name == "Obj_TransformLocalPointToWorld":
            for axis in range(3):
                self.write(self.r(3 + axis), self.f(1 + axis) + self.read(self.r(6) + 0x18 + axis * 4, "f"), "f")
        elif name == "ObjList_GetObjects":
            self.write(self.r(3), 0)
            self.write(self.r(4), getattr(self, "object_count", 0))
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "object_list", 0))
        self.calls.append((name, self.r(3), self.r(4), self.r(5)))
        uc.reg_write(UC_PPC_REG_PC, uc.reg_read(UC_PPC_REG_LR))

    def fifo(self, uc, access, address, size, value, unused):
        assert size == 4, (address, size)
        self.words.append(value)
        if len(self.words) == 4:
            xyz = struct.unpack(">fff", struct.pack(">III", *self.words[:3]))
            self.current[2].append((*xyz, self.words[3]))
            self.words = []

    def call(self, name, *args, dt=1.0):
        self.uc.reg_write(UC_PPC_REG_0 + 1, 0x815F0000)
        self.uc.reg_write(UC_PPC_REG_LR, 0x80002000)
        for i, value in enumerate(args):
            self.uc.reg_write(UC_PPC_REG_0 + 3 + i, value)
        self.setf(1, dt)
        self.uc.emu_start(self.sym[name], 0x80002000, count=2000000)
        assert self.uc.reg_read(UC_PPC_REG_PC) == 0x80002000, "instruction budget exhausted"

    def pad(self, held=0, pressed=0):
        self.write(self.sym["gPadButtonsHeld"], held)
        self.write(self.sym["gPadButtonsJustPressed"], pressed)
        self.write(self.sym["gPadButtonsReleased"], 0)
        self.write(self.sym["gPadButtonsPrevious"], held)
        self.write(self.sym["gPadTriggers"], held & 0x60, "H")
        self.write(self.sym["gPadTriggersPressed"], pressed & 0x60, "H")
        self.write(self.sym["gPadTriggersReleased"], 0, "H")
        self.write(self.sym["gPadPrevTriggers"], held & 0x60, "H")
        self.write(self.sym["gPadStatuses"], held & 0xFFFF, "H")
        self.write(self.sym["gPadStatuses"] + 7, 255 if held & 0x20 else 0, "B")
        self.call("Practice_PadUpdate")

    def state_fixture(self):
        self.bit_table, self.save_data, self.stats = 0x81100000, 0x81108000, 0x8110A000
        self.write(self.sym["gGameBitTable"], self.bit_table)
        self.write(self.sym["gGameBitSaveData"], self.save_data)
        self.write(self.sym["gGameBitCount"], 8192, "h")
        # All unspecified descriptors deliberately invalid, not aliases of bit 0.
        self.uc.mem_write(self.bit_table, b"\xff\xff\x00\x00" * 4096)
        self.uc.mem_write(self.sym["gSaveGameMapActBits"], bytes(240))
        self.uc.mem_write(self.sym["gSaveGameMapObjGroupBits"], bytes(240))
        self.uc.mem_write(self.stats, struct.pack(">bbBBhhBBBB", 12, 16, 0, 0, 40, 100, 20, 1, 5, 0))
        for gid, first, width, bank in ((0x75, 0, 1, 2), (0x3f5, 5, 8, 2), (0x4e4, 13, 1, 2),
                                        (0x958, 14, 1, 2), (0x956, 256, 1, 2),
                                        (0x300, 0, 4, 1), (0x301, 8, 32, 1)):
            self.bit_def(gid, first, width, bank)
        self.call("practiceStateReady")

    def bit_def(self, gid, first, width, bank):
        self.uc.mem_write(self.bit_table + gid * 4, struct.pack(">HBB", first, (bank << 6) | (width - 1), 0))

    def bit_value(self, gid):
        first, flags, _ = struct.unpack(">HBB", self.uc.mem_read(self.bit_table + gid * 4, 4))
        base = self.save_data + (0xef0, 0x564, 0x24, 0x5d8)[flags >> 6]
        return sum(((self.read(base + (first + n) // 8, "B") >> ((first + n) % 8)) & 1) << n
                   for n in range((flags & 31) + 1))

    def set_bit(self, gid, value):
        first, flags, _ = struct.unpack(">HBB", self.uc.mem_read(self.bit_table + gid * 4, 4))
        base = self.save_data + (0xef0, 0x564, 0x24, 0x5d8)[flags >> 6]
        for n in range((flags & 31) + 1):
            addr, shift = base + (first + n) // 8, (first + n) % 8
            byte = self.read(addr, "B")
            self.write(addr, (byte & ~(1 << shift)) | (((value >> n) & 1) << shift), "B")


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload, cls.exports = compile_payload(OUT, True)
        cls.dol = (ROOT / "orig/GSAE01/sys/main.dol").read_bytes()

    def setUp(self):
        self.m = Machine(self.payload, self.exports, self.dol)

    def test_arena_reservation(self):
        for start in (0x803F8480, PAYLOAD_ADDRESS):
            self.m.call("Practice_SetArenaLo", start)
            self.assertEqual(self.m.calls[-1][:2], ("OSSetArenaLo", PAYLOAD_LIMIT))
        self.m.call("Practice_SetArenaLo", 0x80500000)
        self.assertEqual(self.m.calls[-1][1], 0x80500000)

    def test_linki_registration_reads_retail_cells_and_changes_only_unused_slot(self):
        from warp_catalog import LINKI_ORIGIN
        # EN MAPS.tab slot 74: header 98960, cells 99016, end 99240.
        # Retain the audited header/cells as a small loader fixture, so this
        # regression needs only the retail DOL, not an entire ISO at a fixed path.
        cells = [0x7ffe007f] * 56
        for cell, block in ((10, 0), (18, 1), (25, 4), (26, 2), (33, 3), (34, 5)):
            cells[cell] = 0x2400007f | (block << 17)
        header = struct.pack('>4h', 8, 7, 0, 1) + bytes(48)
        map_data = header + struct.pack('>56I', *cells)

        class MapMachine(Machine):
            def service(self, uc, pc, size, unused):
                if pc == self.sym['getTabEntry']:
                    offset, length = self.r(5), self.r(6)
                    assert (offset, length) == (98960, 280)
                    uc.mem_write(self.r(3), map_data)
                    self.calls.append(('getTabEntry', offset, length))
                    uc.reg_write(UC_PPC_REG_PC, uc.reg_read(UC_PPC_REG_LR))
                    return
                super().service(uc, pc, size, unused)

        m = MapMachine(self.payload, self.exports, self.dol)
        delta = m.read(m.sym['getCurMapLayer']) & 0xffff
        if delta & 0x8000:
            delta -= 0x10000
        m.uc.reg_write(UC_PPC_REG_0 + 13, m.sym['curMapLayer'] - delta)
        m.stub[m.sym['initMaps']] = 'initMaps'
        sizes = (1280, 512, 128, 8192)
        buffers = [0x81200000 + i * 0x10000 for i in range(4)]
        before = []
        for i, (address, size) in enumerate(zip(buffers, sizes), 1):
            m.write(m.sym['gShaderMapRomBuffers'] + i * 4, address)
            data = bytes([0 if i == 4 else 0x80 if i == 3 else 0xff]) * size
            m.uc.mem_write(address, data)
            before.append(data)
        m.write(m.sym['gMapsTab'], 0x81300000)
        m.uc.mem_write(0x81300000 + 74 * 28, struct.pack('>3I', 98960, 99016, 99240))
        m.write(m.sym['gMapInfoBuffer'], 0x81310000)
        m.call('Practice_InitMaps')
        self.assertEqual(m.calls[0][0], 'initMaps')
        self.assertEqual(sum(c[0] == 'getTabEntry' for c in m.calls), 1)
        self.assertEqual(struct.unpack('>4h2b', m.uc.mem_read(buffers[0] + 740, 10)),
                         (LINKI_ORIGIN, LINKI_ORIGIN + 7, LINKI_ORIGIN - 1, LINKI_ORIGIN + 5, 0, 1))
        self.assertEqual(m.read(buffers[2] + 74, 'b'), 0)
        occupied = bytes(m.uc.mem_read(buffers[3] + 74 * 64, 64))
        self.assertEqual([n for n in range(512) if occupied[n // 8] & (1 << (n % 8))],
                         [10, 18, 25, 26, 33, 34])
        for address, old, slot_size in zip(buffers, before, (10, 0, 1, 64)):
            after = bytes(m.uc.mem_read(address, len(old)))
            start, end = 74 * slot_size, 75 * slot_size
            self.assertEqual(after[:start] + after[end:], old[:start] + old[end:])

    def test_curated_dim_and_krazoa_entrance_names(self):
        import json
        maps = json.loads((OUT / 'warp-catalog.json').read_text())['maps']
        dim = maps[27]['spawns']
        self.assertEqual([p['name'] for p in dim],
                         ['Bike Entrance', 'Waterfall Room', 'Cannon Bridge Switch', 'Galdon Portal'])
        for p, xyz in zip(dim[1:3], ((-10076.0898, -1948.52502, 17830.9336),
                                    (-7847.50977, -2225.93994, 16918.0762))):
            self.assertEqual(tuple(p[k] for k in ('x', 'y', 'z')), xyz)
            self.assertEqual(p['layer'], -2)
        for mid in (31, 32, 33, 34, 39):
            self.assertEqual(maps[mid]['spawns'][0]['name'], 'Entrance')
        self.assertEqual(maps[74]['spawns'][0]['bank_map'], 12)

    def test_save_integrity_bypass_runs_retail_write_and_preserves_io_errors(self):
        def checksum(block):
            words = struct.unpack(">" + "Q" * (len(block) // 8), block)
            x = 0
            for word in words:
                x ^= word
            return x ^ ((sum(words) + 14) & 0xffffffffffffffff)

        class CardMachine(Machine):
            def service(self, uc, pc, size, unused):
                name = self.stub.get(pc)
                result = 0
                if name == "mmAlloc":
                    result = self.next_allocation
                    self.next_allocation += 0x4000
                elif name == "saveGame":
                    self.identity_during_save = self.read(self.sym["gSaveCardIdentityCheckEnabled"], "B")
                    result = 1
                elif name == "CARDRead":
                    offset = self.r(6)
                    self.read_offsets.append(offset)
                    result = -5 if self.fail_read else 0
                    if result == 0:
                        uc.mem_write(self.r(4), bytes(self.card[offset:offset+self.r(5)]))
                elif name == "CARDWrite":
                    result = -3 if self.fail_write else 0
                    if result == 0:
                        offset = self.r(6)
                        self.card[offset:offset+self.r(5)] = uc.mem_read(self.r(4), self.r(5))
                        self.write_offsets.append(offset)
                elif name not in ("DCInvalidateRange", "DCFlushRange", "CARDClose", "CARDUnmount"):
                    return super().service(uc, pc, size, unused)
                uc.reg_write(UC_PPC_REG_0 + 3, result & 0xffffffff)
                uc.reg_write(UC_PPC_REG_PC, uc.reg_read(UC_PPC_REG_LR))

        manifest = make_patch(self.dol, self.payload, self.exports)
        patched = apply_dol(self.dol, manifest, self.payload)
        for enabled, corrupt, stale_identity, read_error, write_error in (
                (0, True, False, False, False), (1, True, True, False, False),
                (0, False, True, False, False), (1, False, True, False, False),
                (0, False, False, False, False), (1, True, False, True, False),
                (1, False, False, False, True)):
            with self.subTest(enabled=enabled, corrupt=corrupt, identity=stale_identity,
                              read_error=read_error, write_error=write_error):
                m = CardMachine(self.payload, self.exports, patched)
                m.call("__init_registers")
                for name in ("saveGame", "CARDRead", "CARDWrite", "DCInvalidateRange", "DCFlushRange",
                             "CARDClose", "CARDUnmount"):
                    m.stub[m.sym[name]] = name
                m.next_allocation = 0x81180000
                m.fail_read, m.fail_write = read_error, write_error
                m.read_offsets, m.write_offsets = [], []
                m.card = bytearray(0x6000)
                block = bytearray(0x2000)
                struct.pack_into(">Q", block, 0xa40, checksum(m.card[:0x2000]))
                block[0xb00:0xb10] = bytes(range(16))
                value = checksum(block[:0x1ff8])
                struct.pack_into(">Q", block, 0x1ff8, value ^ int(corrupt))
                m.card[0x2000:0x4000] = block
                m.card[0x4000:0x6000] = block
                m.write(m.sym["gSaveCardChecksumHi"], value ^ int(stale_identity), "Q")
                m.write(m.sym["gSaveCardIdentityCheckEnabled"], 1, "B")
                m.toggle("DISABLE SAVE INTEGRITY CHECKS", enabled)
                save, data = 0x81100000, 0x81101000
                m.uc.mem_write(save, b"\x6d" * 0x6ec)
                m.uc.mem_write(data, b"\x37" * 0xe4)
                m.call("Practice_PrepareSave", 0, 1, 0, save, data, m.sym["saveGameWriteSlotCb"])
                success = not (read_error or write_error or (not enabled and (corrupt or stale_identity)))
                self.assertEqual(m.r(3), int(success))
                self.assertEqual(m.identity_during_save, 1 - enabled)
                self.assertEqual(m.read(m.sym["gSaveCardIdentityCheckEnabled"], "B"), 1)
                self.assertEqual(m.read(m.sym["saveIntegrityBypassActive"], "B"), 0)
                if success:
                    self.assertEqual(m.write_offsets[-2:], [0x4000, 0x2000])
                    for offset in (0x2000, 0x4000):
                        written = m.card[offset:offset+0x2000]
                        self.assertEqual(struct.unpack_from(">Q", written, 0x1ff8)[0], checksum(written[:0x1ff8]))
                        self.assertEqual(written[0xa50+0x6ec:0xa50+2*0x6ec], b"\x6d" * 0x6ec)
                        self.assertEqual(written[0xb00:0xb10], bytes(range(16)))
                else:
                    self.assertFalse(m.write_offsets)

    def test_swim_grid_survives_dense_collision_and_map_origin_changes(self):
        m = self.m
        m.toggle("FOX / PLAYER", 1)
        m.toggle("SWIM ANYWHERE", 1)
        m.toggle("TRIGGERS", 0)
        m.write(m.sym["swimActive"], 1, "B")
        m.write(m.sym["waterHeight"], 140, "f")
        hit = 0x81100000
        m.write(m.player + 0x54, hit)
        m.write(hit + 0x60, 1, "H")
        m.write(hit + 0x5a, 20, "h")
        m.write(hit + 0x62, 1, "B")
        m.object_count, m.object_list = 100, 0x81102000
        m.uc.mem_write(m.object_list, struct.pack(">I", m.player) * m.object_count)
        for x, z in ((0, 0), (-9600, 17920)):
            m.write(m.player + 0x18, x, "f")
            m.write(m.player + 0x20, z, "f")
            m.write(m.sym["playerMapOffsetX"], x, "f")
            m.write(m.sym["playerMapOffsetZ"], z, "f")
            m.geometry.clear()
            m.call("Practice_Draw")
            grid = [g for g in m.geometry if g[2][0][3] == 0x3bbfffff]
            self.assertEqual(len(grid), 22)
            self.assertEqual(grid[0][2][0][:3], (-250, 140, -250))
            self.assertEqual(m.read(m.sym["drawLimitReached"]), 1)

    def test_pointer_guard_covers_mem1_but_excludes_payload(self):
        for address, valid in [(0, 0), (PAYLOAD_ADDRESS, 0), (PAYLOAD_LIMIT - 4, 0),
                               (PAYLOAD_LIMIT, 1), (0x817D0000, 1), (0x81800000, 0)]:
            self.m.call("validPointer", address)
            self.assertEqual(self.m.r(3), valid)

    def test_menu_debounce_navigation_and_input(self):
        m = self.m
        m.write(m.sym["timeStop"], 3, "B")
        m.pad(0x64, 4)  # L+R+Down
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 255)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        m.pad(0x64)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        m.pad()
        m.pad(0x100, 0x100)  # A toggles collision off and hides its children.
        self.assertEqual(m.read(m.sym["enabled"], "B"), 0)
        self.assertEqual(m.read(m.sym["expanded"], "B"), 1)
        m.pad(4, 4)
        self.assertEqual(m.read(m.sym["selected"]), 1)
        self.assertEqual(m.read(m.sym["visible"] + 1, "B"), m.row("TRIGGERS"))
        m.pad(8, 8)
        m.pad(0x100, 0x100)  # Re-enabling restores the children and their settings.
        m.pad(4, 4)
        self.assertEqual(m.read(m.sym["visible"] + 1, "B"), m.row("TERRAIN TRIANGLES"))
        self.assertEqual(m.read(m.sym["enabled"] + m.row("TERRAIN TRIANGLES"), "B"), 0)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("OBJECT TRIANGLES"), "B"), 1)
        m.pad(1, 1)  # Left collapses parent
        self.assertEqual(m.read(m.sym["selected"]), 0)
        self.assertEqual(m.read(m.sym["expanded"], "B"), 0)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 3)

    def test_menu_chord_waits_for_physical_down_release_without_cooldown(self):
        m = self.m
        m.write(m.sym["timeStop"], 3, "B")
        m.pad(0x64, 4)
        # A skipped retail poll leaves swallowed input at zero while the
        # physical history still records L+R+Down. It is not a release.
        m.call("Practice_PadUpdate")
        m.pad(0x64)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        # Either shoulder can drop out/recover while Down stays held.
        for held in (0x44, 0x64, 0x24, 0x64, 4, 0x64):
            m.pad(held)
            self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
            self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
            self.assertEqual(m.read(m.sym["selected"]), 0)
        m.pad(0x60)  # Release only Down; keep both shoulders held.
        m.pad(0x64, 4)  # The next press closes immediately.
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 3)
        m.pad(0x44)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        m.call("Practice_PadUpdate")
        m.pad(0x64)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        m.pad(0x60)
        m.pad(0x64, 4)  # No minimum frame count before reopening.
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        m.pad()
        m.pad(0x20, 0x20)  # Ordinary L/R tab navigation still works.
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 3)

    def test_menu_tabs_require_a_physical_shoulder_release_and_press(self):
        m = self.m
        m.pad(0x64, 4)
        m.pad()
        for button, expected in ((0x20, 1), (0x40, 0)):
            m.pad(button, button)
            self.assertEqual(m.read(m.sym["activeTab"], "B"), expected)
            for _ in range(24):
                # A skipped poll sees input swallowed by the preceding menu
                # frame, but the physical history still holds this shoulder.
                m.call("Practice_PadUpdate")
                m.pad(button)
                self.assertEqual(m.read(m.sym["activeTab"], "B"), expected)
            m.pad()
        # Analog depression and the digital click form one physical press.
        def sample(buttons, analog):
            m.write(m.sym["gPadButtonsHeld"], buttons)
            m.write(m.sym["gPadButtonsPrevious"], buttons)
            m.write(m.sym["gPadTriggers"], analog, "H")
            m.write(m.sym["gPadPrevTriggers"], analog, "H")
            m.call("Practice_PadUpdate")
        sample(0, 0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        for buttons, analog in ((0x20, 0x20), (0x20, 0), (0x20, 0x20), (0, 0x20)):
            sample(buttons, analog)
            m.call("Practice_PadUpdate")
            self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        sample(0, 0)
        sample(0, 0x20)  # A real release/repress advances immediately.
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 2)

    def test_surface_hook_preserves_retail_movement(self):
        # Retail's ground-response path uses incoming f31 before assigning it.
        # playerUpdate supplies dt there; the hook must preserve that contract.
        for surface in (0, 3, 13):
            for dt in (1.0, 2.0):
                for swimming in (0, 1, 2):  # Disabled, armed, actively swimming.
                    with self.subTest(surface=surface, dt=dt, swimming=swimming):
                        results = []
                        for hooked in (False, True):
                            m = Machine(self.payload, self.exports, self.dol)
                            m.call("__init_registers")
                            del m.stub[m.sym["playerUpdateSurfaceResponse"]]
                            m.toggle("SWIM ANYWHERE", int(swimming != 0))
                            m.write(m.sym["swimActive"], int(swimming == 2), "B")
                            m.write(m.sym["waterHeight"], 140.0, "f")
                            if swimming == 2 and not hooked:
                                m.write(m.state + 0x1C0, 140.0, "f")
                            m.write(m.state + 0x264, 0x10, "B")
                            m.write(m.state + 0xBC, surface, "B")
                            m.write(m.player + 0x24, 5.0, "f")
                            m.write(m.player + 0x2C, 3.0, "f")
                            m.write(m.sym["timeDelta"], dt, "f")
                            m.setf(31, dt)
                            name = "Practice_SurfaceResponse" if hooked else "playerUpdateSurfaceResponse"
                            m.call(name, m.player, m.state, m.state, dt=dt)
                            if swimming == 2 and not hooked:
                                m.write(m.state + 0x1C0, -100000.0, "f")
                            results.append(bytes(m.uc.mem_read(m.player, 0x2000)))
                        self.assertEqual(results[0], results[1])

    def test_swim_restores_real_water_query(self):
        m = self.m
        m.pad()
        m.toggle("SWIM ANYWHERE", 1)
        m.write(m.sym["swimActive"], 1, "B")
        m.write(m.sym["waterHeight"], 140.0, "f")
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.state + 0x3F0, "B") & 0x20, 0x20)
        self.assertEqual(m.read(m.state + 0x1C0, "f"), -100000.0)
        m.call("Practice_SurfaceResponse", m.player, m.state, m.state)
        self.assertEqual(m.read(m.state + 0x1C0, "f"), -100000.0)
        m.write(m.sym["gPadStatuses"] + 5, 70, "b")
        m.pad(0x40)  # L+C-stick Up
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 142.0)
        m.toggle("SWIM ANYWHERE", 0)
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.state + 0x3F0, "B") & 0x20, 0)

    def test_swim_quick_toggle_recaptures_height_without_menu_chord_collision(self):
        m = self.m
        m.pad()
        m.toggle("SWIM ANYWHERE", 1)
        m.pad(0x44, 4)  # L+Down.
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 140)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        m.pad(0x44)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)  # Held chord does not repeat.
        m.pad()
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("SWIM ANYWHERE"), "B"), 1)
        m.pad()
        m.write(m.player + 0x1c, 900.0, "f")
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 940)
        m.write(m.sym["gPadStatuses"] + 5, 70, "b")
        m.pad(0x40)  # L+C-stick Up controls height without toggling.
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 942)
        m.write(m.sym["gPadStatuses"] + 5, -70, "b")
        m.pad(0x40)
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 940)
        m.write(m.sym["gPadStatuses"] + 5, 70, "b")
        m.pad()  # C-stick without L does not edit the swim surface.
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 940)
        m.pad(0x60)  # Adding R also suppresses water adjustment.
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 940)
        m.toggle("FREE MOVE", 1)
        m.pad(0x64, 4)  # L+R+Down only opens menu.
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)

    def test_free_move_facing_relative_motion_and_input_priority(self):
        m = self.m
        m.pad()
        m.toggle("FREE MOVE", 1)
        m.toggle("AUTO ROLL", 1)
        m.toggle("SWIM ANYWHERE", 1)
        m.write(m.sym["swimActive"], 1, "B")
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.calls[-1][0], "playerUpdate")
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)
        m.pad(0x48)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        # Facing -Z, regardless of where the retail camera used to look.
        m.write(m.sym["gCameras"], 16384, "h")
        m.write(m.sym["gPadStatuses"] + 2, 40, "b")
        m.write(m.sym["gPadStatuses"] + 3, 40, "b")
        m.pad(0x400, 0x400)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
        m.calls.clear()
        m.call("Practice_PlayerUpdate", m.player)
        for k, value in zip((0xc, 0x10, 0x14), (25 / 13, 0, -25 / 13)):
            self.assertAlmostEqual(m.read(m.player + k, "f"), value, places=4)
        self.assertFalse(any(c[0] == "playerUpdate" for c in m.calls))
        m.call("Practice_PlayerHitDetection", m.player)
        self.assertFalse(any(c[0] == "playerDoHitDetection" for c in m.calls))
        for yaw, expected in ((-32768, (-5, 0, 5)), (16384, (-5, 0, -5)), (-16384, (5, 0, 5))):
            m.write(m.sym["freeYaw"], yaw, "h")
            m.write(m.sym["gPadStatuses"] + 2, 40, "b")
            m.write(m.sym["gPadStatuses"] + 3, 40, "b")
            m.pad(0xc00, 0xc00)
            for axis, value in enumerate(expected):
                self.assertAlmostEqual(m.read(m.sym["freeStep"] + axis * 4, "f"), value * 5 / 13, places=4)
        m.pad()
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.calls[-1][0], "playerUpdate")
        m.call("Practice_PlayerHitDetection", m.player)
        self.assertEqual(m.calls[-1][0], "playerDoHitDetection")

    def test_free_move_look_turns_in_place_and_pitch_changes_forward_axis(self):
        m = self.m
        m.pad()
        m.write(m.player + 2, 123, "h")
        m.write(m.player + 4, -456, "h")
        m.toggle("FREE MOVE", 1)
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("INVERT X"), "B"), 1)
        for inverted in (1, 0):
            m.toggle("INVERT X", inverted)
            for shoulders in (0, 0x40):
                for stick in (-59, 59):
                    m.write(m.sym["freeYaw"], 0, "h")
                    m.write(m.sym["gPadStatuses"] + 4, stick, "b")
                    m.pad(shoulders)
                    self.assertEqual(m.read(m.sym["freeYaw"], "h"),
                                     (364 if stick > 0 else -364) * (1 if inverted else -1))
                    self.assertEqual(m.read(m.sym["freePitch"], "h"), 0)
        m.write(m.sym["freeYaw"], 0, "h")
        m.write(m.sym["gPadStatuses"] + 4, 59, "b")
        m.pad()
        m.write(m.sym["gPadStatuses"] + 5, 59, "b")
        m.pad(0x40)
        self.assertEqual(m.read(m.sym["freeYaw"], "h"), -364)
        self.assertEqual(m.read(m.sym["freePitch"], "h"), 364)
        self.assertEqual(bytes(m.uc.mem_read(m.sym["freeStep"], 12)), bytes(12))
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual([m.read(m.player + k, "h") for k in (0, 2, 4)], [-364, 364, 0])
        # Unmodified C-stick swivels while moving vertically, without pitching.
        for frame, (height, expected) in enumerate(((59, 5), (-59, -5), (20, 0)), 2):
            m.write(m.sym["gPadStatuses"] + 4, 59, "b")
            m.write(m.sym["gPadStatuses"] + 5, height, "b")
            m.pad()
            self.assertEqual([m.read(m.sym[name], "h") for name in ("freeYaw", "freePitch")], [-364 * frame, 364])
            self.assertEqual(struct.unpack(">3f", m.uc.mem_read(m.sym["freeStep"], 12)), (0, expected, 0))
        # A 45-degree heading/pitch moves diagonally upward; strafe stays level.
        m.write(m.sym["freeYaw"], -8192, "h")
        m.write(m.sym["freePitch"], 8192, "h")
        m.write(m.sym["gPadStatuses"] + 3, 72, "b")
        m.pad()
        for axis, value in enumerate((2.5, 5 / math.sqrt(2), -2.5)):
            self.assertAlmostEqual(m.read(m.sym["freeStep"] + axis * 4, "f"), value, places=4)
        m.write(m.sym["gPadStatuses"] + 2, 46, "b")  # Half-speed strafe.
        m.pad()
        self.assertAlmostEqual(m.read(m.sym["freeStep"], "f"), 2.5 / math.sqrt(2), places=4)
        self.assertEqual(m.read(m.sym["freeStep"] + 4, "f"), 0)
        m.write(m.sym["freePitch"], 0x37ff, "h")
        m.write(m.sym["gPadStatuses"] + 5, 127, "b")
        m.pad(0x40)
        self.assertEqual(m.read(m.sym["freePitch"], "h"), 0x3800)
        m.pad(0x64, 4)  # Opening the menu freezes look input.
        m.write(m.sym["gPadStatuses"] + 4, 59, "b")
        m.write(m.sym["gPadStatuses"] + 5, -59, "b")
        m.pad()
        self.assertEqual(m.read(m.sym["freeYaw"], "h"), -8192)
        self.assertEqual(m.read(m.sym["freePitch"], "h"), 0x3800)
        m.pad(0x200, 0x200)
        m.pad()
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["freePoseOwner"]), 0)
        self.assertEqual([m.read(m.player + k, "h") for k in (2, 4)], [123, -456])

    def test_swim_and_free_move_are_mutually_exclusive(self):
        m = self.m
        m.pad()
        m.toggle("SWIM ANYWHERE", 1)
        m.toggle("FREE MOVE", 1)
        m.pad(0x44, 4)
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.sym["swimApplied"], "B"), 1)
        m.pad()
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.sym["swimApplied"], "B"), 0)
        surface = m.read(m.sym["waterHeight"], "f")
        m.write(m.sym["gPadStatuses"] + 5, 59, "b")
        m.pad(0x40)  # L+C pitches Free Move; it cannot also edit swim height.
        self.assertGreater(m.read(m.sym["freePitch"], "h"), 0)
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), surface)
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["freePoseOwner"]), 0)
        surface = m.read(m.sym["waterHeight"], "f")  # Re-captured after moving.
        m.write(m.sym["gPadStatuses"] + 5, 59, "b")
        pitch = m.read(m.sym["freePitch"], "h")
        m.pad(0x40)  # In swimming the same chord only changes water height.
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), surface + 2)
        self.assertEqual(m.read(m.sym["freePitch"], "h"), pitch)
        m.pad(0x48, 8)
        m.toggle("SWIM ANYWHERE", 0)
        m.pad()
        m.pad(0x64, 4)
        m.pad()
        m.pad(0x20, 0x20)  # Cheats tab starts with Free Move and Invert X.
        m.write(m.sym["selected"], 4)  # Swim Anywhere, after health/magic and enabled Free Move.
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("SWIM ANYWHERE"), "B"), 1)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)  # Checkbox only arms the shortcut.
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), surface + 2)
        m.pad(0x200, 0x200)
        m.pad()
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)  # Closing the menu does not start swimming.
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["freePoseOwner"]), 0)

    def test_free_move_camera_follows_target_and_releases_to_retail(self):
        m = self.m
        m.call("__init_registers")
        m.pad()
        m.toggle("FREE MOVE", 1)
        m.pad(0x48, 8)
        m.uc.mem_write(m.player + 0x18, struct.pack(">3f", 1000, 200, -300))
        camera = m.sym["gCameras"]
        m.call("Practice_CameraLoadPos")
        self.assertEqual(struct.unpack(">3f", m.uc.mem_read(camera + 0xc, 12)), (1000, 225, -120))
        self.assertEqual(struct.unpack(">3f", m.uc.mem_read(camera + 0x44, 12)), (1000, 225, -120))
        self.assertEqual(m.read(camera, "h"), -32768)
        self.assertEqual(m.camera_load, (1000, 225, -120))
        m.write(m.sym["freeYaw"], -16384, "h")
        m.write(m.sym["freePitch"], 8192, "h")
        m.call("Practice_CameraLoadPos")
        expected = (1000 - 180 / math.sqrt(2), 225 - 180 / math.sqrt(2), -300)
        for actual, value in zip(m.camera_load, expected):
            self.assertAlmostEqual(actual, value, places=3)
        self.assertEqual([m.read(camera + k, "h") for k in (0, 2, 4)], [-16384, -8192, 0])
        snapshot = bytes(m.uc.mem_read(camera, 0x60))
        # Ordinary camera, loading, scripted focus, and secondary views are never overridden.
        for flag in ("disabled", "loading", "focus", "secondary"):
            m.write(m.sym["freeActive"], flag != "disabled", "B")
            m.save_loading = flag == "loading"
            m.write(m.state + 0x7f0, 0x81122000 if flag == "focus" else 0)
            m.write(m.sym["gCameraCurrentViewIndex"], flag == "secondary", "B")
            m.call("Practice_CameraLoadPos")
            self.assertEqual(bytes(m.uc.mem_read(camera, 0x60)), snapshot)
            self.assertEqual(m.camera_load[0], 1.0)
            m.write(m.state + 0x7f0, 0)

    def test_map_cells_use_retail_bounds_all_layers_and_preserve_state(self):
        m = self.m
        # Initialize retail r2/r13 so the real isInBounds can read its globals/constants.
        m.call("__init_registers")
        tables = 0x81120000
        m.uc.mem_write(tables, b'\xff' * (5 * 256))
        for layer in range(5):
            m.write(m.sym["gMapBlockLayerTables"] + layer * 4, tables + layer * 256)
        m.write(tables + 4 * 256, 0, "b")  # Occupancy on layer five counts even with no mesh.
        m.write(m.sym["gMapBlockOriginX"], -2, "i")
        m.write(m.sym["gMapBlockOriginZ"], -1, "i")
        m.write(m.sym["playerMapOffsetX"], -1280, "f")
        m.write(m.sym["playerMapOffsetZ"], -640, "f")
        m.uc.mem_write(m.sym["origin"], struct.pack(">3f", -960, 100, -320))
        before = bytes(m.uc.mem_read(tables, 5 * 256))
        m.call("drawMapCells")
        self.assertEqual(bytes(m.uc.mem_read(tables, 5 * 256)), before)
        colors = {v[3] for _, _, vertices in m.geometry for v in vertices}
        self.assertTrue({0x58d98c30, 0xff657830, 0xe4b45a30, 0xffd16aff} <= colors)
        green = [v for _, _, vertices in m.geometry for v in vertices if v[3] == 0x58d98c30]
        self.assertEqual({v[0] for v in green}, {0, 640})
        self.assertEqual({v[2] for v in green}, {0, 640})
        self.assertEqual({v[1] for v in green}, {102})
        self.assertEqual(m.read(m.sym["enabled"] + m.row("MAP CELLS / GRAVITY"), "B"), 0)
        m.geometry.clear()
        m.save_loading = 1
        m.call("drawMapCells")
        self.assertFalse(m.geometry)
        m.save_loading = 0
        m.write(m.sym["gMapBlockLayerTables"], 0)
        m.call("drawMapCells")
        self.assertFalse(m.geometry)

    def test_free_move_parent_transform_pause_load_and_player_change(self):
        m = self.m
        m.pad()
        m.toggle("FREE MOVE", 1)
        m.pad(0x48, 8)
        parent = 0x81120000
        m.write(parent, 16384, "h")
        m.write(m.player + 0x30, parent)  # ObjAnimComponent.parent.
        m.write(m.sym["freeStep"], 5.0, "f")
        m.call("Practice_PlayerUpdate", m.player)
        transforms = [c for c in m.calls if c[0] == "Obj_TransformWorldVectorToLocal"]
        self.assertTrue(transforms)
        self.assertEqual(m.read(m.player + 0x14, "f"), -5)
        self.assertEqual(m.read(m.player, "h"), -16384)  # Keep facing world -Z on the rotated parent.
        m.pad(0x64, 4)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(bytes(m.uc.mem_read(m.sym["freeStep"], 12)), bytes(12))
        m.pad()
        m.pad(0x200, 0x200)
        m.write(m.sym["joypadDisabled"], 1, "B")
        m.pad()
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.write(m.sym["joypadDisabled"], 0, "B")
        m.pad(0x48, 8)
        m.save_loading = 1
        m.pad()
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.save_loading = 0
        m.pad(0x48, 8)
        m.player += 0x4000
        m.pad()
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("FREE MOVE"), "B"), 1)

    def test_free_move_rebuilds_retail_collision_sweeps_at_destination(self):
        m = self.m
        m.call("__init_registers")
        del m.stub[m.sym["playerRefreshCollisionState"]]
        m.pad()
        m.toggle("FREE MOVE", 1)
        m.pad(0x48, 8)
        collision, points, hits = m.state + 4, 0x81120000, 0x81121000
        m.write(m.player + 0x54, hits)
        m.write(collision, 0x04002008)  # Active segment and local collision points.
        m.write(collision + 4, points)
        m.write(collision + 0xdc, points)
        m.write(collision + 0x25c, 0x11, "B")
        m.write(collision + 0xa8, 2.0, "f")
        m.write(collision + 0xd8, 0x81123000)  # Stale contact object.
        m.write(collision + 0x260, 0x33, "B")
        m.uc.mem_write(m.sym["freeStep"], struct.pack(">3f", 3000, 120, -1500))
        m.call("Practice_PlayerUpdate", m.player)
        destination = (3000, 120, -1500)
        for address in (m.player + 0xc, m.player + 0x18, m.player + 0x80, m.player + 0x8c,
                        hits + 0x10, hits + 0x1c, collision + 8, collision + 0xe4):
            self.assertEqual(struct.unpack(">3f", m.uc.mem_read(address, 12)), destination)
        self.assertEqual(m.read(collision + 0x38, "f"), 3000)
        self.assertAlmostEqual(m.read(collision + 0x3c, "f"), 122.1, places=4)
        self.assertEqual(m.read(collision + 0x40, "f"), -1500)
        self.assertEqual(m.read(collision + 0x118, "f"), 121)
        self.assertEqual(m.read(collision + 0xd8), 0)
        self.assertEqual(m.read(collision + 0x260, "B"), 0)
        self.assertTrue(any(c[0] == "trackInvalidateDynamicSlotsForObject" for c in m.calls))
        m.pad()
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.call("Practice_PlayerUpdate", m.player)
        m.call("Practice_PlayerHitDetection", m.player)
        self.assertEqual(struct.unpack(">3f", m.uc.mem_read(collision + 8, 12)), destination)
        self.assertEqual(m.calls[-1][0], "playerDoHitDetection")

    def test_infinite_resources_restore_capacities_and_guard_lethal_damage(self):
        m = self.m
        m.state_fixture()
        m.toggle("INFINITE HEALTH", 1)
        m.toggle("INFINITE MAGIC", 1)
        m.spend_resources = True
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.stats, "b"), 16)
        self.assertEqual(m.read(m.stats + 4, "h"), 100)
        # Real retail health subtraction must not enter the death routine at zero.
        m.write(m.state + 0x35c, m.stats)
        insn = m.read(m.sym["getCurMapLayer"])
        delta = struct.unpack(">h", struct.pack(">H", insn & 0xffff))[0]
        m.uc.reg_write(UC_PPC_REG_0 + 13, m.sym["curMapLayer"] - delta)
        for edit in make_patch(self.dol, self.payload, self.exports)["edits"]:
            if "hook" in edit:
                m.uc.mem_write(edit["address"], bytes.fromhex(edit["after"]))
        m.calls.clear()
        m.call("playerAddHealth", m.player, (-100) & 0xffffffff)
        self.assertEqual(m.read(m.stats, "b"), 16)
        self.assertFalse(any(c[0] == "playerDie" for c in m.calls))
        # Death without depleted health is scripted/void behavior, not HP loss.
        m.call("Practice_PlayerDie", m.player)
        self.assertEqual(m.calls[-1][0], "playerDie")
        m.toggle("INFINITE HEALTH", 0)
        m.toggle("INFINITE MAGIC", 0)
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.stats, "b"), 1)
        self.assertEqual(m.read(m.stats + 4, "h"), 0)
        m.call("playerAddHealth", m.player, (-100) & 0xffffffff)
        self.assertEqual(m.calls[-1][0], "playerDie")
        m.toggle("INFINITE HEALTH", 1)
        m.toggle("INFINITE MAGIC", 1)
        m.save_loading = 1
        m.call("refillResources", m.player)
        self.assertEqual(m.read(m.stats, "b"), 0)
        self.assertEqual(m.read(m.stats + 4, "h"), 0)

    def test_trigger_boxes_spheres_and_cylinders(self):
        m = self.m
        definition, placement = 0x81100000, 0x81101000
        m.write(m.player + 0x50, definition)
        m.write(m.player + 0x4C, placement)
        m.write(definition + 0x50, 294, "h")
        m.uc.mem_write(placement + 0x3A, bytes([10, 20, 30]))
        m.toggle("TARGET MOTION", 0)
        for type_id, expected_lines, expected_fills in [(0x4D, 12, 12), (0x4B, 72, 224), (0x230, 52, 96)]:
            m.geometry = []
            m.write(placement, type_id, "H")
            m.call("drawTriggers", m.player)
            lines = [g for g in m.geometry if g[0] == 0xA8]
            fills = [g for g in m.geometry if g[0] == 0x90]
            self.assertEqual(len(lines), expected_lines)
            self.assertEqual(len(fills), expected_fills)
            self.assertTrue(all(len(g[2]) == 3 and all(p[3] & 255 == 0x30 for p in g[2]) for g in fills))
            m.toggle("TRANSLUCENT FILL", 0)
            m.geometry = []
            m.call("drawTriggers", m.player)
            self.assertEqual(len(m.geometry), expected_lines)
            m.toggle("TRANSLUCENT FILL", 1)
        m.write(definition + 0x50, 195, "h")
        m.geometry = []
        m.call("drawTriggers", m.player)
        self.assertFalse(m.geometry)

    def test_trigger_plane_inverts_world_to_local_matrix(self):
        m = self.m
        definition, placement = 0x81100000, 0x81101000
        m.write(m.player + 0x50, definition)
        m.write(m.player + 0x4C, placement)
        m.write(definition + 0x50, 294, "h")
        m.write(placement, 0x4C, "H")
        m.toggle("TARGET MOTION", 0)
        m.write(m.state + 0x34, 20.0, "f")
        m.write(m.state + 0x14, 1.0, "f")
        m.uc.mem_write(m.state + 0x38, struct.pack(">12f", 1, 0, 0, -10, 0, 1, 0, -100, 0, 0, 1, -30))
        m.call("drawTriggers", m.player)
        self.assertEqual(len(m.geometry), 7)
        self.assertEqual(m.geometry[0][2][0][:3], (-10, 80, 30))
        self.assertEqual(m.geometry[0][2][1][:3], (30, 80, 30))

    def test_debug_draw_preserves_retail_vertex_formats(self):
        m = self.m
        m.call("__init_registers")
        # Run the real retail format setter, which updates the persistent GX cache.
        del m.stub[m.sym["GXSetVtxAttrFmt"]]
        m.call("GXSetVtxAttrFmt", 7, 9, 1, 3, 0)  # Format 7: XYZ S16.
        m.call("GXSetVtxAttrFmt", 7, 11, 1, 3, 0)  # Format 7: RGBA4.
        m.call("GXSetVtxAttrFmt", 2, 9, 1, 4, 0)  # Format 2: XYZ F32.
        m.call("GXSetVtxAttrFmt", 2, 11, 1, 5, 0)  # Format 2: RGBA8.
        gx = symbols()["gxData"][0]
        before = bytes(m.uc.mem_read(gx + 0x1c, 8 * 4 * 3))
        for menu in (0, 1):
            m.write(m.sym["menuOpen"], menu, "B")
            m.calls.clear()
            m.call("Practice_Draw")
            self.assertEqual(bytes(m.uc.mem_read(gx + 0x1c, 8 * 4 * 3)), before)
            begins = [c for c in m.calls if c[0] == "GXBegin"]
            self.assertTrue(begins)
            self.assertTrue(all(c[2] == 2 for c in begins))

    def test_heap_bars_follow_region_chain(self):
        m = self.m
        start, size = 0x81300000, 0x10000
        slots = [(0x80, 0x1000, 1, 0x11, 1), (0x1080, 0x2000, 0, 0, 2), (0x3080, 0x20, 1, 0xFFFF00FF, 3),
                 (0x30A0, 0x20, 1, 0x7D7D7D7D, 4), (0x30C0, size - 0x30C0, 0, 0, -1)]
        for i, (offset, length, kind, tag, following) in enumerate(slots):
            m.uc.mem_write(start + i * 0x1C, struct.pack(">IIhhhhIII", start + offset, length, kind, i - 1, following,
                                                         i, tag, 0x1234, i))
        table = m.sym["gMmRegionTable"]
        m.uc.mem_write(table, struct.pack(">IIIII", len(slots), len(slots), start, size, 0x1040))
        m.write(m.sym["gMmRegionCount"], 1, "B")
        m.write(m.sym["menuOpen"], 0, "B")
        m.write(m.sym["enabled"] + m.row("HEAP BARS"), 1, "B")
        m.toggle("COLLISION", 0)
        m.toggle("TRIGGERS", 0)
        mask = 0xFFFFFFFF

        def mix(acc, value):
            acc = (acc + value * 0x85EBCA77) & mask
            acc = ((acc << 13) | (acc >> 19)) & mask
            return acc * 0x9E3779B1 & mask

        def finish(h):
            h ^= h >> 15
            h = h * 0x85EBCA77 & mask
            h ^= h >> 13
            h = h * 0xC2B2AE3D & mask
            return h ^ (h >> 16)

        expected = 0x9E3779B1
        for offset, length, kind, tag, _ in slots:
            if kind:
                expected = mix(mix(mix(expected, start + offset), length), tag)
        expected = finish(expected)

        def used_spans():
            m.geometry = []
            m.call("Practice_Draw")
            spans = [(g[2][0][0], g[2][1][0], g[2][0][3]) for g in m.geometry if g[2] and g[2][0][1] == 437]
            return [s for s in spans[2:] if s[0] < 270]  # Skip background, slot table and centred hash.

        # Category ids get a scattered colour; RGBA tags are used opaque; the
        # second block in pixel 121 is clipped away by the first owner.
        self.assertEqual(used_spans(), [(1, 42, (0x12 * 0x9E3779B1 & mask) | 0xFF), (121, 122, 0xFFFF00FF)])
        self.assertEqual(m.read(m.sym["heapLargestFree"]), size - 0x30C0)
        self.assertEqual(m.read(m.sym["heapHash"]), expected)
        backing = [g for g in m.geometry if g[2] and g[2][0][3] == 0x081020FF and g[2][0][1] == 437]
        self.assertEqual([(q[2][0][0], q[2][2][0], q[2][2][1]) for q in backing], [(270, 370, 447)])
        m.uc.mem_write(start + 8, struct.pack(">hhh", 1, -1, 1))  # Allocation ids and ticks are not hashed.
        m.write(start + 0x14, 0x9999)
        m.call("Practice_Draw")
        self.assertEqual(m.read(m.sym["heapHash"]), expected)
        m.write(start + 0x1C * 2 + 4, 0x40)  # Any size change moves the fingerprint.
        m.call("Practice_Draw")
        self.assertNotEqual(m.read(m.sym["heapHash"]), expected)
        m.write(start + 0x1C * 2 + 4, 0x20)
        m.uc.mem_write(start + 4 * 0x1C + 8, struct.pack(">hhh", 0, 3, 0))  # Corrupt chain loops back to slot 0.
        self.assertEqual(used_spans()[:2], [(1, 42, (0x12 * 0x9E3779B1 & mask) | 0xFF), (121, 122, 0xFFFF00FF)])

    def test_menu_geometry_and_preview(self):
        m = self.m
        m.pad(0x64, 4)
        for label in ["COLLISION", "TRIGGERS", "SWIM ANYWHERE"]:
            m.write(m.sym["expanded"] + m.row(label), 1, "B")
        m.call("Practice_Draw")
        self.assertGreater(len(m.geometry), 1000)
        self.assertTrue(all(g[1] == len(g[2]) for g in m.geometry))
        self.assertTrue(all(0 <= p[0] <= 640 and 0 <= p[1] <= 480 for g in m.geometry for p in g[2]))
        m.write(m.sym["selected"], 15)
        m.call("drawMenu")
        self.assertEqual(m.read(m.sym["menuTop"]), 1)
        m.geometry = []
        m.write(m.sym["selected"], 0)
        m.call("drawMenu")
        try:
            from PIL import Image, ImageDraw
        except ImportError:
            return
        picture = Image.new("RGB", (640, 480), (40, 50, 60))
        draw = ImageDraw.Draw(picture)
        for _, _, points in m.geometry:
            color = points[0][3]
            draw.polygon([(p[0], p[1]) for p in points], fill=((color >> 24) & 255, (color >> 16) & 255, (color >> 8) & 255))
        picture.save(OUT / "menu-geometry-preview.png")

    def test_terrain_packed_vertices_and_water_filter(self):
        m = self.m
        m.toggle("TERRAIN TRIANGLES", 1)
        m.block = 0x81100000
        m.blocks[0, 0, 0] = m.block
        group, vertices, tri = m.block + 0x1000, m.block + 0x2000, m.block + 0x3000
        for offset, address in [(0x4C, tri), (0x50, group), (0x58, vertices)]:
            m.write(m.block + offset, address)
        for offset, value in [(0x8E, 50), (0x90, 3), (0x98, 1), (0x9A, 1)]:
            m.write(m.block + offset, value, "H")
        m.uc.mem_write(vertices, struct.pack(">9h", 0, 80, 0, 80, 160, 0, 0, 240, 80))
        m.uc.mem_write(tri, struct.pack(">4H", 0, 1, 2, 0xFFFF))
        m.write(group + 0x14, 1, "H")
        m.call("drawTerrain")
        self.assertEqual(len(m.geometry), 3)
        self.assertEqual(m.geometry[0][2][0][:3], (0, 60, 0))
        self.assertEqual(m.geometry[0][2][1][:3], (10, 70, 0))
        m.geometry = []
        m.write(group + 0x10, 8)
        m.toggle("WATER TRIANGLES", 0)
        m.call("drawTerrain")
        self.assertFalse(m.geometry)
        m.toggle("WATER TRIANGLES", 1)
        m.call("drawTerrain")
        self.assertEqual(len(m.geometry), 3)

    def test_object_mesh_uses_forward_matrix_and_vertex_scale(self):
        m = self.m
        definition, banks, model, file = [0x81100000 + n * 0x1000 for n in range(4)]
        hit, group, vertices, tri = [0x81104000 + n * 0x1000 for n in range(4)]
        m.write(m.player + 0x50, definition)
        m.write(m.player + 0x58, hit)
        m.write(m.player + 0x7C, banks)
        m.write(definition + 0x55, 1, "B")
        m.write(banks, model)
        m.write(model, file)
        for off, value in [(0x28, vertices), (0x5C, tri), (0x60, group)]:
            m.write(file + off, value)
        m.write(file + 2, 0x800, "H")
        m.write(file + 0xE4, 3, "H")
        m.write(file + 0xF0, 1, "H")
        m.write(group + 0x14, 1, "H")
        m.uc.mem_write(vertices, struct.pack(">9h", 8, 16, 24, 80, 160, 0, 0, 240, 80))
        m.uc.mem_write(tri, struct.pack(">4H", 0, 1, 2, 0))
        matrix = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 10, 20, 30, 1]
        m.uc.mem_write(hit + 0x80, struct.pack(">16f", *matrix))
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 3)
        self.assertEqual(m.geometry[0][2][0][:3], (18, 36, 54))
        m.geometry = []
        m.write(file + 2, 0, "H")
        m.call("drawObjectCollision", m.player)
        self.assertEqual(m.geometry[0][2][0][:3], (10.03125, 20.0625, 30.09375))

    def test_terrain_uses_sentinel_masks_and_query_filters(self):
        m = self.m
        m.toggle("TERRAIN TRIANGLES", 1)
        block, group, vertices, tri = [0x81100000 + n * 0x1000 for n in range(4)]
        m.blocks[0, 0, 0] = block
        for off, addr in [(0x4C, tri), (0x50, group), (0x58, vertices)]:
            m.write(block + off, addr)
        for off, value in [(0x90, 3), (0x98, 2), (0x9A, 1)]:
            m.write(block + off, value, "H")
        m.write(group + 0x14, 1, "H")  # Last sentinel excludes a trailing triangle.
        m.uc.mem_write(vertices, struct.pack(">9h", -2400, 0, -2400, 2400, 0, -2400, 0, 0, 2400))
        m.uc.mem_write(tri, struct.pack(">8H", 0, 1, 2, 0xFFFF, 0, 1, 2, 0xFFFF))
        m.write(m.sym["drawDistance"], 250)  # All vertices outside; triangle crosses Fox.
        m.call("drawTerrain")
        self.assertEqual(len(m.geometry), 3)
        for mask in [0, 0xFF, 0xFF00]:
            m.geometry = []
            m.write(tri + 6, mask, "H")
            m.call("drawTerrain")
            self.assertFalse(m.geometry)
        m.write(tri + 6, 0xFFFF, "H")
        m.write(group + 0x10, 2)
        m.call("drawTerrain")
        self.assertEqual(len(m.geometry), 3)  # Fox's side query includes bit-2 groups.
        m.geometry = []
        m.toggle("WATER TRIANGLES", 1)
        m.write(group + 0x10, 9)  # Water with bit 1 never enters the retail query.
        m.call("drawTerrain")
        self.assertFalse(m.geometry)
        m.write(group + 0x10, 0)
        m.uc.mem_write(vertices, bytes(18))
        m.call("drawTerrain")
        self.assertFalse(m.geometry)  # Degenerate faces cannot collide.

    def test_barrier_heights_and_nearby_block_priority(self):
        m = self.m
        m.toggle("BARRIER FILL", 0)
        block, hits = 0x81100000, 0x81101000
        m.blocks[1, 1, 0] = block
        m.blocks[0, 0, 0] = block
        m.write(m.sym["origin"], 650.0, "f")
        m.write(m.sym["origin"] + 8, 650.0, "f")
        m.write(m.sym["lineLimit"], 4)
        m.write(block + 0x70, hits)
        m.write(block + 0x9C, 1, "H")
        m.uc.mem_write(hits, struct.pack(">6h4Bh2x", 0, 10, 20, 30, 0, 0, 0xF6, 40, 0, 1, 0))
        m.call("drawTerrain")  # No triangle buffers: HITS still has to draw.
        self.assertEqual(len(m.geometry), 4)
        self.assertEqual([g[2][0][:3] for g in m.geometry],
                         [(640, 20, 640), (650, 30, 640), (650, 70, 640), (640, 10, 640)])
        m.write(hits + 12, 300, "h")
        m.write(hits + 14, 0x80, "B")
        m.geometry = []
        m.write(m.sym["linesDrawn"], 0)
        m.call("drawTerrain")
        self.assertEqual(m.geometry[2][2][0][:3], (650, 330, 640))
        m.toggle("BARRIERS / LEDGES", 0)
        m.geometry = []
        m.write(m.sym["linesDrawn"], 0)
        m.call("drawTerrain")
        self.assertFalse(m.geometry)

    def test_model_barrier_without_triangle_mesh(self):
        m = self.m
        definition, hits = 0x81100000, 0x81101000
        m.write(m.player + 0x50, definition)
        m.write(definition + 0x30, hits)
        m.write(definition + 0x5C, 1, "B")
        m.uc.mem_write(hits, struct.pack(">6h4Bh2x", 0, 10, 20, 30, 0, 0, 10, 40, 0, 1, 0))
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 6)
        self.assertEqual(m.geometry[2][2][0][:3], (0, 120, 0))
        self.assertEqual(m.geometry[4][2][0][:3], (10, 170, 0))
        self.assertTrue(all(g[0] == 0x90 and all(p[3] & 255 == 0x30 for p in g[2]) for g in m.geometry[:2]))
        m.toggle("TRANSLUCENT FILL", 0)
        m.geometry = []
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 6)  # Independent of trigger fill.
        m.toggle("BARRIER FILL", 0)
        m.geometry = []
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 4)

    def test_tabs_defaults_and_hover_toggle(self):
        m = self.m
        for label in ("TERRAIN TRIANGLES", "WATER TRIANGLES", "DRAW THROUGH WALLS", "FOX / PLAYER", "SWIM ANYWHERE", "AUTO-SHIELD HOVER"):
            self.assertEqual(m.read(m.sym["enabled"] + m.row(label), "B"), 0)
        for label in ("COLLISION", "TRIGGERS", "OBJECT TRIANGLES", "OBJECT HIT VOLUMES", "BARRIERS / LEDGES", "BARRIER FILL", "TRANSLUCENT FILL"):
            self.assertEqual(m.read(m.sym["enabled"] + m.row(label), "B"), 1)
        m.pad(0x64, 4)
        m.call("rebuildRows")
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
        self.assertEqual(m.read(m.sym["visibleCount"]), 18)
        m.pad()
        m.pad(0x20, 0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        self.assertEqual(m.read(m.sym["visibleCount"]), 7)
        self.assertEqual(m.read(m.sym["visible"], "B"), m.row("INFINITE HEALTH"))
        self.assertEqual(m.read(m.sym["visible"] + 1, "B"), m.row("INFINITE MAGIC"))
        self.assertEqual(m.read(m.sym["visible"] + 2, "B"), m.row("FREE MOVE"))
        self.assertEqual(m.read(m.sym["visible"] + 3, "B"), m.row("SWIM ANYWHERE"))
        self.assertEqual(m.read(m.sym["enabled"] + m.row("INVERT X"), "B"), 1)
        m.pad(0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)  # Holding R does not repeat tabs.
        m.write(m.sym["selected"], 2)
        m.pad(0x100, 0x100)  # Free Move reveals its retained Invert X option.
        m.pad()
        self.assertEqual(m.read(m.sym["visibleCount"]), 8)
        self.assertEqual(m.read(m.sym["visible"] + 3, "B"), m.row("INVERT X"))
        m.pad(0x100, 0x100)
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 5)  # Wrap left to Debug.
        self.assertEqual(m.read(m.sym["visibleCount"]), 1)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 4)
        self.assertEqual(m.read(m.sym["visibleCount"]), 10)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 3)
        self.assertEqual(m.read(m.sym["visibleCount"]), 8)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 2)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        m.write(m.sym["selected"], 4)  # Hover; disabled groups hide their children.
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("AUTO-SHIELD HOVER"), "B"), 1)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)  # Menu wins over automation.
        m.pad(0x200, 0x200)
        m.pad()
        self.assertEqual(m.read(m.sym["gPadTriggers"], "H") & 0x20, 0)
        m.pad(0x20, 0x20)
        self.assertEqual(m.read(m.sym["gPadTriggers"], "H") & 0x20, 0x20)

    def test_hover_alternates_edges_preserves_steering_and_releases(self):
        m = self.m
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.write(m.sym["rollBlanks"], 0)
        m.write(m.sym["gPadStatuses"] + 2, 40, "b")
        for frame in range(6):
            m.pad(0xc20, 0x420 if frame == 0 else 0)  # Hold X+R; Y remains available.
            action = 0x20 if frame % 2 == 0 else 0x400
            previous = 0 if frame == 0 else (0x400 if frame % 2 == 0 else 0x20)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800 | action)
            self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]) & 0x420, action)
            self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, previous)
            self.assertEqual(m.read(m.sym["gPadTriggers"], "H") & 0x20, action & 0x20)
            self.assertEqual(m.read(m.sym["gPadStatuses"] + 7, "B"), 255 if action == 0x20 else 0)
            self.assertEqual(m.read(m.sym["gPadStatuses"] + 2, "b"), 40)
            self.assertEqual(m.read(m.sym["gPadButtonsPrevious"]), 0xc20)
        m.pad(0x800)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800)
        self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, 0x400)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
        m.pad(0x800)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800)
        for blocker in ("timeStop", "gDvdErrorPauseActive", "joypadDisabled"):
            m.write(m.sym[blocker], 1, "B")
            m.pad(0x420)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x420)
            self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
            self.assertEqual(m.read(m.sym["hoverPhase"], "B"), 0)
            m.write(m.sym[blocker], 0, "B")
        m.pad(0x20)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x20)

    def test_hover_release_resets_gaps_and_disabled_restores_physical_input(self):
        m = self.m
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.write(m.sym["shieldBlanks"], 3)
        for release_after in (1, 2, 5):  # Shield, blank, and roll frames.
            for frame in range(release_after):
                m.pad(0x420, 0x420 if frame == 0 else 0)
            previous = m.read(m.sym["gPadButtonsHeld"]) & 0x420
            m.pad()
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
            self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, previous)
            self.assertEqual(m.read(m.sym["hoverWait"]), 0)
            self.assertEqual(m.read(m.sym["hoverPhase"], "B"), 0)
            m.pad()
            self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]), 0)
        m.pad(0x420, 0x420)
        m.pad(0x420)  # Blank frame suppresses physical X+R.
        m.toggle("AUTO-SHIELD HOVER", 0)
        m.pad(0x420)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x420)
        self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]), 0x420)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.pad(0x400, 0x400)  # Hold X before an analog-only R press.
        m.write(m.sym["gPadTriggers"], 0x20, "H")
        m.write(m.sym["gPadTriggersPressed"], 0x20, "H")
        m.call("Practice_PadUpdate")
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x20)

    def test_world_depth_default_and_no_depth_writes(self):
        m = self.m
        self.assertEqual(m.read(m.sym["enabled"] + m.row("DRAW THROUGH WALLS"), "B"), 0)
        m.call("drawWorld")
        self.assertIn(("GXSetZMode", 1, 3, 0), m.calls)
        m.calls = []
        m.toggle("DRAW THROUGH WALLS", 1)
        m.call("drawWorld")
        self.assertIn(("GXSetZMode", 0, 3, 0), m.calls)

    def test_warp_navigation_defaults_and_explicit_action(self):
        m = self.m
        m.pad(0x64, 4)
        m.pad()
        m.pad(0x20, 0x20)  # Collision -> Cheats -> Warp.
        m.pad()
        m.pad(0x20, 0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 2)
        self.assertEqual(m.read(m.sym["visibleCount"]), 11)
        self.assertEqual(m.read(m.sym["visible"] + 3, "B"), m.row("WARP NOW"))
        destination = m.sym["warpDestination"]
        default = bytes(m.uc.mem_read(destination, 16))
        self.assertEqual(m.read(m.sym["warpMap"]), 7)
        self.assertAlmostEqual(m.read(destination, "f"), -5541.40576171875)
        m.write(m.sym["selected"], 4)
        m.pad(2, 2)
        self.assertEqual(m.read(destination, "f"), struct.unpack(">f", default[:4])[0] + 10)
        self.assertEqual(m.read(m.sym["warpEdited"], "B"), 1)
        m.write(m.sym["selected"], 2)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["warpSpawn"]), 1)
        self.assertEqual(m.read(m.sym["warpEdited"], "B"), 0)
        self.assertEqual(m.read(destination + 4, "f"), -636.2503051757812)
        m.write(m.sym["selected"], 1)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["warpMap"]), 8)
        self.assertEqual(m.read(m.sym["warpSpawn"]), 0)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        # Browsing object chunks shows unavailable entries, without issuing warps.
        m.write(m.sym["selected"], 0)
        m.write(m.sym["warpCategory"], 8)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["warpMap"]), 75)
        m.write(m.sym["selected"], 3)
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        for mid in (55, 64):  # Duster Cave softlocks; Nik Test deadlocks.
            m.write(m.sym["warpMap"], mid)
            m.call("resetWarpSpawn")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
            self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        # Resetting the map restores the preset, including Y/layer/facing.
        m.write(m.sym["warpMap"], 7)
        m.write(m.sym["warpSpawn"], 0)
        m.call("resetWarpSpawn")
        self.assertEqual(bytes(m.uc.mem_read(destination, 16)), default)
        m.write(m.sym["warpMap"], 27)  # User-provided DIM Bottom arrival.
        m.call("resetWarpSpawn")
        self.assertEqual(bytes(m.uc.mem_read(destination, 16)),
                         struct.pack(">3f2h", -8974.73438, -1627.60266, 17620.2559, -2, 0))

    def test_warp_validates_world_cells_and_uses_retail_transition(self):
        m = self.m
        m.write(m.sym["warpMap"], 23)
        bounds, layers, cells = 0x81100000, 0x81101000, 0x81102000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        m.uc.mem_write(layers, bytes([127]) * 128)
        m.uc.mem_write(bounds + 23 * 10, struct.pack(">4h2b", 5, 5, 6, 6, 0, 0))
        m.write(layers + 23, 0, "b")
        m.write(cells + 23 * 64, 1, "B")
        m.call("resetWarpSpawn")
        m.write(m.sym["menuOpen"], 1, "B")
        m.write(m.sym["timeStop"], 255, "B")
        m.write(m.sym["warpDestination"], 0.0, "f")
        m.call("requestPracticeWarp", m.player)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        m.call("resetWarpSpawn")
        m.call("requestPracticeWarp", m.player)
        self.assertIn(("warpToMap", 2, 1, m.calls[-1][3]), m.calls)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 0)
        self.assertEqual(m.read(m.sym["gPendingWarpIndex"], "h"), 2)
        self.assertEqual(bytes(m.uc.mem_read(m.sym["gRcpPendingWarpDest"], 16)),
                         bytes(m.uc.mem_read(m.sym["warpDestination"], 16)))
        m.write(m.sym["gWarpRequested"], 0, "B")
        m.write(m.sym["warpEdited"], 1, "B")
        m.call("requestPracticeWarp", m.player)
        self.assertEqual(m.read(m.sym["gPendingWarpIndex"], "h"), 128)
        # Negative coordinates must floor toward -infinity, not truncate to zero.
        m.uc.mem_write(bounds + 7 * 10, struct.pack(">4h2b", -9, -9, -2, -2, 0, 0))
        m.write(layers + 7, 0, "b")
        m.write(cells + 7 * 64, 1, "B")
        m.write(m.sym["warpMap"], 7)
        m.write(m.sym["warpSpawn"], 1)  # Egg Room follows the default Arwing arrival.
        m.call("resetWarpSpawn")
        m.call("warpDestinationMap")
        self.assertEqual(m.r(3), 7)

    def test_warp_categories_follow_progression_and_wrap_both_ways(self):
        m = self.m
        for category, expected in ((1, [7, 8, 51, 23, 56, 10, 67, 69, 18, 70, 4, 71, 14, 72, 29, 73, 50, 21]),
                                   (2, [19, 68, 27, 12, 16, 13, 2, 11]),
                                   (4, [28, 43, 48, 44, 40]),
                                   (5, [41, 59, 60, 61, 62, 38]),
                                   (6, [0, 65, 9, 51, 54, 66]),
                                   (7, [52, 26, 74])):
            m.write(m.sym["warpCategory"], category - 1)
            m.call("editWarpRow", m.row("CATEGORY"), 1)
            for mid in expected:
                self.assertEqual(m.read(m.sym["warpMap"]), mid)
                m.call("changeWarpMap", 1)
            self.assertEqual(m.read(m.sym["warpMap"]), expected[0])
            for mid in reversed(expected):
                m.call("changeWarpMap", -1)
                self.assertEqual(m.read(m.sym["warpMap"]), mid)
        m.write(m.sym["warpCategory"], 5)
        m.call("editWarpRow", m.row("CATEGORY"), 1)
        self.assertEqual(m.read(m.sym["warpCategory"]), 6)
        self.assertEqual(m.read(m.sym["warpMap"]), 0)  # Special starts with Ship Battle.
        m.write(m.sym["warpCategory"], 9)
        m.call("editWarpRow", m.row("CATEGORY"), 1)
        self.assertEqual(m.read(m.sym["warpCategory"]), 0)
        visited = []
        for _ in range(117):
            visited.append(m.read(m.sym["warpMap"]))
            m.call("changeWarpMap", 1)
        self.assertEqual(sorted(visited), list(range(117)))
        self.assertEqual(m.read(m.sym["warpMap"]), visited[0])
        m.call("editWarpRow", m.row("CATEGORY"), -1)
        self.assertEqual(m.read(m.sym["warpCategory"]), 9)
        self.assertEqual(m.read(m.sym["warpMap"]), 75)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))

    def test_player_movement_shapes_toggles_and_parent_space(self):
        m = self.m
        m.toggle("FOX / PLAYER", 1)
        c = m.state + 4
        m.write(c, 0x04002009)
        m.write(c + 0x25C, 0x21, "B")
        m.uc.mem_write(c + 8, struct.pack(">6f", 0, 100, 0, 0, 117, 0))
        m.write(c + 0xA8, 0.05, "f")
        m.write(c + 0xAC, 8.5, "f")
        m.write(c + 0x1F0, -100000.0, "f")
        radii = 0x81100000
        m.write(c + 0xE0, radii)
        m.write(radii, 8.5, "f")
        m.uc.mem_write(c + 0xE4, struct.pack(">3f", 2, 105, 3))
        m.toggle("CACHED SWEEP LINES", 0)
        m.call("drawPlayerCollision", m.player)
        self.assertEqual(len(m.geometry), 218)  # Three real spheres plus tiny-ground marker.
        for label, expected in (("FEET / FLOOR CONTACT", 144), ("MOVEMENT BODY SPHERES", 72), ("WALL PROBE SPHERES", 0)):
            m.geometry = []
            m.toggle(label, 0)
            m.call("drawPlayerCollision", m.player)
            self.assertEqual(len(m.geometry), expected)
        parent = 0x81200000
        m.write(m.player + 0x30, parent)  # Canonical ObjAnimComponent.parent.
        m.write(parent + 0x18, 100.0, "f")
        m.write(parent + 0x20, 200.0, "f")
        m.toggle("WALL PROBE SPHERES", 1)
        m.call("drawPlayerCollision", m.player)
        self.assertEqual(m.geometry[0][2][0][:3], (102, 113.5, 203))
        m.geometry = []
        m.write(c, 0)
        m.call("drawPlayerCollision", m.player)
        self.assertFalse(m.geometry)

    def test_player_collision_draws_without_collision_group(self):
        m = self.m
        m.toggle("FOX / PLAYER", 1)
        m.toggle("COLLISION", 0)
        m.toggle("TRIGGERS", 0)
        m.toggle("CACHED SWEEP LINES", 0)
        c = m.state + 4
        m.write(c, 0x04002009)
        m.write(c + 0x25C, 0x21, "B")
        m.uc.mem_write(c + 8, struct.pack(">6f", 0, 100, 0, 0, 117, 0))
        m.write(c + 0xA8, 0.05, "f")
        m.write(c + 0xAC, 8.5, "f")
        m.write(c + 0x1F0, -100000.0, "f")
        radii = 0x81100000
        m.write(c + 0xE0, radii)
        m.write(radii, 8.5, "f")
        m.uc.mem_write(c + 0xE4, struct.pack(">3f", 2, 105, 3))
        m.call("Practice_Draw")
        with_fox = len(m.geometry)
        m.geometry = []
        m.toggle("FOX / PLAYER", 0)
        m.call("Practice_Draw")
        self.assertEqual(with_fox - len(m.geometry), 218)

    def test_practice_warp_queues_destination_banks_only_at_committed_reload(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0xa82, 260, 1, 2)
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 68 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 27 * 2, 0x302, "H")
        m.bit_def(0x302, 40, 32, 1)
        m.calls = []
        # Ordinary game warps must retain their existing loading behavior.
        m.call("Practice_WarpReload")
        self.assertEqual([c[0] for c in m.calls], ["mapReload"])
        # Include all five Krazoa tests as well as Galdon and Andross flight.
        for map_id, layer in ((28, -2), (38, 2), (65, 0), (31, 0), (32, 0), (33, 0), (34, 0), (39, 0), (68, -1), (27, -2)):
            m.calls = []
            m.write(m.sym["warpMap"], map_id)
            m.call("resetWarpSpawn")
            destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
            m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
            m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
            m.write(m.sym["warpLoadPending"], 1, "B")
            # Result of retail mapSetup inside the stubbed mapLoadByCoords.
            m.write(m.sym["gGameLoopPendingMapId"], map_id)
            m.call("Practice_WarpReload")
            self.assertEqual([c[0] for c in m.calls[:2]], ["unlockLevel", "mapLoadByCoords"])
            self.assertEqual([c[:3] for c in m.calls[2:]],
                             [("SaveGame_gplaySetObjGroupStatus", map_id, bit)
                              for bit in ({68: [1], 27: [0]}.get(map_id, []))] +
                             [("mainSetBits", 0xa82 if map_id in (28, 68, 27) else 0x956, 1)])
            self.assertEqual(m.calls[0][1:], (0, 0, 1))
            self.assertEqual(m.loaded_coordinates[:3], struct.unpack(">3f", destination[:12]))
            self.assertEqual(m.loaded_coordinates[3], layer & 0xffffffff)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"),
                             {68: 26, 38: 15, 65: 15}.get(map_id, -1))
            self.assertEqual(m.read(m.sym["warpLoadPending"], "B"), 0)
        # If a normal scripted warp supersedes our request, don't change its banks.
        m.calls = []
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.write(m.sym["gRcpPendingWarpDest"], 0.0, "f")
        m.call("Practice_WarpReload")
        self.assertEqual([c[0] for c in m.calls], ["mapReload"])
        self.assertEqual(m.read(m.sym["warpLoadPending"], "B"), 0)

    def test_arrival_groups_preserve_progress_and_only_apply_to_committed_practice_warp(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 29 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 29 * 2, 0x300, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 10 * 2, 0x302, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 56 * 2, 0x302, "H")
        m.bit_def(0x302, 40, 32, 1)
        m.write(m.sym["warpMap"], 29)
        m.call("resetWarpSpawn")
        group_bit = m.read(m.sym["gSaveGameMapObjGroupBits"] + 29 * 2, "H")
        act_bit = m.read(m.sym["gSaveGameMapActBits"] + 29 * 2, "H")
        m.set_bit(group_bit, 1 << 7)  # Existing room/progress state must survive.
        m.set_bit(act_bit, 2)
        m.write(m.sym["menuOpen"], 1, "B")
        m.write(m.sym["timeStop"], 255, "B")
        # Browsing and editing the preset cannot change persistent groups.
        m.call("editWarpRow", m.row("SPAWN"), 1)
        self.assertEqual(m.bit_value(group_bit), 1 << 7)
        destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
        m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
        m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.write(m.sym["gGameLoopPendingMapId"], 29)
        m.call("Practice_WarpReload")
        expected = (1 << 7) | (1 << 31) | 0x13  # Entry 0/1/4/31 + prior group 7.
        self.assertEqual(m.bit_value(group_bit), expected)
        self.assertEqual(m.read(m.sym["gMapObjGroupStatuses"] + 29 * 4), expected)
        self.assertEqual(m.bit_value(act_bit), 2)
        # A retail reload, or a superseding scripted warp, cannot apply defaults.
        for pending in (0, 1):
            m.set_bit(group_bit, 0)
            m.write(m.sym["warpLoadPending"], pending, "B")
            m.write(m.sym["gRcpPendingWarpDest"], 0.0, "f")
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(group_bit), 0)
        # Shared banks use the retail setter; unsupported maps stay untouched.
        m.call("applyArrivalGroups", 56)
        self.assertEqual(m.read(m.sym["gMapObjGroupStatuses"] + 10 * 4) & 1, 1)
        before = len(m.bit_edits)
        m.call("applyArrivalGroups", 38)  # Arwing: no group bank.
        self.assertEqual(len(m.bit_edits), before)

    def test_ocean_force_point_top_warp_restores_room_groups(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 50 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 50 * 2, 0x300, "H")
        m.write(m.sym["warpMap"], 50)
        m.call("resetWarpSpawn")
        destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
        m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
        m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
        m.write(m.sym["gGameLoopPendingMapId"], 50)
        for act in (1, 2):
            m.set_bit(0x300, act)
            m.set_bit(0x301, 1 << 6)  # Preserve another puzzle's saved group.
            m.bit_edits.clear()
            m.write(m.sym["warpLoadPending"], 1, "B")
            m.call("Practice_WarpReload")
            expected = (1 << 6) | (1 << 20) | (1 << 21) | (1 << 23)
            self.assertEqual(m.bit_value(0x301), expected)
            self.assertEqual(m.read(m.sym["gMapObjGroupStatuses"] + 50 * 4), expected)
            self.assertEqual(m.bit_value(0x300), act)
            self.assertTrue(all(edit[0] in (0x301, 0x956) for edit in m.bit_edits))

    def test_shop_warp_restores_thorntail_exit_without_changing_visit_flags(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 51 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 7 * 2, 0x302, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 8 * 2, 0x302, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 7 * 2, 0x300, "H")
        m.bit_def(0x302, 40, 32, 1)
        m.bit_def(0xad3, 72, 1, 2)  # Shop first-visit dialogue seen.
        m.write(m.sym["warpMap"], 51)
        m.call("resetWarpSpawn")
        destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
        m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
        m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
        m.write(m.sym["gGameLoopPendingMapId"], 51)
        for visited in (0, 1):
            m.set_bit(0xad3, visited)
            m.set_bit(0x300, 2)
            m.set_bit(0x301, 1 << 3)
            m.set_bit(0x302, (1 << 27) | 1)  # Outside enemies loaded before entering.
            m.bit_edits.clear()
            m.write(m.sym["warpLoadPending"], 1, "B")
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(0x301), (1 << 3) | 0x61)
            self.assertEqual(m.bit_value(0x302), (1 << 27) | (1 << 11))
            self.assertEqual(m.read(m.sym["gMapObjGroupStatuses"] + 8 * 4), m.bit_value(0x302))
            self.assertEqual(m.bit_value(0x300), 2)
            self.assertEqual(m.bit_value(0xad3), visited)
            self.assertTrue(all(edit[0] in (0x301, 0x302, 0x956) for edit in m.bit_edits))

    def test_named_room_warps_queue_groups_and_banks_without_resetting_progress(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0x212, 100, 1, 2)
        m.bit_def(0x818, 101, 1, 2)
        m.bit_def(0xe05, 102, 1, 2)
        m.bit_def(0x956, 103, 1, 2)
        m.bit_def(0xd37, 104, 1, 2)
        for bit, first in ((0x142, 105), (0x1ec, 106), (0x40, 107), (0x5bd, 108), (0x9e9, 109)):
            m.bit_def(bit, first, 1, 2)
        m.bit_def(0xa82, 110, 1, 2)
        bounds, layers, cells = 0x81200000, 0x81201000, 0x81202000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        # Expected retail IDs in the requested menu order, room masks and banks.
        cases = {
            2: [(121, 0, -1), (128, 0, -1), (128, 0, -1), (128, 0, -1), (128, 0x1004, -1)],
            4: [(124, 0, -1), (72, 8, -1), (81, 0x140, -1), (122, 0x140, -1), (123, 0, -1)],
            7: [(108, 0, -1), (3, 0x80, -1), (15, 0, -1), (52, 0x100, -1), (102, 0, -1)],
            8: [(95, 0x80000000, 19), (128, 0x2000000, 19)],
            10: [(103, 2, -1), (66, 8, -1), (128, 0x1130, -1), (128, 0x190, 65)],
            11: [(40, 8, -1), (32, 0x60, -1), (34, 0x300, -1), (34, 0x300, -1),
                 (78, 0xc00, -1), (65, 0xc00, -1), (6, 3, -1)],
            12: [(99, 0, -1), (74, 2, -1), (128, 0xc0, 24), (128, 0x8080000, -1)],
            13: [(120, 0, -1), (19, 0, -1), (128, 0, -1), (21, 0, -1), (70, 0, -1),
                 (91, 16, -1), (128, 16, -1), (128, 16, -1), (128, 0, -1)],
            18: [(16, 0, -1), (128, 32, -1), (64, 256, -1), (128, 256, -1)],
            19: [(119, 0, -1), (128, 0, -1), (128, 2, -1), (128, 0x122, -1),
                 (128, 0x140, -1), (128, 8, -1), (128, 0x140280, -1),
                 (128, 0x40080, -1), (128, 0x10000, -1), (128, 0x400, -1),
                 (128, 0x201000, -1), (128, 0x205000, -1)],
            28: [(92, 0, -1), (30, 4, -1), (29, 0, -1), (54, 0, -1)],
            29: [(128, 0, -1), (128, 0, -1), (53, 0, -1), (128, 0, -1), (128, 0, -1),
                 (128, 0, -1), (128, 0, -1), (128, 0, -1), (128, 0, -1)],
            50: [(115, 0, -1), (128, 0, -1), (104, 0, -1)],
        }
        custom = {(8, 1): (-6063.78467, -1378.93994, -1727.74219),
                  (10, 2): (-5006.61035, -769.940002, 2251.30469),
                  (10, 3): (-5783.62256, -834.940002, 1350.67285),
                  (12, 2): (1711.75391, 1866.06006, -16725.6328),
                  (12, 3): (107.256348, 2049.06006, -16931.1602),
                  (13, 2): (-16324.0811, -1122.93994, -13857.9746),
                  (13, 6): (-14271.3672, -1001.94, -12973.8633),
                  (13, 7): (-18367.6523, -1001.94, -14556.7051),
                  (13, 8): (-16320.599609375, -474.0, -13759.7998046875),
                  (18, 1): (-12825.8311, -220.606461, -2201.03027),
                  (18, 3): (-12220.2471, 37.0600014, -4310.73633),
                  (19, 1): (-7468.39258, -1229.19495, 9575.22461),
                  (19, 2): (-7792.62012, -1170.76294, 10578.2334),
                  (19, 3): (-8107.45459, -1251.93994, 12673.5801),
                  (19, 4): (-8457.36621, -1311.93994, 13714.9141),
                  (19, 5): (-8680.41406, -1458.93994, 11013.4033),
                  (19, 6): (-7708.66357, -1258.24097, 13558.5918),
                  (19, 7): (-8374.41016, -1005.94, 14447.2275),
                  (19, 8): (-6573.54492, -1228.93994, 14728.7676),
                  (19, 9): (-7278.93896, -1041.93994, 15043.3613),
                  (19, 10): (-10037.4512, -782.878357, 14736.7),
                  (19, 11): (-9730.06348, -916.940002, 14331.4121),
                  (29, 5): (3299.2041, -1579.93994, -2635.34961),
                  (29, 7): (3358.5166, -1398.93994, -4058.07812),
                  (50, 1): (3371.50684, -1620.93994, -8013.62842)}
        for mid, presets in cases.items():
            m.write(m.sym["gSaveGameMapObjGroupBits"] + mid * 2, 0x301, "H")
            m.write(m.sym["gSaveGameMapActBits"] + mid * 2, 0x300, "H")
            for spawn, (warp, groups, bank) in enumerate(presets):
                with self.subTest(map=mid, spawn=spawn):
                    initial_groups = 1 << 20
                    cleared_groups = 0
                    if mid == 11 and spawn == 6:
                        cleared_groups = (1 << 2) | (1 << 3) | (1 << 5)
                    if mid == 12 and spawn == 3:
                        cleared_groups = sum(1 << n for n in (0, 1, 5, 7, 8))
                    initial_groups |= cleared_groups
                    m.set_bit(0x301, initial_groups)
                    initial_act = 1 if mid == 13 else 2
                    m.set_bit(0x300, initial_act)
                    for bit in (0x212, 0x818, 0xe05, 0x142, 0x1ec):
                        m.set_bit(bit, 0)
                    m.write(m.sym["warpMap"], mid)
                    m.write(m.sym["warpSpawn"], spawn)
                    m.call("resetWarpSpawn")
                    destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
                    x, y, z, layer, _ = struct.unpack(">3f2h", destination)
                    if (mid, spawn) in custom:
                        self.assertEqual(destination[:12], struct.pack(">3f", *custom[mid, spawn]))
                    gx, gz = math.floor(x / 640), math.floor(z / 640)
                    m.uc.mem_write(layers, bytes([127]) * 128)
                    m.write(layers + mid, layer, "b")
                    m.write(cells + mid * 64, 1, "B")
                    m.uc.mem_write(bounds + mid * 10, struct.pack(">4h2b", gx, gx, gz, gz, 0, 0))
                    m.write(m.sym["gWarpRequested"], 0, "B")
                    m.call("requestPracticeWarp", m.player)
                    self.assertEqual(m.read(m.sym["gPendingWarpIndex"], "h"), warp)
                    self.assertEqual(m.read(m.sym["warpQueuedGroups"]), groups)
                    self.assertEqual(m.bit_value(0x301), initial_groups)
                    act = (spawn + 1 if spawn < 6 else 1) if mid == 11 else 0
                    if mid == 13 and spawn == 8:
                        act = 2
                    if mid == 29:
                        act = {5: 3, 7: 2}.get(spawn, 0)
                    self.assertEqual(m.read(m.sym["warpQueuedAct"], "h"), act)
                    self.assertEqual(m.bit_value(0x300), initial_act)
                    flags = {2: 1, 12: 2, 13: 4}.get(mid, 0) if spawn else 0
                    if mid == 12 and spawn == 3:
                        flags |= 8
                    self.assertEqual(m.read(m.sym["warpQueuedFlags"], "H"), flags)
                    self.assertEqual(m.bit_value(0x212), 0)
                    self.assertEqual(m.bit_value(0x818), 0)
                    self.assertEqual(m.bit_value(0x1ec), 0)
                    # Further menu browsing must not replace the queued room.
                    m.write(m.sym["warpSpawn"], 0)
                    m.call("resetWarpSpawn")
                    m.write(m.sym["gGameLoopPendingMapId"], mid)
                    m.bit_edits.clear()
                    m.call("Practice_WarpReload")
                    baseline = {2: 0x18000, 4: 6, 7: 0x43d, 8: 0, 10: 1, 11: 0, 12: 1,
                                13: 0xc23, 18: 0x2000001, 19: 0x400001, 28: 0, 29: 0x80000013, 50: 0xb00000}[mid]
                    if mid == 18 and spawn == 0:
                        baseline |= 4  # Ground Quake exit restores the life-force door corridor.
                    if mid == 12 and spawn == 3:
                        baseline = 0
                    self.assertEqual(m.bit_value(0x301), (1 << 20) | baseline | groups)
                    self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"), bank)
                    self.assertEqual(m.bit_value(0x300), act or initial_act)
                    landing_edits = ([(0x212 if mid == 12 else 0x818, 1)] if flags else []) if mid in (12, 13) else [(0x956, 1)]
                    if mid == 2:
                        landing_edits = [(0x9e9, 1)] if flags else []
                    if mid == 11:
                        landing_edits.append((0xd37, int(warp != 78)))
                    if mid in (19, 28):
                        landing_edits = [(0xa82, int(warp != 119))]
                    if mid == 29 and act == 3:
                        landing_edits = [(0x142, 1), (0x1ec, 1)] + landing_edits
                    self.assertEqual(m.bit_edits, landing_edits)
                    self.assertEqual(m.bit_value(0x40), 0)  # Act overrides do not grant staff spells.
                    self.assertEqual(m.bit_value(0x5bd), 0)
                    self.assertEqual(m.bit_value(0xe05), 0)  # Keep WC's environment initialization.
                    self.assertEqual(m.read(m.sym["warpQueuedGroups"]), 0)
                    self.assertEqual(m.read(m.sym["warpQueuedBankMap"], "h"), -1)
        for pending in (0, 1):
            m.set_bit(0x301, 0)
            m.set_bit(0x212, 0)
            m.set_bit(0x818, 0)
            m.write(m.sym["warpQueuedFlags"], 6, "H")
            m.write(m.sym["warpLoadPending"], pending, "B")
            m.write(m.sym["warpQueuedGroups"], 0xffffffff)
            m.write(m.sym["warpQueuedBankMap"], 67, "h")
            m.write(m.sym["gRcpPendingWarpDest"], 0.0, "f")
            m.write(m.sym["gGameLoopPendingMapDataFileId"], 77)
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(0x301), 0)
            self.assertEqual(m.bit_value(0x212), 0)
            self.assertEqual(m.bit_value(0x818), 0)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"]), 77)

    def test_totem_event_rearms_completed_save_only_for_committed_event_preset(self):
        m = self.m
        m.state_fixture()
        reset = (0x2d0, 0x2bc, 0x64c, 0x64d, 0x64e, 0x64f, 0x650,
                 0xa4c, 0xa4d, 0xa4e, 0xa4f, 0x768, 0x769, 0x76a, 0x76b,
                 0xa50, 0xa51, 0xa52, 0xa53)
        for i, gid in enumerate(reset + (0x2b5, 0x4d0, 0x61c)):
            m.bit_def(gid, 500 + i, 1, 2)
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 14 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 14 * 2, 0x300, "H")
        for flags, warp, pending in ((0, 80, 1), (16, 128, 1), (16, 80, 0),
                                     (16, 80, 1), (16, 80, 1)):
            event = flags == 16 and warp == 80 and pending
            m.set_bit(0x301, (1 << 20) | 2)
            m.set_bit(0x300, 6)
            for gid in reset + (0x61c,):
                m.set_bit(gid, 1)
            for gid in (0x2b5, 0x4d0):
                m.set_bit(gid, 0)
            m.write(m.sym["gGameLoopPendingMapId"], 14)
            m.write(m.sym["gPendingWarpIndex"], warp, "h")
            m.write(m.sym["warpQueuedFlags"], flags, "H")
            m.write(m.sym["warpQueuedAct"], 2, "h")
            m.write(m.sym["warpQueuedGroups"], 4)
            m.write(m.sym["warpLoadPending"], pending, "B")
            m.call("Practice_WarpReload")
            self.assertEqual([m.bit_value(gid) for gid in reset], [int(not event)] * len(reset))
            self.assertEqual(m.bit_value(0x2b5), int(bool(event)))
            self.assertEqual(m.bit_value(0x4d0), int(bool(event)))
            self.assertEqual(m.bit_value(0x61c), 1)  # Tracking/strength progress survives.
            self.assertEqual(m.bit_value(0x301), (1 << 20) | (4 if event else (6 if pending else 2)))

    def test_practice_landings_cover_planet_and_dungeon_submaps(self):
        m = self.m
        m.state_fixture()
        bits = (0x956, 0x212, 0x818, 0x9e9, 0xa82, 0xd37, 0xc85)
        for i, bit in enumerate(bits):
            m.bit_def(bit, 200 + i, 1, 2)
        cases = [(mid, 128, 0x956) for mid in (4, 7, 8, 10, 14, 18, 21, 23, 29, 50, 51, 54, 56, 66, 67)]
        for maps, bit in (((2, 44, 52), 0x9e9), ((12, 16, 43, 74), 0x212),
                          ((13, 48), 0x818), ((19, 27, 28, 68), 0xa82)):
            cases.extend((mid, 128, bit) for mid in maps)
        cases += [(2, 121, None), (12, 99, None), (13, 120, None), (19, 119, None)]
        cases += [(11, 78, 0x956), (11, 6, 0x956)]
        for mid, warp, changed in cases:
            for initial in (0, 1):
                with self.subTest(map=mid, warp=warp, initial=initial):
                    for bit in bits:
                        m.set_bit(bit, initial)
                    m.bit_edits.clear()
                    m.write(m.sym["gPendingWarpIndex"], warp, "h")
                    m.write(m.sym["gGameLoopPendingMapId"], mid)
                    m.write(m.sym["warpLoadPending"], 1, "B")
                    dest = struct.pack(">3f2h", 100, 200, 300, 0, 0)
                    m.uc.mem_write(m.sym["warpQueuedDestination"], dest)
                    m.uc.mem_write(m.sym["gRcpPendingWarpDest"], dest)
                    m.call("Practice_WarpReload")
                    expected_edits = [(changed, 1)] if changed else []
                    if mid == 19 and warp == 119:
                        expected_edits = [(0xa82, 0)]
                    if mid == 11:
                        expected_edits.append((0xd37, int(warp != 78)))
                    self.assertEqual(m.bit_edits, expected_edits)
                    for bit in bits:
                        expected = int(warp != 78) if mid == 11 and bit == 0xd37 else 1 if bit == changed else initial
                        if mid == 19 and warp == 119 and bit == 0xa82:
                            expected = 0
                        self.assertEqual(m.bit_value(bit), expected)
        # A normal Ice Mountain warp, or a scripted warp superseding the queued
        # destination, must not clear Thorntail's pending arrival.
        for pending in (0, 1):
            m.set_bit(0x956, 0)
            m.bit_edits.clear()
            m.write(m.sym["gGameLoopPendingMapId"], 23)
            m.write(m.sym["warpLoadPending"], pending, "B")
            m.write(m.sym["gRcpPendingWarpDest"], 999, "f")
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_edits, [])
            self.assertEqual(m.bit_value(0x956), 0)

    def test_dragon_rock_custom_spawns_suppress_only_the_pending_landing(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0x9e9, 80, 1, 2)
        m.bit_def(0xe7b, 81, 1, 2)
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 2 * 2, 0x301, "H")
        bounds, layers, cells = 0x81200000, 0x81201000, 0x81202000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        m.uc.mem_write(layers, bytes([127]) * 128)
        m.write(layers + 2, 0, "b")
        m.write(cells + 2 * 64, 1, "B")
        coordinates = [None, (-16170.6943, -1406.93994, 13305.6621),
                       (-16116.4424, -1632.93994, 12628.3105),
                       (-17069.1855, -1632.93994, 9946.83105),
                       (-16982.3438, -1647.93994, 8530.29395)]
        for spawn, expected in enumerate(coordinates):
            m.set_bit(0x9e9, 0)
            m.set_bit(0xe7b, 0)
            m.set_bit(0x301, 1 << 5)
            m.write(m.sym["warpMap"], 2)
            m.write(m.sym["warpSpawn"], spawn)
            m.call("resetWarpSpawn")
            destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
            x, y, z, layer, _ = struct.unpack(">3f2h", destination)
            if expected:
                self.assertEqual(destination[:12], struct.pack(">3f", *expected))
            gx, gz = math.floor(x / 640), math.floor(z / 640)
            m.uc.mem_write(bounds + 2 * 10, struct.pack(">4h2b", gx, gx, gz, gz, 0, 0))
            m.write(m.sym["gWarpRequested"], 0, "B")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["warpQueuedFlags"], "H"), int(spawn != 0))
            self.assertEqual(m.bit_value(0x9e9), 0)
            self.assertEqual(bytes(m.uc.mem_read(m.sym["gRcpPendingWarpDest"], 16)), destination)
            m.write(m.sym["warpSpawn"], 0)  # Queued custom arrival survives UI changes.
            m.write(m.sym["gGameLoopPendingMapId"], 2)
            m.bit_edits.clear()
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_edits, [(0x9e9, 1)] if spawn else [])
            self.assertEqual(m.bit_value(0xe7b), 0)  # Keep the weather setup pending.
            self.assertEqual(m.bit_value(0x301), (1 << 5) | 0x18000 | (0x1004 if spawn == 4 else 0))
            self.assertEqual(m.read(m.sym["warpQueuedFlags"], "H"), 0)
        m.set_bit(0x9e9, 0)
        m.write(m.sym["warpQueuedFlags"], 1, "H")
        m.bit_edits.clear()
        m.call("Practice_WarpReload")  # Ordinary arrival must retain the landing sequence.
        self.assertEqual(m.bit_edits, [])
        self.assertEqual(m.bit_value(0x9e9), 0)

    def test_great_fox_presets_queue_scene_act_without_changing_ordinary_warps(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0x956, 100, 1, 2)
        m.write(m.sym["gSaveGameMapActBits"] + 65 * 2, 0x300, "H")
        m.write(m.sym["warpMap"], 65)
        m.call("resetWarpSpawn")
        x, y, z, layer, _ = struct.unpack(">3f2h", m.uc.mem_read(m.sym["warpDestination"], 16))
        bounds, layers, cells = 0x81200000, 0x81201000, 0x81202000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        m.uc.mem_write(layers, bytes([127]) * 128)
        gx, gz = math.floor(x / 640), math.floor(z / 640)
        m.uc.mem_write(bounds + 65 * 10, struct.pack(">4h2b", gx, gx, gz, gz, 0, 0))
        m.write(layers + 65, layer, "b")
        m.write(cells + 65 * 64, 1, "B")
        for spawn, act in ((0, 1), (1, 2)):
            m.set_bit(0x300, 3 - act)
            m.write(m.sym["warpSpawn"], spawn)
            m.call("resetWarpSpawn")
            m.write(m.sym["gWarpRequested"], 0, "B")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["warpQueuedAct"], "h"), act)
            self.assertEqual(m.bit_value(0x300), 3 - act)  # Only at committed arrival.
            m.write(m.sym["warpSpawn"], 1 - spawn)  # UI changes cannot alter queued scene.
            m.write(m.sym["gGameLoopPendingMapId"], 65)
            m.bit_edits.clear()
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(0x300), act)
            self.assertEqual(m.bit_edits, [(0x956, 1)])
            self.assertIn(("SaveGame_gplaySetAct", 65, act), [c[:3] for c in m.calls])
            self.assertEqual(m.read(m.sym["warpQueuedAct"], "h"), 0)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"), 15)
            m.bit_edits.clear()
            m.write(m.sym["warpQueuedAct"], 3 - act, "h")
            m.call("Practice_WarpReload")  # No pending practice arrival.
            self.assertEqual(m.bit_edits, [])
            self.assertEqual(m.bit_value(0x300), act)
            self.assertEqual(m.read(m.sym["warpQueuedAct"], "h"), 0)

    def test_ship_combat_warp_mounts_once_and_restores_previous_character_on_practice_exit(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapActBits"], 0x300, "H")
        m.write(m.sym["gSaveGameMapObjGroupBits"], 0x301, "H")
        m.set_bit(0x301, (1 << 2) | (1 << 7))
        m.write(m.sym["warpMap"], 0)
        m.call("resetWarpSpawn")
        destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
        m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
        m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.write(m.sym["gGameLoopPendingMapId"], 0)
        m.call("Practice_WarpReload")
        self.assertEqual(m.character, 0)
        self.assertEqual(m.bit_value(0x75), 1)
        self.assertEqual(m.bit_value(0x300), 1)
        self.assertEqual(m.bit_value(0x301), 1 << 7)
        self.assertEqual(bytes(m.uc.mem_read(0x8110b000, 12)), destination[:12])
        m.write(m.sym["gShaderCurMapEventId"], 0)
        # A player update before the vehicle arrives must keep setup pending.
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.sym["warpShipPending"], "B"), 1)
        bird, bird_state = 0x81210000, 0x81212000
        m.ship, m.object_list, m.object_count = 0x81213000, 0x81214000, 1
        m.write(m.object_list, bird)
        m.write(bird + 0x46, 0x8c, "h")
        m.write(bird + 0xb8, bird_state)
        for offset, value in ((0x0c, 500.), (0x10, 200.), (0x14, -200.)):
            m.write(bird + offset, value, "f")
        for global_name, offset, callback in (("gPlayerInterface", 0x14, "player_setState"),
                                              ("gCameraInterface", 0x28, "Camera_setFocus"),
                                              ("gCameraInterface", 0x1c, "Camera_setMode")):
            ptr = 0x81215000 if global_name == "gPlayerInterface" else 0x81216000
            m.write(m.sym[global_name], ptr)
            m.write(ptr, ptr + 0x100)
            m.write(ptr + 0x100 + offset, m.sym[callback])
        m.calls.clear()
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.sym["warpShipPending"], "B"), 0)
        self.assertEqual(m.read(m.state + 0x7f0), bird)
        self.assertEqual(m.read(m.state + 0x6e8), m.sym["gPlayerMotionTuning"] + 24)
        self.assertEqual(m.read(m.state + 0x6ec, "B"), 4)
        self.assertIn(("player_setState", m.player, m.state, 0x18), m.calls)
        self.assertIn(("Camera_setMode", 0x4a, 1, 0), m.calls)
        self.assertEqual([c[3] for c in m.calls if c[0] == "getEnvfxActImmediately"],
                         [0x85, 0x83, 0x82, 0x94, 0x84])
        self.assertEqual(struct.unpack(">3f", m.uc.mem_read(m.ship + 12, 12)), (-1100., -100., -50.))
        m.calls.clear()
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual([c[0] for c in m.calls], ["playerUpdate"])
        # A second battle warp must not replace Fox with Krystal as the saved owner.
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.call("Practice_WarpReload")
        self.assertEqual(m.read(m.sym["warpShipPreviousCharacter"], "B"), 1)
        m.write(m.sym["gGameLoopPendingMapId"], 7)
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.call("Practice_WarpReload")
        self.assertEqual(m.character, 1)
        self.assertEqual(m.read(m.sym["warpShipPending"], "B"), 0)
        self.assertEqual(bytes(m.uc.mem_read(0x8110b010, 12)), destination[:12])

    def test_magic_cave_arrivals_set_layout_reward_and_return_without_granting_reward(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapObjGroupBits"] + 54 * 2, 0x301, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 54 * 2, 0x300, "H")
        for gid, first, width in ((0x1b8, 64, 8), (0x91e, 72, 1), (0xe05, 73, 1), (0x2d, 74, 1)):
            m.bit_def(gid, first, width, 2)
        m.write(m.sym["warpMap"], 54)
        m.call("resetWarpSpawn")
        dest = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
        x, y, z, layer, _ = struct.unpack(">3f2h", dest)
        bounds, layers, cells = 0x81200000, 0x81201000, 0x81202000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        m.uc.mem_write(layers, bytes([127]) * 128)
        gx, gz = math.floor(x / 640), math.floor(z / 640)
        m.uc.mem_write(bounds + 54 * 10, struct.pack(">4h2b", gx, gx, gz, gz, 0, 0))
        m.write(layers + 54, layer, "b")
        m.write(cells + 54 * 64, 1, "B")
        contexts = [(0, 2, 102), (1, 1, 52), (2, 2, 3), (1, 2, 95),
                    (0, 1, 103), (2, 1, 53), (3, 2, 72), (4, 2, 16), (5, 2, 21)]
        for index, (group, act, exit_warp) in enumerate(contexts):
            m.write(m.sym["warpMap"], 54)
            m.write(m.sym["warpSpawn"], index)
            m.call("resetWarpSpawn")
            m.set_bit(0x301, 0x3f | (1 << 15))
            m.set_bit(0x91e, 1)
            m.set_bit(0x2d, 1)
            m.write(m.sym["gWarpRequested"], 0, "B")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["warpQueuedCave"], "h"), index + 1)
            # Selection changes after queueing must not change the queued entry.
            m.write(m.sym["warpSpawn"], 0)
            m.write(m.sym["gGameLoopPendingMapId"], 54)
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(0x301), (1 << group) | (1 << 15))
            self.assertEqual(m.bit_value(0x300), act)
            self.assertEqual(m.bit_value(0x1b8), exit_warp)
            self.assertEqual(m.bit_value(0x91e), 0)
            self.assertEqual(m.bit_value(0x2d), 1)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"),
                             [12, 12, 12, 12, 14, 47, 7, 25, 20][index])
            self.assertEqual(m.read(m.sym["warpQueuedCave"], "h"), 0)

    def test_practice_cave_returns_restore_banks_groups_and_select_the_exit_actor(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0x91e, 72, 1, 2)
        m.bit_def(0x818, 73, 1, 2)  # WC_FlewTo: set means landing already completed.
        m.bit_def(0x302, 40, 32, 1)
        obj, placement = 0x81210000, 0x81210200
        m.write(obj + 0x4c, placement)
        for index, source in enumerate((7, 7, 7, 8, 10, 29, 4, 18, 13)):
            entry = m.sym["practiceCaveArrivals"] + index * 12
            exit_warp = m.read(entry + 3, "B")
            ident = m.read(entry + 4)
            entrance_group = m.read(entry + 8, "B")
            m.write(m.sym["gSaveGameMapObjGroupBits"] + source * 2, 0x302, "H")
            m.set_bit(0x302, 1 << 30)
            m.set_bit(0x91e, 1)
            m.set_bit(0x818, 0)
            m.write(m.sym["warpLoadPending"], 0, "B")
            m.write(m.sym["warpActiveCave"], index + 1, "B")
            m.write(m.sym["gShaderCurMapEventId"], 54)
            m.write(m.sym["gPendingWarpIndex"], exit_warp, "h")
            m.write(m.sym["gGameLoopPendingMapId"], source)
            m.calls.clear()
            m.call("Practice_WarpReload")
            self.assertIn("mapLoadByCoords", [c[0] for c in m.calls])
            self.assertEqual(m.bit_value(0x818), int(source == 13))
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), index + 1)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"), 19 if source == 8 else -1)
            expected = {7: 0x43d, 8: 0, 10: 1, 29: 0x80000013, 4: 6, 18: 0x2000005, 13: 0xc23}[source]
            if entrance_group < 32:
                expected |= 1 << entrance_group
            self.assertEqual(m.bit_value(0x302), expected | (1 << 30))
            # A different entrance updating first must leave the handoff alone.
            m.write(obj + 0xac, source, "b")
            m.write(placement + 20, ident ^ 1)
            m.calls.clear()
            m.call("Practice_CaveTopUpdate", obj)
            self.assertFalse(any(c[0] == "MagicCaveTop_update" for c in m.calls))
            self.assertEqual(m.bit_value(0x91e), 1)
            m.write(placement + 20, ident)
            m.call("Practice_CaveTopUpdate", obj)
            self.assertEqual(m.bit_value(0x91e), 0)
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), 0)
        # Unrelated/scripted travel cancels the practice return context.
        m.write(m.sym["warpActiveCave"], 1, "B")
        m.write(m.sym["gPendingWarpIndex"], 3, "h")
        m.set_bit(0x91e, 1)
        m.set_bit(0x818, 0)
        m.calls.clear()
        m.call("Practice_WarpReload")
        self.assertEqual([c[0] for c in m.calls], ["mainGetBit", "mapReload"])
        self.assertEqual(m.bit_value(0x818), 0)
        self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), 0)

    def test_exterior_shrine_presets_start_only_their_own_exit_sequence(self):
        m = self.m
        m.state_fixture()
        m.bit_def(0x91e, 72, 1, 2)
        bounds, layers, cells = 0x81200000, 0x81201000, 0x81202000
        m.write(m.sym["gShaderMapRomBuffers"] + 4, bounds)
        m.write(m.sym["gShaderMapRomBuffers"] + 12, layers)
        m.write(m.sym["gShaderMapRomBuffers"] + 16, cells)
        obj, placement = 0x81210000, 0x81210200
        m.write(obj + 0x4c, placement)
        for index, (mid, spawn) in enumerate(((7, 4), (7, 3), (7, 1), (8, 0),
                                             (10, 0), (29, 2), (4, 1), (18, 0), (13, 3))):
            entry = m.sym["practiceCaveArrivals"] + index * 12
            ident = m.read(entry + 4)
            m.write(m.sym["warpMap"], mid)
            m.write(m.sym["warpSpawn"], spawn)
            m.call("resetWarpSpawn")
            x, y, z, layer, _ = struct.unpack(">3f2h", m.uc.mem_read(m.sym["warpDestination"], 16))
            gx, gz = math.floor(x / 640), math.floor(z / 640)
            m.uc.mem_write(layers, bytes([127]) * 128)
            m.write(layers + mid, layer, "b")
            m.write(cells + mid * 64, 1, "B")
            m.uc.mem_write(bounds + mid * 10, struct.pack(">4h2b", gx, gx, gz, gz, 0, 0))
            m.set_bit(0x91e, 0)
            m.write(m.sym["gWarpRequested"], 0, "B")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["warpQueuedCave"], "h"), -index - 1)
            self.assertEqual(m.bit_value(0x91e), 0)
            m.write(m.sym["gGameLoopPendingMapId"], mid)
            m.call("Practice_WarpReload")
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), index + 1)
            self.assertEqual(m.bit_value(0x91e), 0)
            m.write(obj + 0xac, mid, "b")
            m.write(placement + 20, ident ^ 1)
            m.calls.clear()
            m.call("Practice_CaveTopUpdate", obj)
            self.assertFalse(any(c[0] == "MagicCaveTop_update" for c in m.calls))
            self.assertEqual(m.bit_value(0x91e), 0)
            m.write(placement + 20, ident)
            player = m.player
            m.player = 0
            m.call("Practice_CaveTopUpdate", obj)
            self.assertEqual(m.bit_value(0x91e), 0)
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), index + 1)
            m.player = player
            m.call("Practice_CaveTopUpdate", obj)
            self.assertIn(("mainSetBits", 0x91e, 1),
                          [c[:3] for c in m.calls if c[0] == "mainSetBits"])
            self.assertEqual(m.bit_value(0x91e), 0)
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), 0)
            m.calls.clear()
            m.call("Practice_CaveTopUpdate", obj)
            self.assertFalse(any(c[0] == "mainSetBits" for c in m.calls))
            # An edited coordinate keeps the teleport but omits the sequence.
            m.write(m.sym["warpEdited"], 1, "B")
            m.write(m.sym["gWarpRequested"], 0, "B")
            m.call("requestPracticeWarp", m.player)
            self.assertEqual(m.read(m.sym["warpQueuedCave"], "h"), 0)
            m.call("Practice_WarpReload")
            self.assertEqual(m.read(m.sym["warpReturningCave"], "B"), 0)

    def test_mmp_cave_return_omits_only_the_rolling_door(self):
        m = self.m
        placement = 0x81210200
        m.write(placement, 0x825, "h")
        m.write(placement + 20, 0x4b3f0)
        for active, map_id, expected in ((1, 18, False), (0, 18, True), (1, 7, True)):
            m.write(m.sym["warpMmpCaveReturn"], active, "B")
            m.calls.clear()
            m.call("Practice_CaveGroupObject", placement, 1, map_id, 489, 0)
            self.assertEqual(any(c[0] == "objSetupObject" for c in m.calls), expected)
        m.write(placement + 20, 0x4babf)  # Life-force door remains eligible.
        m.calls.clear()
        m.call("Practice_CaveGroupObject", placement, 1, 18, 473, 0)
        self.assertTrue(any(c[0] == "objSetupObject" for c in m.calls))

    def test_flags_hierarchy_unused_separation_and_back_navigation(self):
        m = self.m
        m.state_fixture()
        m.pad(0x64, 4)
        m.write(m.sym["activeTab"], 3, "B")
        m.pad()
        m.pad(0x100, 0x100)  # Flags -> Inventory.
        self.assertEqual(m.read(m.sym["flagPage"]), 1)
        m.call("rebuildRows")
        self.assertEqual(m.read(m.sym["visibleCount"]), 7)
        m.pad(0x100, 0x100)  # Gear.
        self.assertEqual(m.read(m.sym["flagPage"]), 10)
        m.pad(0x100, 0x100)  # Staff.
        self.assertEqual(m.bit_edits, [(0x75, 1)])
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["flagPage"]), 1)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["flagPage"]), 0)
        m.write(m.sym["selected"], 6)
        m.pad(0x100, 0x100)  # Advanced.
        m.write(m.sym["selected"], 1)
        m.pad(0x100, 0x100)  # Unused / uncertain.
        self.assertEqual(m.read(m.sym["flagPage"]), 9)
        m.call("flagBitId", 0)
        self.assertEqual(m.r(3), 0x958)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["flagPage"]), 7)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)

    def test_link_routes_retain_assets_without_editing_spirit_inventory(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapActBits"] + 66 * 2, 0x300, "H")
        m.write(m.sym["gSaveGameMapActBits"] + 23 * 2, 0x302, "H")
        m.bit_def(0x302, 80, 4, 1)
        spirits = (0xbfd, 0xff, 0xc6e)
        for index, gid in enumerate(spirits):
            m.bit_def(gid, 100 + index, 1, 2)
            m.set_bit(gid, 1)
        for route in range(1, 6):
            m.write(m.sym["warpMap"], 66)
            m.write(m.sym["warpSpawn"], route - 1)
            m.call("resetWarpSpawn")
            dest = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
            m.uc.mem_write(m.sym["gRcpPendingWarpDest"], dest)
            m.uc.mem_write(m.sym["warpQueuedDestination"], dest)
            m.write(m.sym["warpQueuedLink"], route, "h")
            m.write(m.sym["warpLoadPending"], 1, "B")
            m.write(m.sym["gGameLoopPendingMapId"], 66)
            m.call("Practice_WarpReload")
            self.assertEqual(m.bit_value(0x300), 1 if route == 1 else 3 if route == 5 else 2)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"), 15 if route == 5 else 12)
            self.assertEqual(m.read(m.sym["warpQueuedLink"], "h"), 0)
            m.write(m.sym["gShaderCurMapEventId"], 66)
            for index, gid in enumerate(spirits):
                m.call("Practice_LinkRouteBit", gid)
                self.assertEqual(m.r(3), int(route == index + 2) if 2 <= route <= 4 else 1)
                self.assertEqual(m.bit_value(gid), 1)
            # Outside the corridor the inventory is always authoritative.
            m.write(m.sym["gShaderCurMapEventId"], 11)
            m.call("Practice_LinkRouteBit", spirits[0])
            self.assertEqual(m.r(3), 1)
            m.call("Practice_WarpReload")  # Retail onward travel clears override.
            self.assertEqual(m.read(m.sym["warpActiveLink"], "B"), 0)

    def test_item_discovery_flags_do_not_change_inventory_and_remember_back_row(self):
        m = self.m
        m.state_fixture()
        ids = [0x90d, 0x90e, 0x90f, 0x910, 0x18e, 0xcbe, 0xcc0, 0x9a8,
               0x189, 0x196, 0x912, 0xd2a, 0xadb, 0x930]
        for index, gid in enumerate(ids):
            m.bit_def(gid, 200 + index, 1, 2)
        m.set_bit(0x75, 1)  # Staff ownership and bomb-spore count stay intact.
        m.set_bit(0x3f5, 7)
        m.pad(0x64, 4)
        m.write(m.sym["activeTab"], 3, "B")
        m.pad()
        m.write(m.sym["selected"], 7)
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["flagPage"]), 18)
        m.call("flagRowCount")
        self.assertEqual(m.r(3), len(ids))
        for index, gid in enumerate(ids):
            m.call("flagBitId", index)
            self.assertEqual(m.r(3), gid)
            m.write(m.sym["selected"], index)
            m.pad(0x100, 0x100)
            self.assertEqual(m.bit_value(gid), 1)
            m.pad(1, 1)  # Left re-arms the introduction without giving/taking items.
            self.assertEqual(m.bit_value(gid), 0)
        self.assertEqual(m.bit_edits, [(gid, value) for gid in ids for value in (1, 0)])
        self.assertEqual(m.bit_value(0x75), 1)
        self.assertEqual(m.bit_value(0x3f5), 7)
        m.save_loading = True
        m.pad(0x100, 0x100)
        self.assertEqual(m.bit_value(ids[-1]), 0)
        m.save_loading = False
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["flagPage"]), 0)
        self.assertEqual(m.read(m.sym["selected"]), 7)

    def test_state_widths_cross_byte_edits_and_loading_guards(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["flagPage"], 8)
        m.write(m.sym["flagRawId"], 0x3f5)
        m.write(m.sym["selected"], 1)
        m.set_bit(0x75, 1)
        m.set_bit(0x3f5, 254)
        m.call("editFlags", 2)
        self.assertEqual(m.bit_value(0x3f5), 255)
        m.call("editFlags", 2)
        self.assertEqual(m.bit_value(0x3f5), 255)
        self.assertEqual(m.bit_value(0x75), 1)  # Adjacent packed flag unchanged.
        m.write(m.sym["flagStep"], 2)
        m.call("editFlags", 1)
        self.assertEqual(m.bit_value(0x3f5), 0)
        m.save_loading = 1
        m.call("editFlags", 2)
        self.assertEqual(m.bit_value(0x3f5), 0)
        m.save_loading = 0
        for gid in (0x95, 0x96, 4096, 0xffffffff):
            m.call("stateBitWidth", gid)
            self.assertEqual(m.r(3), 0)
        m.bit_def(0x20, 0x80 * 8 - 1, 2, 0)
        m.call("stateBitWidth", 0x20)
        self.assertEqual(m.r(3), 0)  # Descriptor extends past bank end.
        m.bit_table_size = 400
        m.write(m.sym["checkedBitTable"], 0)
        m.call("practiceStateReady")
        m.call("stateBitWidth", 100)
        self.assertEqual(m.r(3), 0)  # Bound by file size, not the retail halfword count.

    def test_flags_act_group_api_routing_and_unsigned_masks(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["gSaveGameMapActBits"] + 23 * 2, 0x300, "H")
        for mid in (7, 23):
            m.write(m.sym["gSaveGameMapObjGroupBits"] + mid * 2, 0x301, "H")
        m.write(m.sym["flagPage"], 8)
        m.write(m.sym["flagRawId"], 0x301)
        m.write(m.sym["selected"], 1)
        m.set_bit(0x301, 0x80000000)
        m.call("editFlags", 2)
        self.assertEqual(m.bit_value(0x301), 0x80000001)
        self.assertEqual(m.read(m.sym["gMapObjGroupStatuses"] + 23 * 4), 0x80000001)
        self.assertTrue(any(c[0] == "SaveGame_gplaySetObjGroupStatus" for c in m.calls))
        self.assertFalse(m.bit_edits)
        m.set_bit(0x301, 0xffffffff)
        m.call("editFlags", 2)
        self.assertEqual(m.bit_value(0x301), 0xffffffff)
        m.call("writeStateBit", 0x300, 3)
        self.assertEqual(m.bit_value(0x300), 3)
        self.assertTrue(any(c[:3] == ("SaveGame_gplaySetAct", 23, 3) for c in m.calls))
        m.write(m.sym["flagPage"], 6)
        m.write(m.sym["flagMap"], 23)
        m.call("flagRowCount")
        self.assertEqual(m.r(3), 33)
        m.write(m.sym["selected"], 32)
        m.call("editFlags", 0x100)
        self.assertEqual(m.bit_value(0x301), 0x7fffffff)

    def test_stats_clamp_to_capacity_and_never_write_while_loading(self):
        m = self.m
        m.state_fixture()
        m.call("editStat", 0, 256)
        self.assertEqual(m.read(m.stats, "b"), 16)
        m.call("editStat", 1, (-10) & 0xffffffff)
        self.assertEqual(m.read(m.stats, "b"), 6)
        self.assertEqual(m.read(m.stats + 1, "b"), 6)
        m.call("editStat", 3, (-90) & 0xffffffff)
        self.assertEqual(m.read(m.stats + 4, "h"), 10)
        m.call("editStat", 4, 256)
        self.assertEqual(m.read(m.stats + 8, "B"), 255)
        before = bytes(m.uc.mem_read(m.stats, 12))
        m.save_loading = 1
        m.call("editStat", 0, 0xffffffff)
        self.assertEqual(bytes(m.uc.mem_read(m.stats, 12)), before)

    def test_logging_filters_baselines_and_observational_state(self):
        m = self.m
        m.state_fixture()
        self.assertEqual(m.read(m.sym["enabled"] + m.row("LOG TO DOLPHIN"), "B"), 1)
        m.toggle("LOG TO DOLPHIN", 0)
        m.toggle("PLAYER STATS", 1)
        m.call("pollStateLog")
        self.assertFalse(m.reports)
        self.assertEqual(m.read(m.sym["logBaseline"], "B"), 0)
        m.toggle("LOG TO DOLPHIN", 1)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 2)  # Enable + baseline acknowledgement, no state dump.
        self.assertIn(b"Logging enabled", m.uart)
        self.assertIn(b"Watching 4096 game bits", m.uart)
        m.reports.clear()
        m.set_bit(0x75, 1)
        m.set_bit(0x4e4, 1)
        m.write(m.stats + 8, 23, "B")
        m.write(m.sym["gMapObjGroupStatuses"] + 23 * 4, 0x80000001)
        saved = bytes(m.uc.mem_read(m.save_data, 0x1000))
        stats = bytes(m.uc.mem_read(m.stats, 12))
        groups = bytes(m.uc.mem_read(m.sym["gMapObjGroupStatuses"], 480))
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 4)
        self.assertEqual(bytes(m.uc.mem_read(m.save_data, 0x1000)), saved)
        self.assertEqual(bytes(m.uc.mem_read(m.stats, 12)), stats)
        self.assertEqual(bytes(m.uc.mem_read(m.sym["gMapObjGroupStatuses"], 480)), groups)
        self.assertFalse(m.bit_edits)
        bit_reports = [args for fmt, args in m.reports if "BIT" in fmt]
        self.assertEqual([(args[1], args[2], args[4], args[5]) for args in bit_reports],
                         [(0x75, 2, 0, 1), (0x4e4, 2, 0, 1)])
        m.reports.clear()
        m.toggle("INVENTORY", 0)
        m.call("pollStateLog")
        m.reports.clear()  # Filter-change acknowledgement.
        m.set_bit(0x75, 0)
        m.call("pollStateLog")
        self.assertFalse(m.reports)
        m.toggle("INVENTORY", 1)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 1)  # Baseline only; filtered history isn't replayed.
        m.reports.clear()
        m.save_loading = 1
        m.call("pollStateLog")
        m.set_bit(0x75, 1)
        m.save_loading = 0
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 1)  # Loading resets baseline.
        m.reports.clear()
        m.set_bit(0x75, 0)
        m.set_bit(0x75, 1)
        m.call("pollStateLog")
        self.assertFalse(m.reports)  # Deliberately net-frame, not every setter.

    def test_logging_burst_limit_advances_snapshot(self):
        m = self.m
        m.state_fixture()
        for i in range(40):
            m.bit_def(0x600 + i, 128 + i, 1, i % 4)
        m.toggle("LOG TO DOLPHIN", 1)
        m.call("pollStateLog")
        m.reports.clear()
        for i in range(40):
            m.set_bit(0x600 + i, 1)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 33)
        self.assertIn("suppressed", m.reports[-1][0])
        self.assertEqual(m.reports[-1][1][1], 8)
        for region in range(4):
            name = GAMEBIT_NAMES.get(0x600 + region, "UNNAMED")
            self.assertIn(f"[BIT {0x600 + region:03X}][REGION {region}] {name}: 00000000 -> 00000001".encode(),
                          m.uart)
        m.reports.clear()
        m.call("pollStateLog")
        self.assertFalse(m.reports)

    def test_debug_uart_chunks_carriage_returns_and_busy_bus(self):
        m = self.m
        message = b"[PRACTICE] This line spans several sixteen-byte FIFO writes\n"
        m.uc.mem_write(m.sym["logLine"], message + b"\0")
        m.call("sendPracticeLog")
        self.assertEqual(bytes(m.uart), message.replace(b"\n", b"\r"))
        self.assertEqual(m.calls[-1][0], "EXIUnlock")
        m.uart.clear()
        m.calls.clear()
        m.exi_busy = True
        m.call("sendPracticeLog")
        self.assertEqual([c[0] for c in m.calls], ["EXILock"])
        self.assertFalse(m.uart)
        m.exi_busy = False
        m.uart_queued = 16
        m.call("sendPracticeLog")  # Full FIFO must return, not spin indefinitely.
        self.assertFalse(m.uart)
        self.assertEqual(m.calls[-1][0], "EXIUnlock")

    def test_area_items_are_grouped_by_memorable_location_and_back_retains_area(self):
        m = self.m
        m.state_fixture()
        m.pad(0x64, 4)
        m.write(m.sym["activeTab"], 3, "B")
        m.pad()
        m.write(m.sym["flagPage"], 1)
        m.write(m.sym["selected"], 3)
        m.call("editFlags", 0x100)
        self.assertEqual(m.read(m.sym["flagPage"]), 13)
        m.call("flagRowCount")
        self.assertEqual(m.r(3), 9)
        expected = ({0x91c}, {0x194, 0x66d}, {0x1ee, 0x17b, 0x17e, 0x17f, 0x180},
                    {0x193}, {0x953}, {0xa9, 0xaf7}, {0xc25, 0xc26, 0xc27}, {0x81d, 0x81e}, {0x1a2})
        for area, required in enumerate(expected):
            m.write(m.sym["selected"], area)
            m.call("editFlags", 0x100)
            self.assertEqual(m.read(m.sym["flagPage"]), 17)
            self.assertEqual(m.read(m.sym["flagItemArea"]), area)
            m.call("flagRowCount")
            ids = set()
            for row in range(m.r(3)):
                m.call("flagBitId", row)
                ids.add(m.r(3))
            self.assertTrue(required <= ids, (area, ids))
            m.pad(0x200, 0x200)
            self.assertEqual(m.read(m.sym["flagPage"]), 13)
            self.assertEqual(m.read(m.sym["selected"]), area)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["flagPage"]), 1)
        self.assertEqual(m.read(m.sym["selected"]), 3)
        for page in (10, 12):  # Upgrades and Consumables have no area quest items.
            m.write(m.sym["flagPage"], page)
            m.call("flagRowCount")
            for row in range(m.r(3)):
                m.call("flagBitId", row)
                self.assertNotIn(m.r(3), {0xa9, 0xaf7, 0x194, 0x66d, 0x1ee})

    def test_maps_bulk_actions_are_first_and_only_edit_map_ownership(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["flagPage"], 1)
        m.write(m.sym["selected"], 6)
        m.call("editFlags", 0x100)
        self.assertEqual(m.read(m.sym["flagPage"]), 16)
        m.call("flagRowCount")
        self.assertEqual(m.r(3), 14)
        m.call("flagBitId", 0)
        self.assertEqual(m.r(3), 0xffffffff)
        m.call("flagBitId", 1)
        self.assertEqual(m.r(3), 0xffffffff)
        ids = (0x5a3, 0x5a0, 0x59e, 0x835, 0x5a1, 0x82f,
               0x5a2, 0x82e, 0x7dd, 0x7e5, 0x59d, 0x7e9)
        for row, gid in enumerate(ids, 2):
            m.bit_def(gid, 80 + row, 1, 0)
            m.call("flagBitId", row)
            self.assertEqual(m.r(3), gid)
        m.call("editFlags", 2)  # Right is not a bulk activation.
        self.assertFalse(m.bit_edits)
        m.save_loading = 1
        m.call("editFlags", 0x100)
        self.assertFalse(m.bit_edits)
        m.save_loading = 0
        m.call("editFlags", 0x100)
        self.assertEqual(m.bit_edits, [(gid, 1) for gid in ids])
        m.call("editFlags", 0x100)
        self.assertEqual(len(m.bit_edits), 12)  # Already unlocked: no repeated setters.
        m.write(m.sym["selected"], 2)
        m.call("editFlags", 0x100)
        self.assertEqual(m.bit_edits[-1], (0x5a3, 0))
        m.write(m.sym["selected"], 1)
        m.call("editFlags", 2)  # Remove All also requires A.
        m.save_loading = 1
        m.call("editFlags", 0x100)
        self.assertEqual(len(m.bit_edits), 13)
        m.save_loading = 0
        m.call("editFlags", 0x100)
        self.assertEqual(m.bit_edits[13:], [(gid, 0) for gid in ids[1:]])
        m.call("editFlags", 0x100)
        self.assertEqual(len(m.bit_edits), 24)  # Already removed: no repeated setters.
        m.write(m.sym["selected"], 0)
        m.player = 0
        m.call("editFlags", 0x100)
        self.assertEqual(len(m.bit_edits), 24)

    def test_short_area_item_labels_keep_area_context_in_logs(self):
        m = self.m
        m.state_fixture()
        for i, gid in enumerate((0x91c, 0xa9)):
            m.bit_def(gid, 72 + i * 2, 2 if gid == 0xa9 else 1, 0)
        m.call("pollStateLog")
        m.set_bit(0x91c, 1)
        m.set_bit(0xa9, 2)
        m.call("pollStateLog")
        self.assertIn(f"[BIT 91C][REGION 0][GALLEON] {GAMEBIT_NAMES[0x91C]}: 00000000 -> 00000001".encode(), m.uart)
        self.assertIn(f"[BIT 0A9][REGION 0][CAPE CLAW] {GAMEBIT_NAMES[0xA9]}: 00000000 -> 00000002".encode(), m.uart)

    def test_log_names_match_gamebit_ids_header(self):
        m = self.m
        offsets, text = m.sym["practiceGameBitNameOffsets"], m.sym["practiceGameBitNameText"]
        count = max(GAMEBIT_NAMES) + 1
        embedded = {}
        for bit in range(count):
            offset = m.read(offsets + bit * 2, "H")
            if offset != 0xFFFF:
                raw = bytes(m.uc.mem_read(text + offset, 160))
                embedded[bit] = raw[:raw.index(0)].decode()
        self.assertEqual(embedded, GAMEBIT_NAMES)
        self.assertEqual(GAMEBIT_NAMES[0xF47], "WM_HitAnimTarget0F47|WM_SwitchRelated0F47")

    def test_inventory_spell_alias_and_tricky_ball(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["flagPage"], 1)
        m.write(m.sym["selected"], 1)  # Inventory -> Staff Spells, immediately after Gear.
        m.call("editFlags", 0x100)
        self.assertEqual(m.read(m.sym["flagPage"]), 11)
        pages = []
        for page in (2, 11, 10, 3):
            m.write(m.sym["flagPage"], page)
            m.call("flagRowCount")
            ids = []
            for row in range(m.r(3)):
                m.call("flagBitId", row)
                ids.append(m.r(3))
            pages.append(ids)
        self.assertEqual(pages[0], pages[1])
        self.assertTrue({0x2d, 0x957, 0x5ce} <= set(pages[0]))
        # All ball possession/availability rows in Gear also exist in Tricky.
        gear_labels = []
        for row in range(len(pages[2])):
            m.write(m.sym["flagPage"], 10)
            m.call("pageBit", row)
            name = bytes(m.uc.mem_read(m.read(m.r(3)), 80)).split(b"\0")[0]
            if b"TRICKY BALL" in name:
                gear_labels.append(pages[2][row])
        self.assertEqual(len(gear_labels), 2)
        self.assertTrue(set(gear_labels) <= set(pages[3]))

    def test_inventory_krazoa_spirits_one_through_six(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["flagPage"], 1)
        m.write(m.sym["selected"], 5)
        m.call("editFlags", 0x100)
        self.assertEqual(m.read(m.sym["flagPage"]), 15)
        m.call("flagRowCount")
        self.assertEqual(m.r(3), 6)
        for row, gid in enumerate((0xba8, 0xbfd, 0xff, 0xc6e, 0xc85, 0x174)):
            m.bit_def(gid, 64 + row, 1, 0)
            m.call("flagBitId", row)
            self.assertEqual(m.r(3), gid)
            m.write(m.sym["selected"], row)
            m.call("editFlags", 0x100)
            self.assertEqual(m.bit_edits[-1], (gid, 1))
        self.assertEqual(len(m.bit_edits), 6)  # No implicit deposit/progression edits.

    def test_quiet_log_defaults_and_explicit_runtime_opt_in(self):
        m = self.m
        m.state_fixture()
        for label, expected in (("PLAYER STATS", 0), ("RUNTIME / ACTION FLAGS", 0),
                                ("SAVE / RESPAWN CHECKPOINTS", 1)):
            self.assertEqual(m.read(m.sym["enabled"] + m.row(label), "B"), expected)
        for i, gid in enumerate((0x961, 0x965, 0x986, 0x3b0, 0x884)):
            m.bit_def(gid, 40 + i, 1, 0)
        m.toggle("LOG TO DOLPHIN", 1)
        m.call("pollStateLog")
        m.reports.clear()
        for gid in (0x961, 0x965, 0x986, 0x3b0):
            m.set_bit(gid, 1)
        m.write(m.stats + 8, 22, "B")
        m.call("pollStateLog")
        self.assertFalse(m.reports)
        m.toggle("RUNTIME / ACTION FLAGS", 1)
        m.call("pollStateLog")
        m.reports.clear()
        for gid in (0x961, 0x965, 0x986, 0x3b0):
            m.set_bit(gid, 0)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 4)
        m.reports.clear()
        m.set_bit(0x884, 1)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 1)
        self.assertIn(GAMEBIT_NAMES[0x884].encode(), m.uart)

    def test_layer_changes_across_loading_and_filter_resets(self):
        m = self.m
        m.state_fixture()
        m.toggle("LOG TO DOLPHIN", 1)
        m.call("pollStateLog")
        m.uart.clear()
        m.layer = -1
        m.call("pollStateLog")
        self.assertIn(b"[LAYER] 0 -> -1", m.uart)
        m.save_loading = 1
        m.layer = 2
        m.call("pollStateLog")
        self.assertIn(b"[LAYER] -1 -> 2", m.uart)
        m.uart.clear()
        m.call("pollStateLog")
        self.assertFalse(m.uart)
        m.toggle("AREA / MAP ACTS", 0)
        m.layer = 1
        m.call("pollStateLog")
        m.toggle("AREA / MAP ACTS", 1)
        m.call("pollStateLog")
        self.assertFalse(m.uart)  # No replay of filtered history.

    def test_retail_checkpoint_hooks_repeat_restore_and_preserve_operations(self):
        m = self.m
        m.state_fixture()
        # Execute the original checkpoint routines with actual patched call sites.
        for edit in make_patch(self.dol, self.payload, self.exports)["edits"]:
            if "hook" in edit:
                m.uc.mem_write(edit["address"], bytes.fromhex(edit["after"]))
        # Recover the retail r13 anchor from getCurMapLayer's single SDA load.
        insn = m.read(m.sym["getCurMapLayer"])
        self.assertEqual((insn >> 16) & 31, 13)
        delta = struct.unpack(">h", struct.pack(">H", insn & 0xffff))[0]
        m.uc.reg_write(UC_PPC_REG_0 + 13, m.sym["curMapLayer"] - delta)
        live = m.sym["gSaveGameData"]
        work, restart, pos = 0x81112000, 0x81110000, 0x81114000
        m.write(m.sym["gSaveGameWorkBuffer"], work)
        m.write(m.sym["pRestartPoint"], 0)
        m.uc.mem_write(live, bytes(0xf70))
        m.uc.mem_write(pos, struct.pack(">3f", 100, 200, -300))
        m.toggle("LOG TO DOLPHIN", 1)
        for _ in range(2):
            m.call("SaveGame_gplaySavePoint", pos, 0x4000, 0, 0xffffffff)
        self.assertEqual(bytes(m.uart).count(b"SAVE SET"), 2)
        self.assertIn(b"layer=-1 XYZ=100,200,-300", m.uart)
        self.assertEqual(bytes(m.uc.mem_read(live, 0xf70)), bytes(m.uc.mem_read(work, 0xf70)))
        m.uart.clear()
        m.write(live + 0x22, 1, "B")
        m.call("SaveGame_gplaySavePoint", 0, 0, 0, 0)
        self.assertFalse(m.uart)  # Suppressed checkpoint is not reported as accepted.
        m.write(live + 0x22, 0, "B")
        m.call("SaveGame_gplaySavePoint", 0, 0, 1, 0)
        self.assertIn(b"SAVE REFRESH (POSITION KEPT)", m.uart)
        for _ in range(2):
            m.call("SaveGame_gplayRestartPoint", pos, 0x2000, 2, 0)
        self.assertEqual(bytes(m.uart).count(b"RESTART SET"), 2)
        self.assertEqual(m.read(m.sym["pRestartPoint"]), restart)
        self.assertIn(b"layer=2 XYZ=100,200,-300", m.uart)
        m.save_loading = 1  # Direct events do not depend on polling readiness.
        m.call("SaveGame_gplayGotoRestartPoint")
        self.assertIn(b"RESPAWN RESTART", m.uart)
        self.assertEqual(bytes(m.uc.mem_read(live, 0xf70)), bytes(m.uc.mem_read(restart, 0xf70)))
        m.call("SaveGame_gplayClearRestartPoint")
        self.assertIn(b"RESTART CLEAR", m.uart)
        self.assertEqual(m.read(m.sym["pRestartPoint"]), 0)
        m.call("SaveGame_gplayGotoRestartPoint")
        self.assertIn(b"RESPAWN SAVE (FALLBACK)", m.uart)
        m.call("SaveGame_gplayGotoSavegame")
        self.assertIn(b"RESTORE SAVE", m.uart)
        self.assertEqual(sum(c[0] == "loadMapForCurrentSaveGame" for c in m.calls), 3)
        m.call("Practice_WriteSave", 2, work, m.sym["saveData"])
        self.assertEqual(m.r(3), 0x35)
        self.assertIn(b"CARD SAVE REQUEST", m.uart)
        m.uart.clear()
        m.allocation = 0
        m.call("SaveGame_gplayRestartPoint", pos, 0, 0, 0)
        self.assertFalse(m.uart)  # Failed allocation creates no checkpoint.
        m.toggle("SAVE / RESPAWN CHECKPOINTS", 0)
        m.call("SaveGame_gplaySavePoint", pos, 0, 0, 0)
        self.assertFalse(m.uart)
        self.assertEqual(m.read(work + 0x684, "f"), 100)

    def test_menu_mutes_owned_object_sounds_and_restores_without_touching_music(self):
        m = self.m
        base = m.sym["gSfxObjectChannels"]
        for i in range(3):
            m.write(base + i * 0x38, 100 + i)
            m.write(base + i * 0x38 + 7, 70 + i, "B")
            m.write(base + i * 0x38 + 0x30, i + 1, "Q")
        m.write(base + 0x38 + 6, 1, "B")  # Already paused by the game.
        m.write(base + 2 * 0x38 + 4, 1, "B")  # Positional sound.
        m.hud_hidden = 1  # An existing cutscene need not have muted these voices.
        m.pad(0x48, 8)  # L+Up alone must keep the original controls when Free Move is not armed.
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        m.pad(0x64, 4)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        self.assertEqual([c[1:] for c in m.calls if c[0] == "sndFXCtrl"], [(100, 7, 0), (102, 7, 0)])
        for i in range(3):
            self.assertEqual(m.read(base + i * 0x38 + 6, "B"), 1)
        m.calls.clear()
        m.pad()
        m.pad(0x200, 0x200)
        self.assertIn(("sndFXCtrl", 100, 7, 70), m.calls)
        self.assertTrue(any(c[:2] == ("Sfx_UpdateObjectChannel3D", base + 2 * 0x38) for c in m.calls))
        self.assertEqual([m.read(base + i * 0x38 + 6, "B") for i in range(3)], [0, 1, 0])

    def test_menu_audio_respects_recycled_voices_and_other_pause_owners(self):
        m = self.m
        base = m.sym["gSfxObjectChannels"]
        m.write(base, 100)
        m.pad(0x64, 4)
        # Recycle the same voice handle into a different, already-paused allocation.
        m.write(base + 0x30, 9, "Q")
        m.call("updateMenuSounds")
        m.pad()
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(base + 6, "B"), 1)
        for guard in ("gDvdErrorPauseActive", "hud"):
            m.write(base + 6, 0, "B")
            m.pad(0x64, 4)
            if guard == "hud":
                m.hud_hidden = 1
            else:
                m.write(m.sym[guard], 1, "B")
            m.pad()
            m.pad(0x200, 0x200)
            self.assertEqual(m.read(base + 6, "B"), 1)
            m.hud_hidden = 0
            m.write(m.sym["gDvdErrorPauseActive"], 0, "B")

    def test_flags_and_log_pages_stay_inside_screen(self):
        m = self.m
        m.state_fixture()
        m.write(m.sym["menuOpen"], 1, "B")
        for tab, page in [(3, n) for n in range(19)] + [(4, 0)]:
            m.geometry = []
            m.write(m.sym["activeTab"], tab, "B")
            m.write(m.sym["flagPage"], page)
            m.write(m.sym["selected"], 0)
            m.call("drawMenu")
            self.assertTrue(m.geometry)
            self.assertTrue(all(0 <= v[0] <= 640 and 0 <= v[1] <= 480 for g in m.geometry for v in g[2]), (tab, page))

    def test_hover_default_gap_requires_both_buttons_and_releases_either(self):
        m = self.m
        self.assertEqual(m.read(m.sym["rollBlanks"]), 3)
        m.toggle("AUTO-SHIELD HOVER", 1)
        for single in (0x400, 0x20):
            m.pad(single, single)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), single)
            self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
            m.pad()
        for released in (0x400, 0x20, 0):
            for action in [0x20, 0x400, 0, 0, 0] * 2:
                m.pad(0x420)
                self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), action)
            m.pad(released)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), released)
            self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)

    def test_auto_roll_roll_then_blank_then_shield_then_roll(self):
        m = self.m
        self.assertEqual(m.read(m.sym["autoRollBlanks"]), 39)
        m.toggle("AUTO ROLL", 1)
        for blanks in (39, 3):
            m.pad()  # Release resets timer.
            m.write(m.sym["autoRollBlanks"], blanks)
            previous = 0
            for frame in range((blanks + 2) * 2 + 1):
                m.pad(0xc00, 0x400 if frame == 0 else 0)  # X held, Y preserved.
                phase = frame % (blanks + 2)
                action = 0x400 if phase == 0 else 0x20 if phase == blanks + 1 else 0
                shield = action & 0x20
                self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800 | action)
                self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]) & 0x420, action & ~previous)
                self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, previous & ~action)
                self.assertEqual(m.read(m.sym["gPadTriggers"], "H"), shield)
                self.assertEqual(m.read(m.sym["gPadTriggersPressed"], "H"), shield)
                self.assertEqual(m.read(m.sym["gPadStatuses"] + 7, "B"), 255 if shield else 0)
                self.assertEqual(m.read(m.sym["gPadButtonsPrevious"]), 0xc00)
                previous = action
            m.pad(0x800)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800)
            self.assertEqual(m.read(m.sym["gPadTriggers"], "H"), 0)
        m.toggle("AUTO-SHIELD HOVER", 1)
        for action in (0x20, 0x400, 0, 0, 0):
            m.pad(0x420)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), action)
        m.pad(0x400)  # Drop R: auto roll resumes with a fresh X press.
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x400)
        m.pad(0x64, 4)  # Opening the menu suppresses both cheats.
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)

    def test_hover_custom_cadence_and_menu_limits(self):
        m = self.m
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.write(m.sym["rollBlanks"], 2)
        m.write(m.sym["shieldBlanks"], 3)
        sequence = [0x20, 0, 0, 0, 0x400, 0, 0] * 2
        previous = 0
        for action in sequence:
            m.pad(0x520, 0x420 if previous == 0 and action == 0x20 else 0)  # Hold X+R; A stays available.
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x100 | action)
            self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]) & 0x420, action & ~previous)
            self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, previous & ~action)
            previous = action
        m.pad(0x64, 4)
        self.assertEqual(m.read(m.sym["hoverWait"]), 0)
        m.pad()
        m.pad(0x20, 0x20)
        m.write(m.sym["selected"], 5)  # Blanks after roll; Free Move/Swimming are off.
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["rollBlanks"]), 3)
        m.write(m.sym["rollBlanks"], 60)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["rollBlanks"]), 60)
        m.write(m.sym["rollBlanks"], 0)
        m.pad(1, 1)
        self.assertEqual(m.read(m.sym["rollBlanks"]), 0)

    def test_object_level_sphere_and_barrel_vertical_span_without_model(self):
        m = self.m
        m.toggle("FOX / PLAYER", 1)
        hit = 0x81100000
        m.write(m.player + 0x54, hit)
        m.write(hit + 0x60, 1, "H")
        m.write(hit + 0x5A, 20, "h")
        m.write(hit + 0x62, 1, "B")
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 72)
        self.assertEqual(m.geometry[0][2][0][:3], (0, 120, 0))
        m.geometry = []
        m.write(hit + 0x62, 2, "B")
        m.write(hit + 0x5C, -5, "h")
        m.write(hit + 0x5E, 20, "h")
        m.call("drawObjectCollision", m.player)
        self.assertEqual(len(m.geometry), 52)
        self.assertEqual(sorted(set(p[1] for g in m.geometry for p in g[2])), [95, 120])
        m.geometry = []
        m.toggle("OBJECT BODY", 0)
        m.call("drawObjectCollision", m.player)
        self.assertFalse(m.geometry)

    def test_disabled_trigger_fill_outline_and_markers_are_gray(self):
        m = self.m
        definition, placement = 0x81100000, 0x81101000
        m.write(m.player + 0x50, definition)
        m.write(m.player + 0x4C, placement)
        m.write(definition + 0x50, 294, "h")
        m.write(placement, 0x4C, "H")
        m.write(m.state + 0x34, 20.0, "f")
        m.uc.mem_write(m.state + 0x38, struct.pack(">12f", 1, 0, 0, -10, 0, 1, 0, -100, 0, 0, 1, -30))
        for status, obj_flags, gate_value in [(4, 0, 1), (0, 0x2000, 1), (0, 0, 0)]:
            m.geometry = []
            m.write(m.state, status, "B")
            m.write(m.player + 0xB0, obj_flags, "H")
            m.gate_bit = gate_value
            m.call("drawTriggers", m.player)
            self.assertEqual(len(m.geometry), 8)
            self.assertTrue(all((p[3] >> 8) == 0x929292 for g in m.geometry for p in g[2]))
        m.geometry = []
        m.write(m.state + 0x82, -1, "h")  # No gate: zero-valued unrelated bit must not gray it.
        m.call("drawTriggers", m.player)
        self.assertEqual(m.geometry[0][2][0][3] >> 8, 0xFF69D4)


if __name__ == "__main__":
    unittest.main()
