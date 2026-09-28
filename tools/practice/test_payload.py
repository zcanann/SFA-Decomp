"""Execute the compiled PPC payload with stubbed game/GX services.

Requires Unicorn (pip install --target build/practice/python unicorn==2.1.4).
These checks exercise real target instructions, not Dolphin or GPU emulation.
"""
import math
import re
import struct
import sys
import unittest

from build import ROOT, PAYLOAD_ADDRESS, PAYLOAD_LIMIT, compile_payload, make_patch, sections, symbols, tool_directory

OUT = ROOT / "build/practice"
sys.path.insert(0, str(OUT / "python"))
from unicorn import Uc, UC_ARCH_PPC, UC_MODE_PPC32, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_FPR0, UC_PPC_REG_MSR, UC_PPC_REG_LR, UC_PPC_REG_PC


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
            "curves_preparePointCollisionFrame", "curves_updateLocalPointTransforms", "setMatrixFromObjectPos")]
        for name, (addr, _) in retail.items():
            if name.startswith("GX") or name in (
                "padUpdate", "Obj_GetPlayerObject", "OSSetArenaLo", "playerDoControls",
                "playerEnterDeepWater", "playerUpdateSurfaceResponse", "Camera_SetCurrentViewIndex",
                "Camera_UpdateProjection", "resetSomeGxFlags", "getScreenResolution", "mathSinf", "mathCosf", "fastFloorf",
                "Matrix_TransformPoint", "mapGetBlockAtPos", "ObjList_GetObjects", "PSMTXInverse", "PSMTXMultVec",
                "Obj_TransformLocalPointToWorld", "mainGetBit", "ObjHits_IsObjectEnabled", "warpToMap",
                "mapReload", "mapLoadByCoords", "unlockLevel", "isSaveGameLoading", "getDataFileSize",
                "SaveGame_getPlayerStats", "getTrickyObject", "mainSetBits", "SaveGame_gplaySetAct",
                "SaveGame_gplaySetObjGroupStatus", "sprintf", "EXILock", "EXISelect", "EXIImm",
                "EXISync", "EXIDeselect", "EXIUnlock", "sndFXCtrl", "getHudHiddenFrameCount", "Sfx_UpdateObjectChannel3D",
                "playerUpdate", "playerDoHitDetection", "playerDie", "Obj_TransformWorldVectorToLocal",
                "playerRefreshCollisionState", "trackInvalidateDynamicSlotsForObject", "angleToVec2",
                "getCurMapLayer", "memcpy", "mmAlloc", "mm_free", "loadMapForCurrentSaveGame", "_saveGame"):
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
        elif name == "angleToVec2":
            angle = self.r(3) * math.pi / 32768
            self.write(self.r(4), math.sin(angle), "f")
            self.write(self.r(5), math.cos(angle), "f")
        elif name == "mainGetBit":
            uc.reg_write(UC_PPC_REG_0 + 3, self.bit_value(self.r(3)) if hasattr(self, "bit_table") else getattr(self, "gate_bit", 1))
        elif name == "mainSetBits":
            self.bit_edits.append((self.r(3), self.r(4)))
            self.set_bit(self.r(3), self.r(4))
        elif name == "isSaveGameLoading":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "save_loading", 0))
        elif name == "getDataFileSize":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "bit_table_size", 0x4000))
        elif name == "SaveGame_getPlayerStats":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "stats", 0))
        elif name == "getTrickyObject":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "tricky", 0))
        elif name == "SaveGame_gplaySetAct":
            self.set_bit(self.read(self.sym["gSaveGameMapActBits"] + self.r(3) * 2, "H"), self.r(4))
        elif name == "SaveGame_gplaySetObjGroupStatus":
            gamebit = self.read(self.sym["gSaveGameMapObjGroupBits"] + self.r(3) * 2, "H")
            mask = 1 << self.r(4)
            value = self.bit_value(gamebit)
            value = value | mask if self.r(5) else value & ~mask
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
            args = tuple(self.r(i) for i in range(5, 12))
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
            self.write(self.r(4), 0)
            uc.reg_write(UC_PPC_REG_0 + 3, 0)
        self.calls.append((name, self.r(3), self.r(4), self.r(5)))
        uc.reg_write(UC_PPC_REG_PC, uc.reg_read(UC_PPC_REG_LR))

    def fifo(self, uc, access, address, size, value, unused):
        assert size == 4, (address, size)
        self.words.append(value)
        if len(self.words) == 4:
            xyz = struct.unpack(">fff", struct.pack(">III", *self.words[:3]))
            self.current[2].append((*xyz, self.words[3]))
            self.words = []

    def call(self, name, *args):
        self.uc.reg_write(UC_PPC_REG_0 + 1, 0x815F0000)
        self.uc.reg_write(UC_PPC_REG_LR, 0x80002000)
        for i, value in enumerate(args):
            self.uc.reg_write(UC_PPC_REG_0 + 3 + i, value)
        self.setf(1, 1.0)
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
                                        (0x958, 14, 1, 2), (0x300, 0, 4, 1), (0x301, 8, 32, 1)):
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
        m.pad(0x100, 0x100)  # A toggles collision off, keeps its children visible.
        self.assertEqual(m.read(m.sym["enabled"], "B"), 0)
        self.assertEqual(m.read(m.sym["expanded"], "B"), 1)
        m.pad(4, 4)
        self.assertEqual(m.read(m.sym["selected"]), 1)
        m.pad(1, 1)  # Left collapses parent
        self.assertEqual(m.read(m.sym["selected"]), 0)
        self.assertEqual(m.read(m.sym["expanded"], "B"), 0)
        m.pad(0x200, 0x200)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 0)
        self.assertEqual(m.read(m.sym["timeStop"], "B"), 3)

    def test_swim_restores_real_water_query(self):
        m = self.m
        m.pad()
        m.toggle("FORCED SWIMMING", 1)
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
        m.toggle("FORCED SWIMMING", 0)
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.state + 0x3F0, "B") & 0x20, 0)

    def test_swim_quick_toggle_recaptures_height_without_menu_chord_collision(self):
        m = self.m
        m.pad()
        m.toggle("FORCED SWIMMING", 1)
        m.pad(0x48, 8)  # L+Up.
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 140)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        m.pad(0x48)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)  # Held chord does not repeat.
        m.pad()
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("FORCED SWIMMING"), "B"), 1)
        m.pad()
        m.write(m.player + 0x1c, 900.0, "f")
        m.pad(0x48, 8)
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
        m.pad(0x48, 8)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 1)

    def test_free_move_camera_relative_cstick_height_and_input_priority(self):
        m = self.m
        m.pad()
        m.toggle("FREE MOVE", 1)
        m.toggle("AUTO ROLL", 1)
        m.toggle("FORCED SWIMMING", 1)
        m.write(m.sym["swimActive"], 1, "B")
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.calls[-1][0], "playerUpdate")  # Armed is not active.
        m.pad(0x44, 4)  # L+Down.
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(m.read(m.sym["swimActive"], "B"), 0)
        m.pad(0x44)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        m.write(m.sym["gPadStatuses"] + 2, 70, "b")
        m.write(m.sym["gPadStatuses"] + 3, 70, "b")
        m.write(m.sym["gPadStatuses"] + 5, 70, "b")
        m.write(m.sym["gCameras"], -32768, "h")  # Main view faces -Z, right is +X.
        m.pad(0x400, 0x400)  # X must not descend or trigger auto roll.
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)
        m.calls.clear()
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual([m.read(m.player + k, "f") for k in (0xc, 0x10, 0x14)], [5, 5, -5])
        self.assertFalse(any(c[0] == "playerUpdate" for c in m.calls))
        m.call("Practice_PlayerHitDetection", m.player)
        self.assertFalse(any(c[0] == "playerDoHitDetection" for c in m.calls))
        m.write(m.sym["gPadStatuses"] + 5, -70, "b")
        m.pad(0x800, 0x800)  # C-stick down descends; Y has no movement role.
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.read(m.player + 0x10, "f"), 0)
        for yaw, expected in ((0, (-5, 0, 5)), (16384, (-5, 0, -5)), (-16384, (5, 0, 5))):
            m.write(m.sym["gCameras"], yaw, "h")
            m.write(m.sym["gCameras"] + 2, 16384, "h")  # Looking vertically never adds climb.
            m.write(m.sym["gPadStatuses"] + 2, 70, "b")
            m.write(m.sym["gPadStatuses"] + 3, 70, "b")
            m.pad(0xc00, 0xc00)  # Neither X nor Y affects height.
            for axis, value in enumerate(expected):
                self.assertAlmostEqual(m.read(m.sym["freeStep"] + axis * 4, "f"), value, places=4)
        m.pad()
        m.pad(0x44, 4)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)  # Exit chord swallowed too.
        m.call("Practice_PlayerUpdate", m.player)
        self.assertEqual(m.calls[-1][0], "playerUpdate")
        m.call("Practice_PlayerHitDetection", m.player)
        self.assertEqual(m.calls[-1][0], "playerDoHitDetection")

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
        m.pad(0x44, 4)
        parent = 0x81120000
        m.write(m.player + 0x30, parent)  # ObjAnimComponent.parent.
        m.write(m.sym["freeStep"], 5.0, "f")
        m.call("Practice_PlayerUpdate", m.player)
        transforms = [c for c in m.calls if c[0] == "Obj_TransformWorldVectorToLocal"]
        self.assertTrue(transforms)
        self.assertEqual(m.read(m.player + 0x14, "f"), -5)
        m.pad(0x64, 4)
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 1)
        self.assertEqual(bytes(m.uc.mem_read(m.sym["freeStep"], 12)), bytes(12))
        m.pad()
        m.pad(0x200, 0x200)
        m.write(m.sym["joypadDisabled"], 1, "B")
        m.pad()
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.write(m.sym["joypadDisabled"], 0, "B")
        m.pad(0x44, 4)
        m.save_loading = 1
        m.pad()
        self.assertEqual(m.read(m.sym["freeActive"], "B"), 0)
        m.save_loading = 0
        m.pad(0x44, 4)
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
        m.pad(0x44, 4)
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
        m.pad(0x44, 4)
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

    def test_menu_geometry_and_preview(self):
        m = self.m
        m.pad(0x64, 4)
        for label in ["COLLISION", "TRIGGERS", "FORCED SWIMMING"]:
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
        for label in ("TERRAIN TRIANGLES", "WATER TRIANGLES", "DRAW THROUGH WALLS", "FORCED SWIMMING", "AUTO-SHIELD HOVER"):
            self.assertEqual(m.read(m.sym["enabled"] + m.row(label), "B"), 0)
        for label in ("COLLISION", "TRIGGERS", "OBJECT TRIANGLES", "OBJECT HIT VOLUMES", "BARRIERS / LEDGES", "BARRIER FILL", "TRANSLUCENT FILL"):
            self.assertEqual(m.read(m.sym["enabled"] + m.row(label), "B"), 1)
        m.pad(0x64, 4)
        m.call("rebuildRows")
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
        self.assertEqual(m.read(m.sym["visibleCount"]), 24)
        m.pad()
        m.pad(0x20, 0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        self.assertEqual(m.read(m.sym["visibleCount"]), 11)
        self.assertEqual(m.read(m.sym["visible"]), m.row("FORCED SWIMMING"))
        m.pad(0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)  # Holding R does not repeat tabs.
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 4)  # Wrap left to Log.
        self.assertEqual(m.read(m.sym["visibleCount"]), 10)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 3)
        self.assertEqual(m.read(m.sym["visibleCount"]), 7)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 2)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        m.write(m.sym["selected"], 3)
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
        self.assertEqual(m.read(m.sym["visible"] + 3 * 4), m.row("WARP NOW"))
        destination = m.sym["warpDestination"]
        default = bytes(m.uc.mem_read(destination, 16))
        self.assertAlmostEqual(m.read(destination, "f"), 3583.789306640625)
        m.write(m.sym["selected"], 4)
        m.pad(2, 2)
        self.assertEqual(m.read(destination, "f"), struct.unpack(">f", default[:4])[0] + 10)
        self.assertEqual(m.read(m.sym["warpEdited"], "B"), 1)
        m.write(m.sym["selected"], 2)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["warpSpawn"]), 1)
        self.assertEqual(m.read(m.sym["warpEdited"], "B"), 0)
        self.assertEqual(m.read(destination + 4, "f"), 6545.6337890625)
        m.write(m.sym["selected"], 1)
        m.pad(2, 2)
        self.assertNotEqual(m.read(m.sym["warpMap"]), 23)
        self.assertEqual(m.read(m.sym["warpSpawn"]), 0)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        # Browsing object chunks shows unavailable entries, without issuing warps.
        m.write(m.sym["selected"], 0)
        m.write(m.sym["warpCategory"], 6)
        m.pad(2, 2)
        self.assertEqual(m.read(m.sym["warpMap"]), 75)
        m.write(m.sym["selected"], 3)
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["menuOpen"], "B"), 1)
        self.assertFalse(any(c[0] == "warpToMap" for c in m.calls))
        # Resetting the map restores the preset, including Y/layer/facing.
        m.write(m.sym["warpMap"], 23)
        m.write(m.sym["warpSpawn"], 0)
        m.call("resetWarpSpawn")
        self.assertEqual(bytes(m.uc.mem_read(destination, 16)), default)

    def test_warp_validates_world_cells_and_uses_retail_transition(self):
        m = self.m
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
        m.call("resetWarpSpawn")
        m.call("warpDestinationMap")
        self.assertEqual(m.r(3), 7)

    def test_player_movement_shapes_toggles_and_parent_space(self):
        m = self.m
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

    def test_practice_warp_queues_destination_banks_only_at_committed_reload(self):
        m = self.m
        # Ordinary game warps must retain their existing loading behavior.
        m.call("Practice_WarpReload")
        self.assertEqual([c[0] for c in m.calls], ["mapReload"])
        # Include all five Krazoa tests as well as Galdon and Andross flight.
        for map_id, layer in ((28, -2), (38, 2), (31, 0), (32, 0), (33, 0), (34, 0), (39, 0)):
            m.calls = []
            m.write(m.sym["warpMap"], map_id)
            m.call("resetWarpSpawn")
            destination = bytes(m.uc.mem_read(m.sym["warpDestination"], 16))
            m.uc.mem_write(m.sym["warpQueuedDestination"], destination)
            m.uc.mem_write(m.sym["gRcpPendingWarpDest"], destination)
            m.write(m.sym["warpLoadPending"], 1, "B")
            m.call("Practice_WarpReload")
            self.assertEqual([c[0] for c in m.calls], ["unlockLevel", "mapLoadByCoords"])
            self.assertEqual(m.calls[0][1:], (0, 0, 1))
            self.assertEqual(m.loaded_coordinates[:3], struct.unpack(">3f", destination[:12]))
            self.assertEqual(m.loaded_coordinates[3], layer & 0xffffffff)
            self.assertEqual(m.read(m.sym["gGameLoopPendingMapDataFileId"], "i"), -1)
            self.assertEqual(m.read(m.sym["warpLoadPending"], "B"), 0)
        # If a normal scripted warp supersedes our request, don't change its banks.
        m.calls = []
        m.write(m.sym["warpLoadPending"], 1, "B")
        m.write(m.sym["gRcpPendingWarpDest"], 0.0, "f")
        m.call("Practice_WarpReload")
        self.assertEqual([c[0] for c in m.calls], ["mapReload"])
        self.assertEqual(m.read(m.sym["warpLoadPending"], "B"), 0)

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
        self.assertEqual([(args[1], args[3], args[4]) for args in bit_reports], [(0x75, 0, 1), (0x4e4, 0, 1)])
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
            m.bit_def(0x600 + i, i, 1, 0)
        m.toggle("LOG TO DOLPHIN", 1)
        m.call("pollStateLog")
        m.reports.clear()
        for i in range(40):
            m.set_bit(0x600 + i, 1)
        m.call("pollStateLog")
        self.assertEqual(len(m.reports), 33)
        self.assertIn("suppressed", m.reports[-1][0])
        self.assertEqual(m.reports[-1][1][1], 8)
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
        self.assertEqual(m.r(3), 8)
        expected = ({0x91c}, {0x194, 0x66d}, {0x1ee, 0x17b, 0x17e, 0x17f, 0x180},
                    {0x193}, {0x953}, {0xa9, 0xaf7}, {0xc25, 0xc26, 0xc27}, {0x81d, 0x81e})
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
        self.assertIn(b"[BIT 91C][GALLEON] GOLD KEY", m.uart)
        self.assertIn(b"[BIT 0A9][CAPE CLAW] FIRE GEMS", m.uart)

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
        self.assertIn(b"WARPSTONE / TRANSPORT", m.uart)

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
        m.pad(0x44, 4)  # L+Down alone must keep the original controls.
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
        for tab, page in [(3, n) for n in range(18)] + [(4, 0)]:
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
        m.write(m.sym["selected"], 4)  # Blanks after roll.
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
