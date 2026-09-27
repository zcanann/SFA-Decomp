"""Execute the compiled PPC payload with stubbed game/GX services.

Requires Unicorn (pip install --target build/practice/python unicorn==2.1.4).
These checks exercise real target instructions, not Dolphin or GPU emulation.
"""
import math
import struct
import sys
import unittest

from build import ROOT, PAYLOAD_ADDRESS, PAYLOAD_LIMIT, compile_payload, sections, symbols, tool_directory

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
        for name, (addr, _) in symbols().items():
            if name.startswith("GX") or name in (
                "padUpdate", "Obj_GetPlayerObject", "OSSetArenaLo", "playerDoControls",
                "playerEnterDeepWater", "playerUpdateSurfaceResponse", "Camera_SetCurrentViewIndex",
                "Camera_UpdateProjection", "resetSomeGxFlags", "getScreenResolution", "mathSinf", "mathCosf",
                "Matrix_TransformPoint", "mapGetBlockAtPos", "ObjList_GetObjects", "PSMTXInverse", "PSMTXMultVec",
                "Obj_TransformLocalPointToWorld", "mainGetBit"):
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
        for index in range(22):
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
        if PAYLOAD_ADDRESS <= pc < PAYLOAD_ADDRESS + len(self.payload):
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
        elif name == "mainGetBit":
            uc.reg_write(UC_PPC_REG_0 + 3, getattr(self, "gate_bit", 1))
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
        m.write(m.sym["waterHeight"], 140.0, "f")
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.state + 0x3F0, "B") & 0x20, 0x20)
        self.assertEqual(m.read(m.state + 0x1C0, "f"), -100000.0)
        m.call("Practice_SurfaceResponse", m.player, m.state, m.state)
        self.assertEqual(m.read(m.state + 0x1C0, "f"), -100000.0)
        m.pad(0x48)  # L+Up
        self.assertEqual(m.read(m.sym["waterHeight"], "f"), 142.0)
        m.toggle("FORCED SWIMMING", 0)
        m.call("Practice_PlayerControls", m.player, m.state)
        self.assertEqual(m.read(m.state + 0x3F0, "B") & 0x20, 0)

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
        self.assertEqual(m.read(m.sym["visibleCount"]), 16)
        m.pad()
        m.pad(0x20, 0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)
        self.assertEqual(m.read(m.sym["visibleCount"]), 6)
        self.assertEqual(m.read(m.sym["visible"]), m.row("FORCED SWIMMING"))
        m.pad(0x20)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)  # Holding R does not repeat tabs.
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 0)
        m.pad()
        m.pad(0x40, 0x40)
        self.assertEqual(m.read(m.sym["activeTab"], "B"), 1)  # Wrap left.
        m.write(m.sym["selected"], 3)
        m.pad(0x100, 0x100)
        self.assertEqual(m.read(m.sym["enabled"] + m.row("AUTO-SHIELD HOVER"), "B"), 1)
        self.assertEqual(m.read(m.sym["hoverActive"], "B"), 0)  # Menu wins over automation.
        m.pad(0x200, 0x200)
        m.pad()
        self.assertEqual(m.read(m.sym["gPadTriggers"], "H") & 0x20, 0x20)

    def test_hover_alternates_edges_preserves_steering_and_releases(self):
        m = self.m
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.write(m.sym["gPadStatuses"] + 2, 40, "b")
        for frame in range(6):
            m.pad(0x800)  # Y remains held; no physical X/R input.
            action = 0x20 if frame % 2 == 0 else 0x400
            previous = 0 if frame == 0 else (0x400 if frame % 2 == 0 else 0x20)
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800 | action)
            self.assertEqual(m.read(m.sym["gPadButtonsJustPressed"]) & 0x420, action)
            self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, previous)
            self.assertEqual(m.read(m.sym["gPadTriggers"], "H") & 0x20, action & 0x20)
            self.assertEqual(m.read(m.sym["gPadStatuses"] + 7, "B"), 255 if action == 0x20 else 0)
            self.assertEqual(m.read(m.sym["gPadStatuses"] + 2, "b"), 40)
            self.assertEqual(m.read(m.sym["gPadButtonsPrevious"]), 0x800)
        m.toggle("AUTO-SHIELD HOVER", 0)
        m.pad(0x800)
        self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0x800)
        self.assertEqual(m.read(m.sym["gPadButtonsReleased"]) & 0x420, 0x400)
        m.toggle("AUTO-SHIELD HOVER", 1)
        for blocker in ("timeStop", "gDvdErrorPauseActive", "joypadDisabled"):
            m.write(m.sym[blocker], 1, "B")
            m.pad()
            self.assertEqual(m.read(m.sym["gPadButtonsHeld"]), 0)
            self.assertEqual(m.read(m.sym["hoverPhase"], "B"), 0)
            m.write(m.sym[blocker], 0, "B")
        m.pad()
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

    def test_hover_custom_cadence_and_menu_limits(self):
        m = self.m
        m.toggle("AUTO-SHIELD HOVER", 1)
        m.write(m.sym["rollBlanks"], 2)
        m.write(m.sym["shieldBlanks"], 3)
        sequence = [0x20, 0, 0, 0, 0x400, 0, 0] * 2
        previous = 0
        for action in sequence:
            m.pad(0x100)  # A stays available while X/R are automated.
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
        m.toggle("OBJECT HIT VOLUMES", 0)
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
