"""Exercise the recovered slot union with the production quad-write sequence.

Only pointer-free slot declarations cross into the native harness. Tests compare
field values; serialized PowerPC byte order remains the target build's concern.
"""
import ctypes
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body


ROOT = Path(__file__).resolve().parents[1]


class ExpgfxSlotLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the slot-layout harness")
        header = (ROOT / "include/main/expgfx_internal.h").read_text()
        first = header.index("typedef union ExpgfxSlotStateBits")
        last = header.index("#define EXPGFX_STATIC_DATA", first)
        declarations = header[first:last]
        first = header.index("typedef union ExpgfxFloatWord")
        last = header.index("} ExpgfxFloatWord;", first) + len("} ExpgfxFloatWord;")
        declarations = header[first:last] + "\n" + declarations
        source = (ROOT / "src/dlls/engine/10_expgfx/expgfx.c").read_text()
        first, last = find_function_body(source, "expgfx_initSlotQuad")
        body = source[first:last + 1]
        writes = body[body.index("quad = slot->quad;"):]
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-expgfx-slot-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "slot.c"
        fixture.write_text(r'''
#include <stddef.h>
typedef signed short s16;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned int u32;
typedef float f32;
typedef struct Vec3s { s16 x, y, z; } Vec3s;
#define EXPGFX_SLOT_SIZE 0xA0
#define STATIC_ASSERT(x) _Static_assert(x, #x)
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
''' + declarations + r'''
EXPORT void fillQuad(ExpgfxSlot* slot, Vec3s* quadTemplate,
                     s16 texS0, s16 texS1, s16 texT0, s16 texT1) {
    ExpgfxQuadVertex* quad;
''' + writes + r'''
EXPORT void setMetadata(ExpgfxSlot* slot, s16* values, u8* colors) {
    slot->lifetimeFrame = values[0];
    slot->lifetimeFrameLimit = values[1];
    slot->sequenceId = values[2];
    slot->impactEffectId = values[3];
    slot->initialAlpha = colors[0];
    slot->startColorR = colors[1];
    slot->startColorG = colors[2];
    slot->startColorB = colors[3];
}
EXPORT void readVertexMetadata(ExpgfxSlot* slot, s16* values, u8* colors) {
    int i;
    for (i = 0; i < 4; ++i) {
        values[i] = slot->quad[i].pad06;
        colors[i] = slot->quad[i].alpha;
    }
}
''')
        library = directory / ("slot.dll" if sys.platform == "win32" else "slot.so")
        command = [compiler, "-shared", "-O2", str(fixture), "-o", str(library)]
        if sys.platform == "win32":
            command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
        else:
            command += ["-fPIC"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        if sys.platform == "win32":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        cls.library.fillQuad.argtypes = [ctypes.c_void_p, ctypes.c_void_p] + [ctypes.c_short] * 4
        cls.library.fillQuad.restype = None
        for name in ("setMetadata", "readVertexMetadata"):
            function = getattr(cls.library, name)
            function.argtypes = [ctypes.c_void_p] * 3
            function.restype = None

    def test_metadata_aliases(self):
        slot = (ctypes.c_ubyte * 0xA0)()
        values = (ctypes.c_short * 4)(-1, 300, 0x1234, 0x284)
        colors = (ctypes.c_ubyte * 4)(255, 73, 121, 13)
        out_values = (ctypes.c_short * 4)()
        out_colors = (ctypes.c_ubyte * 4)()
        self.library.setMetadata(slot, values, colors)
        self.library.readVertexMetadata(slot, out_values, out_colors)
        self.assertEqual(list(out_values), list(values))
        self.assertEqual(list(out_colors), list(colors))

    def test_quad_writes_preserve_metadata_and_simulation_state(self):
        rng = random.Random(0x80099AC4)
        for _ in range(100):
            slot = (ctypes.c_ubyte * 0xA0)(*(rng.randrange(256) for _ in range(0xA0)))
            expected = bytearray(slot)
            vertices = (ctypes.c_short * 12)(*(rng.randrange(-32768, 32768) for _ in range(12)))
            s0, s1, t0, t1 = (rng.randrange(-32768, 32768) for _ in range(4))
            uv = ((s0, t0), (s1, t0), (s1, t1), (s0, t1))
            for index in range(4):
                base = index * 16
                expected[base:base + 6] = bytes(vertices)[index * 6:index * 6 + 6]
                expected[base + 8:base + 12] = bytes((ctypes.c_short * 2)(*uv[index]))
            self.library.fillQuad(slot, vertices, s0, s1, t0, t1)
            self.assertEqual(bytes(slot), expected)


if __name__ == "__main__":
    unittest.main()
