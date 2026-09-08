"""Run the production glyph and error-rule rasterizers against a guarded framebuffer.

The host harness records cache-store requests; it does not emulate GPU scanout
or PowerPC cache-line rounding.
"""
import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WIDTH, HEIGHT, GUARD = 640, 480, 32
SENTINEL, COLOR = 0x1357, 0xC080


class DebugFramebufferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/dll_80136a40.c").read_text()
        constants = "\n".join(re.findall(r"^#define DEBUG_(?:FRAMEBUFFER|GLYPH)_.*$", source, re.M))
        glyph = re.search(r"^void debugTextDrawToFrameBuffer\([^;\n]*\) \{.*?^\}", source, re.M | re.S).group()
        rule = re.search(r"^static inline void errorDrawHorizontalRule\(.*?^\}", source, re.M | re.S).group()
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-debug-framebuffer-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "raster.c"
        fixture.write_text(r'''
#include <stddef.h>
typedef unsigned char u8;
typedef unsigned short u16;
u16 storage[640 * 480 + 64];
int flushes[10][2], flushCount;
static u16* debugDrawFrameBuffer = storage + 32;
static int enableDebugText;
static void DCStoreRange(void* address, unsigned int size) {
    if (flushCount < 10) {
        flushes[flushCount][0] = (u16*)address - debugDrawFrameBuffer;
        flushes[flushCount][1] = size;
    }
    flushCount++;
}
''' + constants + "\n" + glyph + "\n" + rule + r'''
void runGlyph(int enabled, int x, int y, u8* grid) {
    enableDebugText = enabled;
    flushCount = 0;
    debugTextDrawToFrameBuffer(x, y, grid, -1);
}
void runRule(int row, int width) {
    flushCount = 0;
    errorDrawHorizontalRule(row, width);
}
''')
        cls.libraries = []
        for optimization in ("-O0", "-O2"):
            library = directory / (optimization[1:] + ".so")
            subprocess.run([compiler, "-shared", "-fPIC", optimization, str(fixture),
                            "-o", str(library)], check=True, timeout=30)
            handle = ctypes.CDLL(str(library))
            handle.runGlyph.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       ctypes.POINTER(ctypes.c_ubyte)]
            handle.runGlyph.restype = None
            handle.runRule.argtypes = [ctypes.c_int, ctypes.c_int]
            handle.runRule.restype = None
            cls.libraries.append(handle)

    def check_pixels(self, library, draw, pixels, flushes):
        storage = (ctypes.c_ushort * (WIDTH * HEIGHT + GUARD * 2)).in_dll(library, "storage")
        initial = (ctypes.c_ushort * len(storage))(*([SENTINEL] * len(storage)))
        ctypes.memmove(storage, initial, ctypes.sizeof(initial))
        expected = bytearray(bytes(initial))
        color = bytes(ctypes.c_ushort(COLOR))
        for x, y in pixels:
            offset = 2 * (GUARD + y * WIDTH + x)
            expected[offset:offset + 2] = color
        draw()
        self.assertEqual(bytes(storage), expected)
        count = ctypes.c_int.in_dll(library, "flushCount").value
        self.assertEqual(count, len(flushes))
        recorded = ((ctypes.c_int * 2) * 10).in_dll(library, "flushes")
        self.assertEqual([tuple(recorded[i]) for i in range(count)], flushes)

    def test_glyph_footprints_and_cache_ranges(self):
        # Each bit has a two-by-two footprint, with consecutive bits one pixel apart.
        patterns = [[0] * 5, [255] * 5, [1, 2, 4, 8, 128]]
        patterns += [[1 << bit] * 5 for bit in range(8)]
        for library in self.libraries:
            for x, y in ((0, 0), (17, 23), (631, 470)):
                for rows in patterns:
                    grid = (ctypes.c_ubyte * 5)(*rows)
                    pixels = {(x + bit + dx, y + row * 2 + dy)
                              for row, bits in enumerate(rows) for bit in range(8)
                              if bits & (1 << bit) for dx in (0, 1) for dy in (0, 1)}
                    flushes = [((y + row) * WIDTH + x, 16) for row in range(10)]
                    self.check_pixels(library, lambda: library.runGlyph(1, x, y, grid), pixels, flushes)
            self.check_pixels(library, lambda: library.runGlyph(0, 0, 0, None), set(), [])

    def test_horizontal_rule_footprints(self):
        # Retail call sites use rows 58, 91 and the stack-dependent lower separator.
        cases = [(58, 640), (91, 240), (280, 640), (479, 640), (0, 640), (0, 1), (58, 0)]
        for library in self.libraries:
            for row, width in cases:
                rows = (row - 1, row) if row else (0,)
                pixels = {(x, y) for y in rows for x in range(width)}
                self.check_pixels(library, lambda: library.runRule(row, width), pixels, [])


if __name__ == "__main__":
    unittest.main()
