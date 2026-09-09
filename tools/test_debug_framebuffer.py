"""Run the production backdrop, glyph and rule rasterizers against a guarded framebuffer.

The host harness records cache-store requests; it does not emulate GPU scanout
or PowerPC cache-line rounding.
"""
import ctypes
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
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
        constants = "\n".join(re.findall(r"^#define DEBUG_(?:FRAMEBUFFER|GLYPH|TEXT|BACKDROP)_.*$", source, re.M))
        glyph = re.search(r"^void debugTextDrawToFrameBuffer\([^;\n]*\) \{.*?^\}", source, re.M | re.S).group()
        pixel = re.search(r"^static inline void debugDrawTextPixel\(.*?^\}", source, re.M | re.S).group()
        rule = re.search(r"^static inline void errorDrawHorizontalRule\(.*?^\}", source, re.M | re.S).group()
        backdrop = re.search(r"^static inline void errDisplayFillBackdrop\(.*?^\}", source, re.M | re.S).group()
        backdrop_calls = re.findall(r"if \(enableDebugText != 0\) \{\s*errDisplayFillBackdrop\(\);\s*\}", source)
        if len(backdrop_calls) != 2:
            raise AssertionError("Re-audit the two guarded crash-display backdrop calls")
        calls = re.findall(r"^            if \(enableDebugText != 0\) \{\n"
                           r"                errorDrawHorizontalRule\([^;]+\);\n            \}", source, re.M)
        if len(calls) != 3:
            raise AssertionError("Re-audit the three crash-display rule call sites")
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-debug-framebuffer-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "raster.c"
        fixture.write_text(r'''
#include <stddef.h>
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
EXPORT u16 storage[640 * 480 + 64];
EXPORT int flushes[10][2], flushCount;
static u16* debugDrawFrameBuffer = storage + 32;
static int enableDebugText;
static void DCStoreRange(void* address, unsigned int size) {
    if (flushCount < 10) {
        flushes[flushCount][0] = (u16*)address - debugDrawFrameBuffer;
        flushes[flushCount][1] = size;
    }
    flushCount++;
}
''' + constants + "\n" + pixel + "\n" + glyph + "\n" + rule + "\n" + backdrop + r'''
EXPORT void runBackdrop(int enabled) {
    enableDebugText = enabled;
    flushCount = 0;
''' + backdrop_calls[0] + "\n}\n" + r'''
EXPORT void runGlyph(int enabled, int x, int y, u8* grid) {
    enableDebugText = enabled;
    flushCount = 0;
    debugTextDrawToFrameBuffer(x, y, grid, -1);
}
EXPORT void runRule(int row, int width) {
    flushCount = 0;
    errorDrawHorizontalRule(row, width);
}
EXPORT void runCrashRules(int enabled, int y) {
    enableDebugText = enabled;
    flushCount = 0;
''' + "\n".join(calls) + "\n}\n")
        cls.libraries = []
        for optimization in ("-O0", "-O2"):
            library = directory / (optimization[1:] + (".dll" if sys.platform == "win32" else ".so"))
            command = [compiler, "-shared", optimization, "-fno-builtin", str(fixture), "-o", str(library)]
            if sys.platform == "win32":
                command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
            else:
                command += ["-fPIC"]
            subprocess.run(command, check=True, timeout=30)
            handle = ctypes.CDLL(str(library))
            if sys.platform == "win32":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, handle._handle)
            handle.runGlyph.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       ctypes.POINTER(ctypes.c_ubyte)]
            handle.runGlyph.restype = None
            handle.runBackdrop.argtypes = [ctypes.c_int]
            handle.runBackdrop.restype = None
            handle.runRule.argtypes = [ctypes.c_int, ctypes.c_int]
            handle.runRule.restype = None
            handle.runCrashRules.argtypes = [ctypes.c_int, ctypes.c_int]
            handle.runCrashRules.restype = None
            cls.libraries.append(handle)

    def check_pixels(self, library, draw, pixels, flushes, pixel_color=COLOR):
        storage = (ctypes.c_ushort * (WIDTH * HEIGHT + GUARD * 2)).in_dll(library, "storage")
        initial = (ctypes.c_ushort * len(storage))(*([SENTINEL] * len(storage)))
        ctypes.memmove(storage, initial, ctypes.sizeof(initial))
        expected = bytearray(bytes(initial))
        color = bytes(ctypes.c_ushort(pixel_color))
        for x, y in pixels:
            offset = 2 * (GUARD + y * WIDTH + x)
            expected[offset:offset + 2] = color
        draw()
        self.assertEqual(bytes(storage), expected)
        count = ctypes.c_int.in_dll(library, "flushCount").value
        self.assertEqual(count, len(flushes))
        recorded = ((ctypes.c_int * 2) * 10).in_dll(library, "flushes")
        self.assertEqual([tuple(recorded[i]) for i in range(count)], flushes)

    def test_backdrop_covers_framebuffer_and_preserves_guards(self):
        for library in self.libraries:
            pixels = ((x, y) for y in range(HEIGHT) for x in range(WIDTH))
            self.check_pixels(library, lambda: library.runBackdrop(1), pixels, [], 0x1080)
            self.check_pixels(library, lambda: library.runBackdrop(0), [], [])

    def test_glyph_footprints_and_cache_ranges(self):
        # Each bit has a two-by-two footprint, with consecutive bits one pixel apart.
        patterns = [[0] * 5, [255] * 5, [1, 2, 4, 8, 128]]
        patterns += [[1 << bit] * 5 for bit in range(8)]
        for library in self.libraries:
            # Negative columns and row crossings remain valid linear framebuffer
            # indices here; the retail glyph writer does not clip at scanlines.
            for x, y in ((0, 0), (17, 23), (631, 470), (-4, 1), (639, 10)):
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
        rng = random.Random(0x9100)
        cases += [(rng.randrange(HEIGHT), rng.randrange(WIDTH + 1)) for _ in range(80)]
        for library in self.libraries:
            for row, width in cases:
                rows = (row - 1, row) if row else (0,)
                pixels = {(x, y) for y in rows for x in range(width)}
                self.check_pixels(library, lambda: library.runRule(row, width), pixels, [])

    def test_crash_display_call_sites(self):
        for library in self.libraries:
            for enabled in (0, 1, 255):
                for stack_y in (192, 204):
                    pixels = set()
                    if enabled:
                        for row, width in ((58, 640), (91, 240), (stack_y + 76, 640)):
                            pixels.update((x, y) for y in (row - 1, row) for x in range(width))
                    self.check_pixels(library, lambda: library.runCrashRules(enabled, stack_y), pixels, [])


if __name__ == "__main__":
    unittest.main()
