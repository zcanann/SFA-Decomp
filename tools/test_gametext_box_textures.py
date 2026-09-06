"""Check the production box-texture tiler against a linear-to-GX pixel oracle."""
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
HEADER_SIZE = 0x60
GUARD_SIZE = 16


class GameTextBoxTextureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/textrender_boxtex.c").read_text()
        source = re.sub(r'^#include[^\n]*\n', '', source, flags=re.M)
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-box-textures-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "box.c"
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef signed short s16;
typedef struct Texture { u8 header[0x60]; } Texture;
#define GX_TF_RGB5A3 5
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
static s16 gGameTextBoxTexAssets = 0x1C4;
static u16 gGameTextBoxCornerTexSrc[256];
static u16 gGameTextBoxEdgeTexSrc[400];
static Texture* background;
static Texture* allocations[2];
static void* flushAddresses[2];
static unsigned int flushSizes[2];
static int loadCount, allocationCount, flushCount, valid;

EXPORT void prepare(Texture* bg, Texture* corner, Texture* edge,
                    const u16* cornerPixels, const u16* edgePixels) {
    int i;
    background = bg;
    allocations[0] = corner;
    allocations[1] = edge;
    loadCount = allocationCount = flushCount = 0;
    valid = 1;
    for (i = 0; i < 256; i++) gGameTextBoxCornerTexSrc[i] = cornerPixels[i];
    for (i = 0; i < 400; i++) gGameTextBoxEdgeTexSrc[i] = edgePixels[i];
}

static Texture* textureLoadAsset(int asset) {
    valid &= allocationCount == 0 && flushCount == 0 && asset == 0x1C4;
    loadCount++;
    return background;
}
static Texture* textureAlloc(int width, int height, int format,
                             int a, int b, int c, int d, int e, int f) {
    int index = allocationCount++;
    int expectedSize = index == 0 ? 16 : 20;
    valid &= loadCount == 1 && flushCount == index;
    valid &= width == expectedSize && height == expectedSize && format == GX_TF_RGB5A3;
    valid &= a == 0 && b == 0 && c == 0 && d == 0 && e == 1 && f == 1;
    return allocations[index & 1];
}
static void DCFlushRange(void* address, unsigned int size) {
    int index = flushCount++;
    valid &= allocationCount == index + 1;
    flushAddresses[index & 1] = address;
    flushSizes[index & 1] = size;
}
''' + source + r'''
EXPORT void run(void) { gameTextInitBoxTextures(); }
EXPORT int lifecycleIsValid(void) {
    return valid && loadCount == 1 && allocationCount == 2 && flushCount == 2 &&
           gGameTextBoxBgTexture == background &&
           gGameTextBoxCornerTexture == allocations[0] &&
           gGameTextBoxEdgeTexture == allocations[1] &&
           flushAddresses[0] == allocations[0] + 1 && flushSizes[0] == 512 &&
           flushAddresses[1] == allocations[1] + 1 && flushSizes[1] == 800;
}
EXPORT int sourcesAreUnchanged(const u16* corner, const u16* edge) {
    int i;
    for (i = 0; i < 256; i++) if (corner[i] != gGameTextBoxCornerTexSrc[i]) return 0;
    for (i = 0; i < 400; i++) if (edge[i] != gGameTextBoxEdgeTexSrc[i]) return 0;
    return 1;
}
''')
        library = directory / ("box.dll" if sys.platform == "win32" else "box.so")
        command = [compiler, "-shared", "-O2", "-fno-builtin", str(fixture), "-o", str(library)]
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
        cls.library.prepare.argtypes = [ctypes.c_void_p] * 5
        cls.library.prepare.restype = None
        cls.library.run.argtypes = []
        cls.library.run.restype = None
        cls.library.lifecycleIsValid.argtypes = []
        cls.library.lifecycleIsValid.restype = ctypes.c_int
        cls.library.sourcesAreUnchanged.argtypes = [ctypes.c_void_p] * 2
        cls.library.sourcesAreUnchanged.restype = ctypes.c_int

    def check_pixels(self, corner, edge):
        buffers = []
        snapshots = []
        addresses = []
        for size in (32, 512, 800):
            buffer = (ctypes.c_ubyte * (GUARD_SIZE + HEADER_SIZE + size + GUARD_SIZE))()
            ctypes.memset(buffer, 0xA5, len(buffer))
            buffers.append(buffer)
            snapshots.append(bytes(buffer))
            addresses.append(ctypes.addressof(buffer) + GUARD_SIZE)
        corner_input = (ctypes.c_ushort * 256)(*corner)
        edge_input = (ctypes.c_ushort * 400)(*edge)
        self.library.prepare(*addresses, corner_input, edge_input)
        self.library.run()
        self.assertEqual(self.library.lifecycleIsValid(), 1)
        self.assertEqual(self.library.sourcesAreUnchanged(corner_input, edge_input), 1)
        self.assertEqual(bytes(buffers[0]), snapshots[0])
        for index, (width, pixels) in enumerate(((16, corner), (20, edge)), start=1):
            buffer = buffers[index]
            start = GUARD_SIZE + HEADER_SIZE
            actual = (ctypes.c_ushort * (width * width)).from_buffer(buffer, start)
            for y in range(width):
                for x in range(width):
                    tile = (y // 4) * (width // 4) + x // 4
                    tiled_index = tile * 16 + (y % 4) * 4 + x % 4
                    self.assertEqual(actual[tiled_index], pixels[y * width + x], (width, x, y))
            self.assertEqual(bytes(buffer[:start]), snapshots[index][:start])
            self.assertEqual(bytes(buffer[-GUARD_SIZE:]), snapshots[index][-GUARD_SIZE:])

    def test_coordinate_and_random_pixels(self):
        self.check_pixels(list(range(256)), list(range(400)))
        rng = random.Random(0x8001C794)
        for _ in range(32):
            self.check_pixels([rng.randrange(65536) for _ in range(256)],
                              [rng.randrange(65536) for _ in range(400)])

    def test_retained_texture_assets(self):
        source = (ROOT / "src/main/textrender_drawbox.c").read_text()
        assets = []
        for name, count in (("Corner", 256), ("Edge", 400)):
            match = re.search(r"u16 gGameTextBox" + name + r"TexSrc\[\d+\] = \{([^}]+)\}", source)
            self.assertIsNotNone(match)
            pixels = [int(word, 16) for word in re.findall(r"0x[0-9a-fA-F]+", match.group(1))]
            self.assertEqual(len(pixels), count)
            assets.append(pixels)
        self.check_pixels(*assets)


if __name__ == "__main__":
    unittest.main()
