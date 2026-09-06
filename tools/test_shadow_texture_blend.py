"""Exercise the actual blendTextures body on host-native tiled halfwords.

The host fixture mirrors only the retail header fields used by this function.
Pixel values, not serialized byte order, cross the host/PowerPC boundary.
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
HEADER_SIZE = 0x60
RGB565 = 4
RGBA8 = 6


class TextureHeader(ctypes.Structure):
    _fields_ = [
        ("prefix", ctypes.c_ubyte * 10),
        ("width", ctypes.c_ushort),
        ("height", ctypes.c_ushort),
        ("reserved0e", ctypes.c_ubyte * 8),
        ("format", ctypes.c_ubyte),
        ("reserved17", ctypes.c_ubyte * 0x2D),
        ("dataSize", ctypes.c_uint),
        ("reserved48", ctypes.c_ubyte * 24),
    ]


class Texture:
    def __init__(self, width, height, format, rng):
        size = width * height * (2 if format == RGB565 else 4)
        self.storage = (ctypes.c_ubyte * (HEADER_SIZE + size))()
        self.header = TextureHeader.from_buffer(self.storage)
        self.header.width = width
        self.header.height = height
        self.header.format = format
        self.header.dataSize = size
        self.pixels = (ctypes.c_ushort * (size // 2)).from_buffer(self.storage, HEADER_SIZE)
        for i in range(len(self.pixels)):
            self.pixels[i] = rng.randrange(65536)

    @property
    def address(self):
        return ctypes.addressof(self.storage)


def reference_pixels(a, b, weight, width, height, format):
    weight = ctypes.c_float(weight).value
    first = int(ctypes.c_float(255.0 * weight).value) & 255
    second = 255 - first

    def mix(x, y):
        return ((x * first) // 256 + (y * second) // 256) & 255

    def expand5(x):
        return (x << 3) | (x >> 2)

    def expand6(x):
        return (x << 2) | (x >> 4)

    result = [0] * len(a)
    for y in range(height):
        for x in range(width):
            tile = (y // 4) * (width // 4) + x // 4
            pixel = (y % 4) * 4 + x % 4
            if format == RGB565:
                index = tile * 16 + pixel
                p, q = a[index], b[index]
                red = mix(expand5(p >> 11), expand5(q >> 11))
                green = mix(expand6((p >> 5) & 63), expand6((q >> 5) & 63))
                blue = mix(expand5(p & 31), expand5(q & 31))
                result[index] = ((red >> 3) << 11) | ((green >> 2) << 5) | (blue >> 3)
            else:
                index = tile * 32 + pixel
                result[index] = mix(a[index] & 255, b[index] & 255)
                result[index + 16] = (
                    mix(a[index + 16] >> 8, b[index + 16] >> 8) << 8
                ) | mix(a[index + 16] & 255, b[index + 16] & 255)
    return result


class ShadowTextureBlendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        assert ctypes.sizeof(TextureHeader) == HEADER_SIZE
        source = (ROOT / "src/main/newshadows.c").read_text()
        start, end = find_function_body(source, "blendTextures")
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-shadow-blend-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "blend.c"
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef float f32;
#define NULL ((void*)0)
#define GX_TF_RGB565 4
#define GX_TF_RGBA8 6
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
typedef struct Texture {
    u8 prefix[10];
    u16 width, height;
    u8 reserved0e[8];
    u8 format;
    u8 reserved17[0x2D];
    u32 dataSize;
    u8 reserved48[24];
} Texture;
_Static_assert(sizeof(Texture) == 0x60, "texture header size");
static unsigned int flushCount, flushSize;
static void* flushAddress;
void DCStoreRange(void* address, unsigned int size) {
    flushCount++;
    flushAddress = address;
    flushSize = size;
}
EXPORT void resetFlush(void) { flushCount = 0; }
EXPORT unsigned int getFlushCount(void) { return flushCount; }
EXPORT unsigned int getFlushSize(void) { return flushSize; }
EXPORT void* getFlushAddress(void) { return flushAddress; }
EXPORT void blendTextures(Texture* src1, Texture* src2, f32 blend, Texture* dst)
''' + source[start:end + 1] + "\n")
        library = directory / ("blend.dll" if sys.platform == "win32" else "blend.so")
        command = [compiler, "-shared", "-O2", "-ffp-contract=off", str(fixture), "-o", str(library)]
        if sys.platform == "win32":
            command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
        else:
            command += ["-fPIC"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        # Windows holds the DLL file open until it is explicitly unloaded.
        if sys.platform == "win32":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        cls.library.blendTextures.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_float, ctypes.c_void_p]
        cls.library.blendTextures.restype = None
        cls.library.getFlushAddress.restype = ctypes.c_void_p

    def test_tiled_formats_and_in_place_destinations(self):
        rng = random.Random(0x80069B1C)
        for format in (RGB565, RGBA8):
            for width, height in ((4, 4), (8, 4), (4, 12), (16, 8), (32, 32)):
                for weight in (-0.25, 0.0, 0.25, 0.5, 0.9, 1.0, 1.25):
                    for alias in (None, "first", "second"):
                        with self.subTest(format=format, size=(width, height), weight=weight, alias=alias):
                            a, b, out = [Texture(width, height, format, rng) for _ in range(3)]
                            if alias == "first":
                                out = a
                            elif alias == "second":
                                out = b
                            expected = reference_pixels(list(a.pixels), list(b.pixels), weight, width, height, format)
                            header = bytes(out.storage)[:HEADER_SIZE]
                            self.library.resetFlush()
                            self.library.blendTextures(a.address, b.address, weight, out.address)
                            self.assertEqual(list(out.pixels), expected)
                            self.assertEqual(bytes(out.storage)[:HEADER_SIZE], header)
                            self.assertEqual(self.library.getFlushCount(), 1)
                            self.assertEqual(self.library.getFlushSize(), out.header.dataSize)
                            self.assertEqual(self.library.getFlushAddress(), out.address + HEADER_SIZE)

    def test_invalid_arguments_do_not_write_or_flush(self):
        rng = random.Random(4)
        for case in ("null_first", "null_second", "null_destination", "format", "second_format",
                     "destination_format", "second_width", "second_height", "destination_width", "destination_height"):
            with self.subTest(case=case):
                a, b, out = [Texture(8, 8, RGB565, rng) for _ in range(3)]
                first, second, destination = a.address, b.address, out.address
                if case == "null_first":
                    first = None
                elif case == "null_second":
                    second = None
                elif case == "null_destination":
                    destination = None
                elif case == "format":
                    a.header.format = 3
                else:
                    target, field = case.split("_")
                    setattr(b.header if target == "second" else out.header, field, 6 if field == "format" else 4)
                before = bytes(out.storage)
                self.library.resetFlush()
                self.library.blendTextures(first, second, 0.5, destination)
                self.assertEqual(bytes(out.storage), before)
                self.assertEqual(self.library.getFlushCount(), 0)


if __name__ == "__main__":
    unittest.main()
