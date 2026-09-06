"""Exercise the recovered generator's addressing and external-call contract.

Noise sampling and trigonometry are controlled dependencies here, not substitutes
for the retail numerical algorithms. The sampler has a separate exact PPC match.
"""
import ctypes
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body
from test_shadow_texture_blend import HEADER_SIZE, ROOT, TextureHeader


class ShadowNoiseGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/newshadows.c").read_text()
        start, end = find_function_body(source, "newshadows_initProceduralTextures")
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-shadow-noise-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "noise.c"
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef float f32;
#define NEW_SHADOW_MAX_NOISE_PLACEMENTS 50
#define NEW_SHADOW_NOISE_FRAME_COUNT 16
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
typedef struct Texture { u8 prefix[0x44]; u32 dataSize; u8 tail[24]; } Texture;
typedef struct NewShadowNoisePlacement {
    f32 frameCount, x, z, startRadius, endRadius;
} NewShadowNoisePlacement;
typedef struct NewShadowNoiseData {
    NewShadowNoisePlacement placements[50];
    u8 unknownTail[0x60];
} NewShadowNoiseData;
_Static_assert(sizeof(Texture) == 0x60, "texture size");
_Static_assert(sizeof(NewShadowNoiseData) == 0x448, "noise data size");
static NewShadowNoiseData gNewShadowNoiseData;
static Texture* gNewShadowNoiseTexFrames[16];
static Texture* gNewShadowCausticTexture;
static f32 gNewShadowReflectionScrollX, gNewShadowReflectionScrollY;
static Texture** textures;
static int allocationCount, flushCount, randomCount, sampleCount, sinCount, cosCount, valid;
static int heapCalls;
static u8 heap;
float sqrtf(float);
static float __fabsf(float value) { return __builtin_fabsf(value); }
static u8 mmSetForceHeap3Only(u8 value) {
    u8 previous = heap;
    heap = value;
    heapCalls++;
    return previous;
}
static int randomGetRange(int minimum, int maximum) {
    randomCount++;
    /* Two identical centers force the second placement's retry limit. */
    return maximum == 999 ? 500 : minimum;
}
static Texture* textureAlloc(int width, int height, int format, int a, int b,
                             int c, int d, int e, int f) {
    valid &= width == 64 && height == 64 && format == 3 &&
             a == 0 && b == 0 && c == 1 && d == 1 && e == 1 && f == 1 && heap == 1;
    if (allocationCount >= 17) { valid = 0; return textures[16]; }
    return textures[allocationCount++];
}
static void DCFlushRange(void* address, u32 size) {
    valid &= allocationCount == flushCount + 1 && size == 8192;
    if (flushCount < 17) { valid &= address == textures[flushCount] + 1; }
    else { valid = 0; }
    flushCount++;
}
static void evalNoisePlacements(f32 x, f32 z, f32 frame,
    const NewShadowNoisePlacement* placements, int count, f32* shift, f32* intensity) {
    valid &= count == 2 && placements == gNewShadowNoiseData.placements;
    valid &= frame == sampleCount / 4096;
    sampleCount++;
    *shift = x;
    *intensity = z;
}
static f32 mathSinfHighPrecision(f32 phase) {
    valid &= __fabsf(phase - (6.284f / 16.0f) * (sinCount % 64)) < 0.00001f;
    sinCount++;
    return 0.25f;
}
static f32 mathCosfHighPrecision(f32 phase) {
    int pixel = cosCount / 2;
    f32 expected = (cosCount & 1) ? (6.284f / 16.0f) * (pixel % 64)
                                 : 0.125f + (6.284f / 64.0f) * (pixel / 64);
    valid &= __fabsf(phase - expected) < 0.00001f;
    cosCount++;
    return 0.5f;
}
static void newshadows_initProceduralTextures(void)
''' + source[start:end + 1] + r'''
EXPORT int generate(Texture** targets) {
    int i;
    u8* state = (u8*)&gNewShadowNoiseData;
    for (i = 0; i < sizeof(gNewShadowNoiseData); i++) { state[i] = 0; }
    for (i = 0; i < 0x60; i++) { gNewShadowNoiseData.unknownTail[i] = 0xAB; }
    textures = targets;
    allocationCount = flushCount = randomCount = sampleCount = sinCount = cosCount = heapCalls = 0;
    valid = 1;
    heap = 7;
    gNewShadowReflectionScrollX = gNewShadowReflectionScrollY = 10.0f;
    newshadows_initProceduralTextures();
    valid &= allocationCount == 17 && flushCount == 17 && randomCount == 20008;
    valid &= sampleCount == 65536 && sinCount == 4096 && cosCount == 8192 && heap == 7 && heapCalls == 2;
    valid &= gNewShadowReflectionScrollX == 0 && gNewShadowReflectionScrollY == 0;
    valid &= gNewShadowCausticTexture == targets[16];
    for (i = 0; i < 16; i++) { valid &= gNewShadowNoiseTexFrames[i] == targets[i]; }
    for (i = 0; i < 2; i++) {
        NewShadowNoisePlacement* p = &gNewShadowNoiseData.placements[i];
        valid &= p->frameCount == 8 && p->x == 0.5f && p->z == 0.5f;
        valid &= __fabsf(p->startRadius - 0.05f) < 0.000001f;
        valid &= __fabsf(p->endRadius - 0.01f) < 0.000001f;
    }
    for (i = 2 * sizeof(NewShadowNoisePlacement); i < 50 * sizeof(NewShadowNoisePlacement); i++) {
        valid &= state[i] == 0;
    }
    for (i = 0; i < 0x60; i++) { valid &= gNewShadowNoiseData.unknownTail[i] == 0xAB; }
    return valid;
}
''')
        library = directory / ("noise.dll" if sys.platform == "win32" else "noise.so")
        command = [compiler, "-shared", "-O2", "-ffp-contract=off", "-fno-math-errno", "-fno-builtin-memset", str(fixture), "-o", str(library)]
        command += ["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"] if sys.platform == "win32" else ["-fPIC"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        if sys.platform == "win32":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        cls.library.generate.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        cls.library.generate.restype = ctypes.c_int

    def test_retry_limit_tiled_channels_and_resource_lifecycle(self):
        buffers, headers = [], []
        for _ in range(17):
            storage = (ctypes.c_ubyte * (HEADER_SIZE + 8192 + 32))()
            ctypes.memset(storage, 0xCD, len(storage))
            TextureHeader.from_buffer(storage).dataSize = 8192
            buffers.append(storage)
            headers.append(bytes(storage[:HEADER_SIZE]))
        addresses = (ctypes.c_void_p * 17)(*[ctypes.addressof(b) for b in buffers])
        self.assertEqual(self.library.generate(addresses), 1)
        for frame, storage in enumerate(buffers):
            self.assertEqual(bytes(storage[:HEADER_SIZE]), headers[frame])
            self.assertEqual(bytes(storage[-32:]), bytes([0xCD]) * 32)
            pixels = (ctypes.c_ushort * 4096).from_buffer(storage, HEADER_SIZE)
            for y in range(64):
                for x in range(64):
                    tile = (y // 4) * 16 + x // 4
                    pixel = (y % 4) * 4 + x % 4
                    expected = ((255 * y // 64) << 8) | (255 * x // 64) if frame < 16 else (158 << 8) | 190
                    self.assertEqual(pixels[tile * 16 + pixel], expected, (frame, x, y))


if __name__ == "__main__":
    unittest.main()
