"""Exercise the production ground-query coordinator with controlled geometry hits.

The triangle collector and transforms are mocks; this tests bounds, dispatch,
capacity, result ownership and ordering, not triangle intersection arithmetic.
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


def record(source, name):
    return re.search(r"typedef struct " + name + r"\s*\{.*?\}\s*" + name + r";",
                     source, re.S).group()


def declaration(source, name):
    return re.search(r"^[\w* ]+\b" + name + r"(?:\[\d+\])?;", source, re.M).group()


class TrackGroundQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/track_dolphin.c").read_text()
        hits = (ROOT / "include/main/track_hit_results.h").read_text()
        track = (ROOT / "include/main/track_dolphin.h").read_text()
        function = re.search(r"^int trackGetHeight\(.*?^\}", source, re.M | re.S).group()
        declarations = "\n".join(declaration(source, name) for name in (
            "gTrackBlockDescriptors", "gTrackGroundHits", "gTrackGroundHitOrder",
            "gActiveTrackBlockCount", "gTrackGroundHitCount", "gTrackGroundHitWriteCursor",
            "gTrackGroundHitPtrs", "gTrackTriangleBuffer"))
        triangle = re.search(r"^struct TrackTriangle \{.*?^\};", source, re.M | re.S).group()
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-ground-query-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "query.c"
        fixture.write_text(r'''
typedef float f32;
typedef int s32;
typedef short s16;
typedef signed char s8;
typedef unsigned char u8;
typedef struct GameObject { int unused; } GameObject;
typedef struct TrackTriangle TrackTriangle;
#define NULL ((void*)0)
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
''' + record(hits, "TrackGroundHit") + record(hits, "TrackQueryBounds") +
                           record(track, "TrackBlockDescriptor") + triangle + declarations + r'''
static GameObject objects[2], queryObject;
static TrackTriangle triangles[11];
static int matrixTokens[2];
static float inputHeights[35];
static int requests[2], broadphaseCalls, collectCalls, transformCalls, valid, nextHit;
static TrackGroundHit** output;

static void trackIntersectBroadphase(GameObject* obj, TrackQueryBounds* bounds, int mask, int mode) {
    broadphaseCalls++;
    valid &= obj == &queryObject && mask == 0x42 && mode == 1;
    valid &= bounds->minX == 2 && bounds->maxX == 2;
    valid &= bounds->minY == -9989 && bounds->maxY == 10010;
    valid &= bounds->minZ == -3 && bounds->maxZ == -3;
}
static void Matrix_TransformPoint(void* matrix, float x, float y, float z,
                                  float* tx, float* ty, float* tz) {
    valid &= matrix == gTrackBlockDescriptors[collectCalls].currentMatrix;
    valid &= x == 2.75f && y == 0.0f && z == -3.5f;
    transformCalls++;
    *tx = x + 100.0f;
    *ty = 7.0f;
    *tz = z - 50.0f;
}
static int expectedMode;
static void trackCollectGroundHits(TrackTriangle* first, TrackTriangle* end,
                                   TrackBlockDescriptor* desc, float x, float z, int mode) {
    int block = collectCalls++, i;
    valid &= block < 2 && desc == &gTrackBlockDescriptors[block];
    valid &= first == triangles + (block == 0 ? 3 : 7);
    valid &= end == triangles + (block == 0 ? 7 : 11);
    valid &= mode == expectedMode;
    valid &= x == (desc->object ? 102.75f : 2.75f);
    valid &= z == (desc->object ? -53.5f : -3.5f);
    for (i = 0; i < requests[block] && gTrackGroundHitCount < 35; i++) {
        TrackGroundHit* hit = gTrackGroundHitWriteCursor++;
        valid &= hit == &gTrackGroundHits[nextHit];
        hit->height = inputHeights[nextHit];
        hit->normalX = nextHit + 1.0f;
        hit->normalY = nextHit + 2.0f;
        hit->normalZ = nextHit + 3.0f;
        hit->object = desc->object;
        hit->surfaceType = nextHit;
        nextHit++;
        gTrackGroundHitCount++;
    }
}
''' + function + r'''
EXPORT int runQuery(int blocks, int firstCount, int secondCount, int objectMask,
                    int mode, const float* heights) {
    int i;
    valid = 1;
    broadphaseCalls = collectCalls = transformCalls = nextHit = 0;
    requests[0] = firstCount;
    requests[1] = secondCount;
    expectedMode = mode >= 0 ? mode : mode == -1 ? 0 : 1;
    for (i = 0; i < 35; i++) inputHeights[i] = heights[i];
    for (i = 0; i < 2; i++) {
        gTrackBlockDescriptors[i].object = objectMask & (1 << i) ? &objects[i] : NULL;
        gTrackBlockDescriptors[i].currentMatrix = &matrixTokens[i];
    }
    gTrackBlockDescriptors[0].firstTriangle = 3;
    gTrackBlockDescriptors[1].firstTriangle = 7;
    gTrackBlockDescriptors[2].firstTriangle = 11;
    gActiveTrackBlockCount = blocks;
    gTrackTriangleBuffer = triangles;
    output = NULL;
    return trackGetHeight(&queryObject, 2.75f, 10.25f, -3.5f, &output, mode, 0x42);
}
EXPORT int lifecycleIsValid(int broadphase, int collectors, int transforms) {
    return valid && broadphaseCalls == broadphase && collectCalls == collectors &&
           transformCalls == transforms && output == gTrackGroundHitOrder &&
           gTrackGroundHitPtrs == gTrackGroundHitOrder &&
           gTrackGroundHitWriteCursor == gTrackGroundHits + nextHit;
}
EXPORT int orderedIndex(int index) {
    return (int)(output[index] - gTrackGroundHits);
}
EXPORT int recordsAreUnchanged(int firstCount, int objectMask) {
    int i;
    for (i = 0; i < nextHit; i++) {
        int block = i < firstCount ? 0 : 1;
        TrackGroundHit* hit = &gTrackGroundHits[i];
        if (hit->height != inputHeights[i] || hit->normalX != i + 1.0f ||
            hit->normalY != i + 2.0f || hit->normalZ != i + 3.0f || hit->surfaceType != i ||
            hit->object != (objectMask & (1 << block) ? &objects[block] : NULL)) return 0;
    }
    return 1;
}
EXPORT int capacitiesAreValid(void) {
    return sizeof(gTrackGroundHits) / sizeof(gTrackGroundHits[0]) == 35 &&
           sizeof(gTrackGroundHitOrder) / sizeof(gTrackGroundHitOrder[0]) == 35 &&
           sizeof(gTrackBlockDescriptors) / sizeof(gTrackBlockDescriptors[0]) == 20;
}
''')
        library = directory / ("query.dll" if sys.platform == "win32" else "query.so")
        command = [compiler, "-shared", "-O2", "-fno-builtin", str(fixture), "-o", str(library)]
        command += (["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
                    if sys.platform == "win32" else ["-fPIC"])
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        if sys.platform == "win32":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        for name, args in {
            "runQuery": [ctypes.c_int] * 5 + [ctypes.POINTER(ctypes.c_float)],
            "lifecycleIsValid": [ctypes.c_int] * 3,
            "orderedIndex": [ctypes.c_int],
            "recordsAreUnchanged": [ctypes.c_int] * 2,
            "capacitiesAreValid": [],
        }.items():
            function = getattr(cls.library, name)
            function.argtypes = args
            function.restype = ctypes.c_int

    def check_query(self, blocks, first, second, mask, mode, heights):
        values = (ctypes.c_float * 35)(*(heights + [0.0] * (35 - len(heights))))
        count = min(35, (first if blocks else 0) + (second if blocks > 1 else 0))
        collectors = min(blocks, 1) + (blocks > 1 and first < 35)
        transforms = sum(bool(mask & (1 << i)) for i in range(collectors))
        self.assertEqual(self.library.capacitiesAreValid(), 1)
        self.assertEqual(self.library.runQuery(blocks, first, second, mask, mode, values), count)
        self.assertEqual(self.library.lifecycleIsValid(mode >= 0, collectors, transforms), 1)
        self.assertEqual(self.library.recordsAreUnchanged(first, mask), 1)
        self.assertEqual([self.library.orderedIndex(i) for i in range(count)],
                         sorted(range(count), key=lambda i: -values[i]))

    def test_modes_and_coordinate_spaces(self):
        for mode in (0, 1, 2, -1, -2, -99):
            for mask in range(4):
                with self.subTest(mode=mode, mask=mask):
                    self.check_query(2, 2, 3, mask, mode, [3.0, -2.0, 7.0, 3.0, 0.0])

    def test_empty_capacity_and_repeated_queries(self):
        rng = random.Random(0x8000C6B4)
        for blocks, first, second in ((0, 0, 0), (1, 1, 0), (2, 0, 0), (2, 17, 17),
                                      (2, 18, 17), (2, 35, 1), (0, 0, 0), (1, 1, 0)):
            with self.subTest(blocks=blocks, first=first, second=second):
                self.check_query(blocks, first, second, 3, 0,
                                 [float(rng.randrange(-100, 100)) for _ in range(35)])

    def test_stable_order(self):
        for heights in ([4.0] * 35, list(map(float, range(35))),
                        list(map(float, reversed(range(35))))):
            self.check_query(2, 18, 17, 2, -1, heights)


if __name__ == "__main__":
    unittest.main()
