"""Check surface response against line/plane and constrained-projection geometry.

Compile the production response/helper and vector normalization. Host libm stands
in for the game's approximations; this is geometry coverage, not Gekko rounding.
"""
import ctypes
import math
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
F32 = ctypes.c_float
FLOAT_PTR = ctypes.POINTER(F32)


def function(source, name):
    # Do not start at the forward declaration and consume an unrelated body.
    return re.search(r"^(?:static inline )?(?:int|f32|void) " + name +
                     r"\([^;{}]*\) \{.*?^\}", source, re.M | re.S).group()


class SurfaceResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-surface-response-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        source = (ROOT / "src/main/track_dolphin.c").read_text()
        vectors = (ROOT / "src/main/vecmath_vec3.c").read_text()
        fixture = directory / "response.c"
        fixture.write_text('''#include <math.h>
typedef float f32;
typedef unsigned char u8;
static float mathCosfHighPrecision(float value) { return cosf(value); }
static float mathSinfHighPrecision(float value) { return sinf(value); }
static float atan2fHighPrecision(float y, float x) { return atan2f(y, x); }
''' + function(vectors, "Vec3_Normalize") + "\n" +
                           function(source, "trackProjectOntoOffsetPlane") + "\n" +
                           function(source, "trackResolveSurfacePenetration"))
        cls.libraries = []
        for optimization in ("-O0", "-O2"):
            library = directory / (optimization[1:] + ".dylib")
            subprocess.run([compiler, optimization, "-shared", "-fPIC", str(fixture),
                            "-o", str(library), "-lm"], check=True)
            dll = ctypes.CDLL(str(library))
            resolve = dll.trackResolveSurfacePenetration
            resolve.argtypes = [FLOAT_PTR] * 4 + [F32, F32, ctypes.c_ubyte]
            resolve.restype = ctypes.c_int
            cls.libraries.append((optimization, dll, resolve))

    def run_response(self, resolve, start, position, contact, plane, separation, clearance, mode):
        # Guard the only output and verify every read-only input remains intact.
        arrays = [(F32 * len(value))(*value) for value in (start, contact, plane)]
        original = [bytes(array) for array in arrays]
        guarded = (F32 * 5)(12345.0, *position, -54321.0)
        output = ctypes.cast(ctypes.byref(guarded, ctypes.sizeof(F32)), FLOAT_PTR)
        self.assertEqual(resolve(arrays[0], output, arrays[1], arrays[2], separation, clearance, mode), 1)
        self.assertEqual((guarded[0], guarded[4]), (12345.0, -54321.0))
        self.assertEqual([bytes(array) for array in arrays], original)
        return list(guarded)[1:4]

    def assert_point(self, actual, expected):
        for got, wanted in zip(actual, expected):
            self.assertTrue(math.isclose(got, wanted, rel_tol=3e-5, abs_tol=3e-5), (actual, expected))

    def test_line_intersection_and_equal_distance_fallback(self):
        cases = [
            # (start, contact, plane, clearance, expected)
            ((0, 2, 0), (4, -2, 8), (0, 1, 0, 0), 0, (2, 0, 4)),
            ((0, 2, 0), (4, -2, 8), (0, 1, 0, 0), 1, (1, 1, 2)),
            ((2, 0, 0), (-2, 4, 8), (1, 0, 0, 0), 0, (0, 2, 4)),
            # Fractions are not clamped to the segment.
            ((0, 2, 0), (4, 1, 8), (0, 1, 0, 0), 0, (8, 0, 16)),
            ((0, 2, 0), (4, 2, 8), (0, 1, 0, 0), 0, (0, 2, 0)),
            ((1, 2, 3), (1, 2, 3), (0, 1, 0, 0), 0, (1, 2, 3)),
        ]
        for optimization, _, resolve in self.libraries:
            for start, contact, plane, clearance, expected in cases:
                with self.subTest(optimization=optimization, start=start, contact=contact):
                    actual = self.run_response(resolve, start, (30, 40, 50), contact,
                                               plane, 91, clearance, 3)
                    self.assert_point(actual, expected)

    def test_all_modes_against_constrained_projection(self):
        # Binary32 normals on both sides of the strict wall/floor threshold.
        normals = [(1, 0, 0), (0, 0, -1), (0, 1, 0), (0, -1, 0)]
        for ny in (-0.9, -0.7071, -0.707, -0.7069, -0.5, 0.5, 0.7069, 0.707, 0.7071, 0.9):
            horizontal = math.sqrt(1 - ny * ny)
            normals.append((horizontal * 0.6, ny, horizontal * 0.8))
        normals = [tuple(F32(value).value for value in normal) for normal in normals]
        modes = (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 255)
        position = (1.25, -2.5, 3.75)
        threshold = F32(0.707).value
        for optimization, _, resolve in self.libraries:
            for normal in normals:
                nx, ny, nz = normal
                for desired_correction in (-1.25, 0, 0.75, 2.0):
                    offset = F32(0.625 + desired_correction - sum(a*b for a, b in zip(normal, position))).value
                    plane = (*normal, offset)
                    clearance = 0.625
                    delta = clearance - (sum(a*b for a, b in zip(normal, position)) + offset)
                    for mode in modes:
                        wall = -threshold < ny < threshold
                        horizontal = wall and mode in (1, 8, 10)
                        vertical = not wall and mode not in (5, 8)
                        if horizontal:
                            step = max(delta, 0) / (nx*nx + nz*nz)
                            expected = (position[0] + step*nx, position[1], position[2] + step*nz)
                        elif vertical:
                            expected = (position[0], position[1] + max(delta, 0)/ny, position[2])
                        else:
                            expected = tuple(value + delta*n for value, n in zip(position, normal))
                        with self.subTest(optimization=optimization, normal=normal, mode=mode, delta=delta):
                            actual = self.run_response(resolve, (10, 20, 30), position, (40, 50, 60),
                                                       plane, -1.125, clearance, mode)
                            self.assert_point(actual, expected)


if __name__ == "__main__":
    unittest.main()
