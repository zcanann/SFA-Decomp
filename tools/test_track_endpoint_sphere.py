"""Check the recovered endpoint sweep against independent ray/sphere roots.

Host vector adapters test geometry and branches, not Gekko floating-point
rounding. The production coordinator remains checked separately by objdiff.
"""
import ctypes as C
import math
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from test_track_sphere_edge import Vec, dot, function, unit

ROOT = Path(__file__).resolve().parents[1]


def oracle(center, radius_squared, origin, direction, limit):
    offset = [o - c for o, c in zip(origin, center)]
    a = dot(direction, direction)
    b = 2 * dot(offset, direction)
    c = dot(offset, offset) - radius_squared
    discriminant = b * b - 4 * a * c
    if discriminant < 0:
        return None
    # Retail selects the exit root for an interior or surface start.
    sign = -1 if c > 0 else 1
    distance = (-b + sign * math.sqrt(discriminant)) / (2 * a)
    if distance < 0 or distance > limit:
        return None
    point = [o + distance * d for o, d in zip(origin, direction)]
    normal = unit([p - c for p, c in zip(point, center)])
    return distance, point, normal + [math.sqrt(radius_squared) - dot(point, normal)]


class EndpointSphereTests(unittest.TestCase):
    def test_endpoint_sweeps(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required')
        source = (ROOT / 'src/main/track_dolphin.c').read_text()
        fixture = '''#include <math.h>
typedef float f32;
typedef struct { float x, y, z; } Vec;
static void PSVECSubtract(const Vec* a, const Vec* b, Vec* out) {
 out->x=a->x-b->x; out->y=a->y-b->y; out->z=a->z-b->z;
}
static void PSVECAdd(const Vec* a, const Vec* b, Vec* out) {
 out->x=a->x+b->x; out->y=a->y+b->y; out->z=a->z+b->z;
}
static float PSVECDotProduct(const Vec* a, const Vec* b) {
 return a->x*b->x+a->y*b->y+a->z*b->z;
}
static float PSVECSquareMag(const Vec* a) { return PSVECDotProduct(a,a); }
static void PSVECScale(const Vec* a, Vec* out, float scale) {
 out->x=a->x*scale; out->y=a->y*scale; out->z=a->z*scale;
}
static void PSVECNormalize(const Vec* a, Vec* out) {
 float scale=1.0f/sqrtf(PSVECSquareMag(a)); PSVECScale(a,out,scale);
}
'''
        fixture += function(source, 'trackSweepEndpointSphere').replace('static inline ', '')
        cases = []
        for origin, direction, limit in (
                ((3, 0, 0), (-1, 0, 0), 5), ((3, 0, 0), (1, 0, 0), 5),
                ((3, 2, 0), (-1, 0, 0), 5), ((3, 1, 0), (-1, 0, 0), 5),
                ((0, 0, 0), (1, 0, 0), 5), ((0.5, 0, 0), (-1, 0, 0), 5),
                ((1, 0, 0), (1, 0, 0), 5), ((1, 0, 0), (-1, 0, 0), 5),
                ((3, 0, 0), (-1, 0, 0), 1), ((3, 0, 0), (-1, 0, 0), 2),
                ((3, 0, 0), (-1, 0, 0), -1)):
            cases.append((Vec(0, 0, 0), 1.0, Vec(*origin), Vec(*direction), limit))
        rng = random.Random(0x80066000)
        for index in range(600):
            center = Vec(*(rng.uniform(-5, 5) for _ in range(3)))
            radius = rng.uniform(0.2, 2)
            radial = unit([rng.uniform(-1, 1) for _ in range(3)])
            distance = radius * (rng.uniform(0.1, 0.9) if index % 3 == 0 else rng.uniform(1.2, 4))
            origin = Vec(*(c + distance * n for c, n in zip(center, radial)))
            direction = Vec(*([-n for n in radial] if index % 3 else unit([rng.uniform(-1, 1) for _ in range(3)])))
            cases.append((center, C.c_float(radius * radius).value, origin, direction, 10))
        for _ in range(600):
            center = Vec(*(rng.uniform(-5, 5) for _ in range(3)))
            origin = Vec(*(rng.uniform(-5, 5) for _ in range(3)))
            direction = Vec(*unit([rng.uniform(-1, 1) for _ in range(3)]))
            radius = rng.uniform(0.2, 2)
            cases.append((center, C.c_float(radius * radius).value, origin, direction, 10))
        with tempfile.TemporaryDirectory(prefix='sfa-endpoint-') as tmp:
            path = Path(tmp) / 'endpoint.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                library = Path(tmp) / ('endpoint' + optimization + '.so')
                subprocess.run([compiler, '-std=c11', optimization, '-shared', '-fPIC',
                                '-fno-strict-aliasing', str(path), '-o', str(library)],
                               check=True, capture_output=True, timeout=30)
                sweep = C.CDLL(str(library)).trackSweepEndpointSphere
                pointer = C.POINTER(C.c_float)
                sweep.argtypes = [pointer, C.c_float, pointer, pointer, C.c_float, pointer, pointer, pointer]
                sweep.restype = C.c_int
                hits = 0
                for index, (center, radius_squared, origin, direction, limit) in enumerate(cases):
                    expected = oracle(center, radius_squared, origin, direction, limit)
                    point, plane, distance = Vec(99, 99, 99), (C.c_float * 4)(99, 99, 99, 99), C.c_float(99)
                    before = bytes(center), bytes(origin), bytes(direction)
                    actual = sweep(center, radius_squared, origin, direction, limit, point, plane, C.byref(distance))
                    self.assertEqual(actual, int(expected is not None), (optimization, index))
                    self.assertEqual(before, (bytes(center), bytes(origin), bytes(direction)))
                    if expected is None:
                        self.assertEqual((*point, *plane, distance.value), (99,) * 8)
                    else:
                        hits += 1
                        for value, want in zip((distance.value, *point, *plane), (expected[0], *expected[1], *expected[2])):
                            self.assertAlmostEqual(value, want, delta=3e-4, msg=(optimization, index))
                print(f'{optimization}: {len(cases)} endpoint sweeps passed ({hits} hits)')


if __name__ == '__main__':
    unittest.main()
