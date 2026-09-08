"""Check the production edge sweep against an independent cylinder quadratic.

Uses production vector helpers and the pointer-free edge record. The oracle
checks the finite cylinder side only; triangle faces and endpoint spheres are
handled separately by the coordinator and are outside this test's scope.
"""

import ctypes as C
import math
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
Vec = C.c_float * 3


class Edge(C.Structure):
    _fields_ = [('start', Vec), ('end', Vec), ('direction', Vec),
                ('radius', C.c_float), ('radiusSquared', C.c_float), ('length', C.c_float)]


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def unit(v):
    length = math.sqrt(dot(v, v))
    return [x / length for x in v]


def oracle(edge, origin, direction, limit):
    axis = list(edge.direction)
    offset = [o - a for o, a in zip(origin, edge.start)]
    ray_along, origin_along = dot(direction, axis), dot(offset, axis)
    ray_perp = [d - ray_along * e for d, e in zip(direction, axis)]
    origin_perp = [o - origin_along * e for o, e in zip(offset, axis)]
    a = dot(ray_perp, ray_perp)
    b = dot(ray_perp, origin_perp)
    c = dot(origin_perp, origin_perp) - edge.radiusSquared
    if a < 1e-12:
        return None
    discriminant = b * b - a * c
    if discriminant < -1e-8:
        return None
    distance = (-b - math.sqrt(max(discriminant, 0))) / a
    along = origin_along + distance * ray_along
    if distance < 0 or distance > limit or along < 0 or along > edge.length:
        return None
    center = [o + distance * d for o, d in zip(origin, direction)]
    normal = unit([p - (s + along * e) for p, s, e in zip(center, edge.start, axis)])
    return distance, center, normal + [edge.radius - dot(center, normal)]


def function(source, name):
    start, end = find_function_body(source, name)
    declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
    return source[declaration:end + 1]


class SphereEdgeTests(unittest.TestCase):
    def test_finite_edge_sweeps(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required')
        source = (ROOT / 'src/main/track_dolphin.c').read_text()
        header = (ROOT / 'include/main/track_dolphin.h').read_text()
        vectors = (ROOT / 'src/main/vecmath_vec3.c').read_text()
        record = re.search(r'typedef struct TrackSphereSweepEdge \{.*?\} TrackSphereSweepEdge;', header, re.S)[0]
        fixture = '#include <math.h>\n#include <stddef.h>\ntypedef float f32;\ntypedef unsigned char u8;\n'
        fixture += record + '\n'
        for field, offset in (('start', 0), ('end', 12), ('direction', 24),
                              ('radius', 36), ('radiusSquared', 40), ('length', 44)):
            fixture += f'_Static_assert(offsetof(TrackSphereSweepEdge, {field}) == {offset}, "{field}");\n'
        fixture += '_Static_assert(sizeof(TrackSphereSweepEdge) == 48, "size");\n'
        fixture += function(vectors, 'Vec3_Normalize') + '\n' + function(vectors, 'Vec3_Cross') + '\n'
        fixture += function(source, 'trackSweepSphereAgainstEdge')
        cases = []
        # Hits, misses, parallel motion, interior starts, endpoint rejection,
        # tangent contact and an entry beyond the supplied movement length.
        for origin, direction, limit in (
                ((3, 0, 2), (-1, 0, 0), 5), ((3, 2, 2), (-1, 0, 0), 5),
                ((3, 0, 2), (0, 0, 1), 5), ((0.5, 0, 2), (-1, 0, 0), 5),
                ((3, 0, -1), (-1, 0, 0), 5), ((3, 0, 5), (-1, 0, 0), 5),
                ((3, 1, 2), (-1, 0, 0), 5), ((3, 0, 2), (-1, 0, 0), 1)):
            cases.append((Edge(Vec(0, 0, 0), Vec(0, 0, 4), Vec(0, 0, 1), 1, 1, 4),
                          Vec(*origin), Vec(*direction), limit))
        rng = random.Random(0x80066100)
        for _ in range(300):
            start = [rng.uniform(-5, 5) for _ in range(3)]
            axis = unit([rng.uniform(-1, 1) for _ in range(3)])
            length, radius = rng.uniform(1, 8), rng.uniform(0.2, 2)
            end = [s + e * length for s, e in zip(start, axis)]
            edge = Edge(Vec(*start), Vec(*end), Vec(*axis), radius, radius * radius, length)
            origin = Vec(*(s + rng.uniform(-4, 4) for s in start))
            direction = Vec(*unit([rng.uniform(-1, 1) for _ in range(3)]))
            cases.append((edge, origin, direction, 10))
        # Oriented interior-edge entries exercise successful contacts broadly.
        for _ in range(200):
            axis = unit([rng.uniform(-1, 1) for _ in range(3)])
            candidate = [rng.uniform(-1, 1) for _ in range(3)]
            radial = unit([v - dot(candidate, axis) * e for v, e in zip(candidate, axis)])
            start = [rng.uniform(-5, 5) for _ in range(3)]
            length, radius = rng.uniform(2, 8), rng.uniform(0.2, 2)
            along = length * rng.uniform(0.2, 0.8)
            end = [s + e * length for s, e in zip(start, axis)]
            edge = Edge(Vec(*start), Vec(*end), Vec(*axis), radius, radius * radius, length)
            origin = Vec(*(s + along * e + (radius + 3) * n for s, e, n in zip(start, axis, radial)))
            cases.append((edge, origin, Vec(*[-n for n in radial]), 10))
        with tempfile.TemporaryDirectory(prefix='sfa-edge-') as tmp:
            path = Path(tmp) / 'edge.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                library = Path(tmp) / ('edge' + optimization + '.so')
                subprocess.run([compiler, '-std=c11', optimization, '-shared', '-fPIC',
                                '-fno-strict-aliasing', str(path), '-o', str(library)],
                               check=True, capture_output=True, timeout=30)
                sweep = C.CDLL(str(library)).trackSweepSphereAgainstEdge
                pointer = C.POINTER(C.c_float)
                sweep.argtypes = [C.POINTER(Edge), pointer, pointer, C.c_float, pointer,
                                  pointer, C.c_float, pointer, C.c_float]
                sweep.restype = C.c_int
                hits = 0
                for index, (edge, origin, direction, limit) in enumerate(cases):
                    expected = oracle(edge, origin, direction, limit)
                    point, plane, distance = Vec(99, 99, 99), (C.c_float * 4)(99, 99, 99, 99), C.c_float(99)
                    before = bytes(edge), bytes(origin), bytes(direction)
                    actual = sweep(C.byref(edge), origin, direction, limit, point, plane,
                                   edge.radius + 0.01, C.byref(distance), 0)
                    self.assertEqual(actual, 0 if expected is None else 3, (optimization, index))
                    self.assertEqual(before, (bytes(edge), bytes(origin), bytes(direction)))
                    if expected is None:
                        self.assertEqual((*point, *plane, distance.value), (99,) * 8)
                    else:
                        hits += 1
                        values = (distance.value, *point, *plane)
                        target = (expected[0], *expected[1], *expected[2])
                        for value, want in zip(values, target):
                            self.assertAlmostEqual(value, want, delta=2e-4, msg=(optimization, index))
                print(f'{optimization}: {len(cases)} edge sweeps passed ({hits} hits)')


if __name__ == '__main__':
    unittest.main()
