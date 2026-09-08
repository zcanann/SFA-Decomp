"""Exercise the production intersection wrapper with controlled engine callbacks.

Checks result initialization, capacity, normal conversion, contact registration
and mask ownership. Triangle geometry and pointer-bearing retail layouts are
outside this host harness; MWCC layout assertions and objdiff cover the latter.
"""

import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def record(source, name):
    return re.search(r'typedef struct ' + name + r' \{.*?\} ' + name + ';', source, re.S)[0]


class IntersectWrapperTests(unittest.TestCase):
    def test_result_lifecycle(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required')
        source = (ROOT / 'src/main/track_dolphin.c').read_text()
        header = (ROOT / 'include/main/track_hit_results.h').read_text()
        track = (ROOT / 'include/main/track_dolphin.h').read_text()
        start, end = find_function_body(source, 'trackGetIntersect')
        declaration = source.rfind('\n', 0, source.rfind('trackGetIntersect', 0, start)) + 1
        function = source[declaration:end + 1]
        capacity = re.search(r'^#define TRACK_HIT_MAX_POINTS .*$', header, re.M)[0]
        fixture = r'''
#include <string.h>
typedef float f32;
typedef short s16;
typedef signed char s8;
typedef unsigned char u8;
typedef struct GameObject { int id; } GameObject;
typedef struct TrackTriangle { int unused; } TrackTriangle;
''' + capacity + '\n' + record(header, 'TrackHitResults') + '\n' + record(track, 'TrackBlockDescriptor') + r'''
static TrackTriangle triangles[6];
static TrackTriangle* gTrackTriangleBuffer = triangles;
static TrackBlockDescriptor gTrackBlockDescriptors[2];
static GameObject owners[4], contactSource;
static f32 fromPoints[12], toPoints[12];
static int expectedCount, requestedMask, expectedContact, valid, queries, transforms, contacts;
static TrackHitResults* activeResults;
#define CHECK(test) (valid &= !!(test))

static int trackGetIntersect2(int mode, void* first, void* last, f32* from, f32* to,
                             int count, void* storage, int flags) {
    TrackHitResults* results = storage;
    int i, hits = 0;
    queries++;
    CHECK(mode == 0 && flags == 0 && count == expectedCount);
    CHECK(first == triangles + 1 && last == triangles + 4);
    CHECK(from == fromPoints && to == toPoints && results == activeResults);
    CHECK(results->hitCount == 0 && results->hitMask == 0x66);
    for (i = 0; i < 4; i++) {
        CHECK(results->radii[i] == i + 0.5f && results->queryTypes[i] == i + 1);
        CHECK(results->surfaceTypes[i] == -1 && results->triangleFlags[i] == 0x88);
    }
    for (i = 0; i < expectedCount; i++) {
        CHECK(results->planes[i][0] == 0 && results->planes[i][1] == 1);
        CHECK(results->planes[i][2] == 0 && results->planes[i][3] == 0);
        CHECK(results->objects[i] == NULL);
        results->planes[i][0] = i + 1;
        results->planes[i][1] = i + 2;
        results->planes[i][2] = i + 3;
        results->planes[i][3] = i + 4;
        if (requestedMask & (1 << i)) {
            results->objects[i] = &owners[i];
            hits++;
        }
    }
    results->hitCount = hits;
    return requestedMask;
}

static void Obj_TransformLocalVectorByWorldMatrix(GameObject* object, f32* in, f32* out) {
    int i = object->id;
    CHECK(i >= 0 && i < expectedCount && in == activeResults->planes[i] && out == in);
    CHECK(requestedMask & (1 << i));
    transforms++;
    out[0] += 10;
    out[1] *= 2;
    out[2] = -out[2];
}

static void ObjHits_AddContactObject(GameObject* object, GameObject* source) {
    CHECK(expectedContact && source == &contactSource && object == &owners[object->id]);
    CHECK(requestedMask & (1 << object->id));
    CHECK(transforms == contacts + 1);
    contacts++;
}
''' + function + r'''

int runCase(int suppliedCount, int wantedCount, int mask, int hasContact) {
    TrackHitResults results, before;
    int i, j, expectedHits = 0, returned;
    memset(&results, 0, sizeof(results));
    for (i = 0; i < 4; i++) {
        owners[i].id = i;
        for (j = 0; j < 4; j++) results.planes[i][j] = 99;
        results.objects[i] = &contactSource;
        results.radii[i] = i + 0.5f;
        results.queryTypes[i] = i + 1;
        results.surfaceTypes[i] = -1;
        results.triangleFlags[i] = 0x88;
    }
    results.hitCount = 99;
    results.hitMask = 0x66;
    before = results;
    activeResults = &results;
    expectedCount = wantedCount;
    requestedMask = mask;
    expectedContact = hasContact;
    gTrackBlockDescriptors[0].firstTriangle = 1;
    gTrackBlockDescriptors[1].firstTriangle = 4;
    valid = 1;
    queries = transforms = contacts = 0;
    returned = trackGetIntersect(hasContact ? &contactSource : NULL, fromPoints, toPoints,
                                suppliedCount, &results, 0x123);
    CHECK(queries == 1 && returned == (mask & 0xff) && results.hitMask == (mask & 0xff));
    CHECK(memcmp(before.radii, results.radii, sizeof(results.radii)) == 0);
    CHECK(memcmp(before.queryTypes, results.queryTypes, sizeof(results.queryTypes)) == 0);
    CHECK(memcmp(before.surfaceTypes, results.surfaceTypes, sizeof(results.surfaceTypes)) == 0);
    CHECK(memcmp(before.triangleFlags, results.triangleFlags, sizeof(results.triangleFlags)) == 0);
    for (i = 0; i < 4; i++) {
        if (i >= wantedCount) {
            CHECK(memcmp(results.planes[i], before.planes[i], sizeof(results.planes[i])) == 0);
            CHECK(results.objects[i] == before.objects[i]);
        } else {
            int hit = (mask & (1 << i)) != 0;
            expectedHits += hit;
            CHECK(results.planes[i][0] == i + 1 + (hit ? 10 : 0));
            CHECK(results.planes[i][1] == (i + 2) * (hit ? 2 : 1));
            CHECK(results.planes[i][2] == (i + 3) * (hit ? -1 : 1));
            CHECK(results.planes[i][3] == i + 4);
            CHECK(results.objects[i] == (hit ? &owners[i] : NULL));
        }
    }
    CHECK(results.hitCount == expectedHits && transforms == expectedHits);
    CHECK(contacts == (hasContact ? expectedHits : 0));
    return valid;
}
'''
        with tempfile.TemporaryDirectory(prefix='sfa-track-wrapper-') as tmp:
            path = Path(tmp) / 'wrapper.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                library = Path(tmp) / ('wrapper' + optimization + '.so')
                subprocess.run([compiler, '-std=c99', optimization, '-shared', '-fPIC',
                                str(path), '-o', str(library)], check=True, capture_output=True, timeout=30)
                run = ctypes.CDLL(str(library)).runCase
                run.argtypes = [ctypes.c_int] * 4
                run.restype = ctypes.c_int
                count = 0
                for supplied, expected in ((-3, -3), (0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 4), (9, 4)):
                    for mask in (0, 1, 5, 15, 0xa5, 0x1ff):
                        for contact in (0, 1):
                            args = supplied, expected, mask, contact
                            self.assertEqual(run(*args), 1, (optimization, args))
                            count += 1
                print(f'{optimization}: {count} wrapper scenarios passed')


if __name__ == '__main__':
    unittest.main()
