"""Check production track-contact sphere selection against a host-side oracle.

Geometry is mocked. Retail layouts and code generation are checked separately;
this exercises mask selection, packed links, buffer selection, capacity and the
contact result consumed by the caller.
"""
import ctypes
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def record(text, name):
    return re.search(r'typedef struct ' + name + r' \{.*?\} ' + name + ';', text, re.S)[0]


def fixture():
    source = (ROOT / 'src/main/objhits.c').read_text()
    start, end = find_function_body(source, 'ObjHits_CheckTrackContact')
    function = source[source.rfind('\nvoid ', 0, start) + 1:end + 1]
    model = (ROOT / 'include/main/model.h').read_text()
    track = (ROOT / 'include/main/track_hit_results.h').read_text()
    flags = (ROOT / 'include/main/objhits.h').read_text()
    types = (ROOT / 'include/main/objhits_types.h').read_text()
    constants = '\n'.join(re.findall(
        r'^#define (?:TRACK_HIT_MAX_POINTS|OBJHITS_SHAPE_MODEL_HIT_VOLUMES|OBJHITS_CONTACT_FLAG_KIND_NONZERO|OBJHITS_CONTACT_FLAG_KIND0)\s+[^\n]+',
        track + '\n' + flags + '\n' + types, re.M))
    return r'''
#include <string.h>
typedef float f32;
typedef unsigned int u32;
typedef int s32;
typedef unsigned short u16;
typedef short s16;
typedef unsigned char u8;
typedef signed char s8;
typedef struct GameObject GameObject;
typedef struct Vec { float x, y, z; } Vec;
''' + constants + '\n' + '\n'.join(record(text, name) for text, name in [
        (model, 'ModelHitSphereDef'), (model, 'ObjModelHitSphere'),
        (track, 'TrackQueryBounds'), (track, 'TrackHitResults')]) + r'''
typedef struct ModelFileHeader { u8* hitVolumes; u8 hitVolumeCount; } ModelFileHeader;
typedef struct ObjModel {
    ModelFileHeader* file;
    u16 bufferFlags;
    u8* hitVolumeSphereBuffers[2];
} ObjModel;
typedef struct ObjHitsPriorityState {
    u8 objectHitMask, suppressOutgoingHits, secondaryShapeFlags;
    int trackContactMask, contactHitVolume;
    float contactPosX, contactPosY, contactPosZ;
    int contactFlags;
} ObjHitsPriorityState;
typedef struct ModelInstance { u8 fallbackHitSphereRadius; } ModelInstance;
typedef struct Anim {
    void* hitReactState;
    void* banks[1];
    int bankIndex;
    float worldPosX, worldPosY, worldPosZ;
    float previousWorldPosX, previousWorldPosY, previousWorldPosZ;
    ModelInstance* modelInstance;
} Anim;
struct GameObject { Anim anim; };
static float playerMapOffsetX = 1000, playerMapOffsetZ = -1000;
static GameObject objects[2], owner;
static int wanted[4], wantedCount, selectedBuffer, queryMask, owned, fallback, valid, phase;
static GameObject* queryObject;
#define CHECK(x) (valid &= !!(x))
static void hitDetect_calcSweptSphereBounds(TrackQueryBounds* bounds, float* from,
                                          float* to, float* radii, int count) {
    int j;
    CHECK(phase++ == 0 && count == wantedCount);
    for (j = 0; j < count; j++) {
        int i = wanted[j];
        if (fallback) {
            CHECK(from[3*j] == 1 && from[3*j+1] == 2 && from[3*j+2] == 3);
            CHECK(to[3*j] == 4 && to[3*j+1] == 5 && to[3*j+2] == 6);
            CHECK(radii[j] == (fallback == 1 ? 0.1f : 9.0f));
        } else {
            CHECK(to[3*j] == 1000 + selectedBuffer*100 + i);
            CHECK(to[3*j+1] == i+10 && to[3*j+2] == i-1000+20);
            CHECK(from[3*j] == 1000 + (selectedBuffer^1)*100 + i);
            CHECK(from[3*j+1] == i+10 && from[3*j+2] == i-1000+20);
            CHECK(radii[j] == i+0.5f);
        }
    }
}
static void trackIntersectBroadphase(GameObject* obj, TrackQueryBounds* bounds, int mask, int flags) {
    CHECK(phase++ == 1 && obj == queryObject && mask == 0x246 && flags == 1);
}
static int trackGetIntersect(GameObject* obj, float* from, float* to, int count, void* storage, int flags) {
    TrackHitResults* results = storage;
    int i;
    CHECK(phase++ == 2 && obj == queryObject && count == wantedCount && flags == 0);
    for (i = 0; i < count; i++) {
        CHECK(results->surfaceTypes[i] == -1 && results->queryTypes[i] == 7);
        results->surfaceTypes[i] = 20+i;
        results->objects[i] = owned ? &owner : NULL;
        to[3*i] += 10;
    }
    return queryMask;
}
''' + function + r'''
int runCase(int self, int mask, int suppress, int fallbackKind, int buffer,
            int count, u16* links, int* owners, int* bits, int* expected, int expectedCount,
            int resultMask, int hasOwner) {
    ModelHitSphereDef defs[16];
    ObjModelHitSphere spheres[2][32];
    ModelFileHeader file;
    ModelInstance instance;
    ObjModel model;
    ObjHitsPriorityState states[2];
    ObjHitsPriorityState* out;
    int i, b, first = 0;
    memset(objects, 0, sizeof(objects));
    memset(states, 0, sizeof(states));
    memset(defs, 0, sizeof(defs));
    memset(&model, 0, sizeof(model));
    for (i=0; i<count; i++) {
        defs[i].linkedSpheres=links[i]; defs[i].sphereIndex=owners[i]; defs[i].maskBit=bits[i];
    }
    for (b=0; b<2; b++) for (i=0; i<32; i++) {
        spheres[b][i].pos[0]=100*b+i; spheres[b][i].pos[1]=i+10;
        spheres[b][i].pos[2]=i+20; spheres[b][i].radius=i+0.5f;
    }
    file.hitVolumes=(u8*)defs; file.hitVolumeCount=count;
    model.file=&file; model.bufferFlags=buffer<<2;
    model.hitVolumeSphereBuffers[0]=(u8*)spheres[0]; model.hitVolumeSphereBuffers[1]=(u8*)spheres[1];
    instance.fallbackHitSphereRadius=fallbackKind == 1 ? 0 : 9;
    for (i=0; i<2; i++) {
        objects[i].anim.hitReactState=&states[i]; objects[i].anim.banks[0]=&model;
        objects[i].anim.modelInstance=&instance;
        states[i].secondaryShapeFlags=fallbackKind ? 0 : OBJHITS_SHAPE_MODEL_HIT_VOLUMES;
        states[i].trackContactMask=0x246; states[i].contactHitVolume=-5;
        states[i].contactFlags=0x4000;
    }
    states[0].objectHitMask=mask; states[0].suppressOutgoingHits=suppress;
    objects[0].anim.worldPosX=4; objects[0].anim.worldPosY=5; objects[0].anim.worldPosZ=6;
    objects[0].anim.previousWorldPosX=1; objects[0].anim.previousWorldPosY=2; objects[0].anim.previousWorldPosZ=3;
    queryObject=&objects[self ? 0 : 1]; out=(ObjHitsPriorityState*)queryObject->anim.hitReactState;
    wantedCount=expectedCount; memcpy(wanted, expected, expectedCount*sizeof(int));
    selectedBuffer=buffer; queryMask=resultMask; owned=hasOwner; fallback=fallbackKind;
    phase=0; valid=1;
    ObjHits_CheckTrackContact(&objects[0], queryObject);
    CHECK(phase == (wantedCount ? 3 : 0));
    if (wantedCount && resultMask) {
        while (!(resultMask & (1<<first))) first++;
        CHECK(out->contactHitVolume == 20+first);
        CHECK(out->contactPosX == (fallback ? 14 : 1010+100*buffer+wanted[first]));
        CHECK(out->contactPosY == (fallback ? 5 : wanted[first]+10));
        CHECK(out->contactPosZ == (fallback ? 6 : wanted[first]-980));
        CHECK(out->contactFlags == (0x4000 | (owned ? OBJHITS_CONTACT_FLAG_KIND_NONZERO : OBJHITS_CONTACT_FLAG_KIND0)));
    } else {
        CHECK(out->contactHitVolume == -5 && out->contactFlags == 0x4000);
    }
    return valid;
}
'''


class TrackContactTests(unittest.TestCase):
    def test_selection_and_contact(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required')
        rng = random.Random(239)
        cases = []
        for n in range(240):
            count = n % 17
            links = [rng.choice([0, 0x1234, 0x0102, 0x3000, 0xffff]) for _ in range(count)]
            owners = [i if rng.randrange(4) else -1 for i in range(count)]
            bits = [rng.randrange(4) for _ in range(count)]
            self_query, mask, suppress, fallback, buffer = n % 2, rng.randrange(256), n % 13 == 0, n % 7 % 3, n // 2 % 2
            active = mask >> 4 if self_query else mask & 15
            selected = []
            if active and not suppress:
                if fallback:
                    selected = [0]
                else:
                    for i in range(count):
                        if owners[i] != i or not active & (1 << bits[i]):
                            continue
                        offsets = [int(d, 16) for d in f'{links[i]:04x}'.rstrip('0')] if links[i] else [0]
                        selected.extend(i + offset for offset in offsets)
                    selected = selected[:4]
            result = rng.randrange(1 << len(selected)) if selected else 0
            cases.append((self_query, mask, suppress, fallback, buffer, links, owners, bits, selected, result, n % 2))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'probe.c').write_text(fixture())
            for opt in ('-O0', '-O2'):
                library = path / (opt + '.dylib')
                subprocess.run([compiler, '-std=c99', opt, '-shared', '-fPIC', str(path / 'probe.c'), '-o', str(library)], check=True)
                run = ctypes.CDLL(str(library)).runCase
                run.restype = ctypes.c_int
                for case in cases:
                    self_query, mask, suppress, fallback, buffer, links, owners, bits, selected, result, owned = case
                    ints = lambda values: (ctypes.c_int * max(1, len(values)))(*values)
                    with self.subTest(opt=opt, case=case):
                        self.assertEqual(run(self_query, mask, suppress, fallback, buffer, len(links),
                                             (ctypes.c_ushort * max(1, len(links)))(*links), ints(owners), ints(bits),
                                             ints(selected), len(selected), result, owned), 1)


if __name__ == '__main__':
    unittest.main()
