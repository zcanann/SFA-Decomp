"""Check production shadow collection against fixed geometry and capacity contracts.

The matrix-array SDK call is modeled with ordinary affine math. These tests do
not execute GameCube cache operations or validate final shadow-volume rendering.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def record(source, name):
    return re.search(r'typedef struct ' + name + r'\s*\{.*?\}\s*' + name + r';',
                     source, re.S).group()


class ShadowTriangleCollectionTests(unittest.TestCase):
    def test_geometry_and_capacity(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang is required for the source-body harness')
        source = (ROOT / 'src/main/tex_dolphin.c').read_text()
        header = (ROOT / 'include/main/track_dolphin.h').read_text()
        function = re.search(r'^int collectShadowTrackTriangles\(.*?^\}', source, re.M | re.S).group()
        records = '\n'.join(record(header, name) for name in
                            ('TrackBlockDescriptor', 'TrackShadowTriangle', 'TrackTriangle'))
        fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef float f32;
typedef signed char s8;
typedef short s16;
typedef unsigned char u8;
typedef unsigned int u32;
typedef struct Vec3f { f32 x, y, z; } Vec3f;
typedef Vec3f Vec;
typedef f32 (*MtxPtr)[4];
typedef struct GameObject {
    struct { void* parent; f32 localPosX, localPosY, localPosZ; } anim;
} GameObject;
''' + records + r'''
static TrackBlockDescriptor descriptors[4];
static u32 descriptorCount;
static TrackTriangle input[1300];
static TrackShadowTriangle output[1202];
static Vec3f vertices[3606];
static TrackBlockDescriptor* trackGetBlockDescriptors(u32* count) {
    *count = descriptorCount;
    return descriptors;
}
static f32 __OSs16tof32(const s16* p) { return *p; }
static void PSMTXMultVecArray(MtxPtr m, Vec* in, Vec* out, u32 count) {
    u32 i;
    for (i = 0; i < count; i++) {
        Vec v = in[i];
        out[i].x = m[0][0]*v.x + m[0][1]*v.y + m[0][2]*v.z + m[0][3];
        out[i].y = m[1][0]*v.x + m[1][1]*v.y + m[1][2]*v.z + m[1][3];
        out[i].z = m[2][0]*v.x + m[2][1]*v.y + m[2][2]*v.z + m[2][3];
    }
}
''' + function + r'''
static void assert_filled(const void* data, unsigned char value, size_t size) {
    const unsigned char* bytes = data;
    size_t i;
    for (i = 0; i < size; i++) assert(bytes[i] == value);
}
static void reset_output(void) {
    memset(output, 0xA5, sizeof(output));
    memset(vertices, 0xA5, sizeof(vertices));
}
static void assert_tail(int count) {
    assert_filled(output + count, 0xA5, sizeof(output) - count * sizeof(output[0]));
    assert_filled(vertices + count * 3, 0xA5, sizeof(vertices) - count * 3 * sizeof(vertices[0]));
}
int main(void) {
    GameObject obj = {{0, 10, 20, 30}};
    GameObject parent, other;
    f32 collisionMatrix[16] = {0, -1, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 5, 7, 11, 1};
    const Vec3f expected[9] = {
        {91,-18,173}, {94,-15,176}, {97,-12,179},
        {-9,-18,-27}, {-6,-15,-24}, {-3,-12,-21},
        {-1,-14,-16}, {5,-17,-13}, {11,-20,-10}
    };
    const s8 selectedFlags[2][3] = {{8,12,(s8)0x88}, {4,12,(s8)0x84}};
    int i, axis, count, selector;
    obj.anim.parent = &parent;
    for (i = 0; i < 1300; i++) {
        for (axis = 0; axis < 3; axis++) {
            input[i].vx[axis] = 1 + axis * 3;
            input[i].vy[axis] = 2 + axis * 3;
            input[i].vz[axis] = 3 + axis * 3;
        }
        input[i].planeN[0] = .25f;
        input[i].planeN[1] = .5f;
        input[i].planeN[2] = .75f;
    }
    descriptors[0].firstTriangle = 0;
    descriptors[1].firstTriangle = 2;
    descriptors[1].object = &parent;
    descriptors[2].firstTriangle = 4;
    descriptors[2].object = &other;
    descriptors[2].currentCollisionMatrix = collisionMatrix;
    descriptors[3].firstTriangle = 6;
    input[0].flags=4; input[1].flags=8; input[2].flags=12;
    input[3].flags=0; input[4].flags=(s8)0x84; input[5].flags=(s8)0x88;
    descriptorCount = 3;
    for (selector = 0; selector < 2; selector++) {
        reset_output();
        count = collectShadowTrackTriangles(&obj, input, output, vertices, 1, 100, 200, 99, selector);
        assert(count == 3);
        for (i = 0; i < 9; i++) {
            assert(vertices[i].x == expected[i].x);
            assert(vertices[i].y == expected[i].y);
            assert(vertices[i].z == expected[i].z);
        }
        for (i = 0; i < 3; i++) {
            assert(output[i].normal.x == .25f && output[i].normal.y == .5f && output[i].normal.z == .75f);
            assert(output[i].flags == selectedFlags[selector][i]);
            assert_filled(&output[i].planeDistance, 0xA5, sizeof(f32));
            assert_filled(output[i].pad11, 0xA5, sizeof(output[i].pad11));
        }
        assert_tail(count);
    }
    descriptorCount = 0;
    reset_output();
    assert(collectShadowTrackTriangles(&obj,input,output,vertices,0,100,200,0,0)==0);
    assert_tail(0);
    descriptorCount = 1;
    descriptors[1].firstTriangle = 1300;
    for (i = 0; i < 1300; i++) input[i].flags = 8;
    reset_output();
    assert(collectShadowTrackTriangles(&obj,input,output,vertices,0,100,200,0,0)==1200);
    assert(vertices[3599].x == 97 && vertices[3599].y == -12 && vertices[3599].z == 179);
    assert_tail(1200);
    reset_output();
    assert(collectShadowTrackTriangles(&obj,input,output,vertices,0,100,200,0,1)==0);
    assert_tail(0);
    puts("5 shadow collection scenarios passed");
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='sfa-shadow-collection-') as temporary:
            directory = Path(temporary)
            c_file = directory / 'fixture.c'
            c_file.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                executable = directory / ('fixture' + optimization)
                subprocess.run([compiler, '-std=c99', optimization, str(c_file), '-o', str(executable)], check=True)
                subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    unittest.main()
