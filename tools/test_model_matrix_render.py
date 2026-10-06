#!/usr/bin/env python3
"""Run the production matrix commands with native pointers and GX call spies.

Pointer-bearing model owners use host views. The stream and joint records,
matrix tables, identity matrix, diagnostic, and command bodies come from source.
SDK matrix math is modeled here; objdiff and the DOL checksum cover target code.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    source = (ROOT / 'src/main/objprint_dolphin.c').read_text()
    records = []
    for header, name in [('model.h', 'ObjModelJointMatrix'),
                         ('model_render_instrs_api.h', 'ModelRenderInstrsState')]:
        text = (ROOT / 'include/main' / header).read_text()
        records.append(re.search(r'typedef struct ' + name + r'\s*\{[^}]*\} ' + name + ';', text).group())
    data = source[source.index('u8 gObjGxPosMtxIdTable['):source.index('extern s32 gModelMtxCacheState;')]
    bodies = []
    for name in ['modelBuildPosNrmMtxs', 'modelLoadMtxsToGx', 'renderOpMatrix']:
        start, end = find_function_body(source, name)
        declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
        bodies.append(source[declaration:end + 1])
    return PRELUDE + '\n'.join(records) + data + SPIES + '\n'.join(bodies) + CHECKS


PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef int s32;
typedef float f32;
typedef f32 Mtx[3][4];
typedef f32 (*MtxPtr)[4];
typedef struct ModelFileHeader { u8 jointCount, extraJointCount; } ModelFileHeader;
typedef struct ObjModel { int marker; } ObjModel;
enum { GX_MTX3x4 = 0 };
'''

SPIES = r'''
static s32 gModelMtxCacheState;
static ObjModel model;
static ObjModelJointMatrix joints[256], savedJoints[256];
static union { f32 alignment; u8 bytes[0x4020]; } cache, expectedCache;
static int waits, cacheCalls, jointCalls, eventCount, eventRead;
static struct Event { char kind; u32 id; Mtx matrix; } events[36];
static void* getCache(void) { cacheCalls++; return cache.bytes + 16; }
static void cacheQueueWait(int value) { assert(value == 0); waits++; }
static ObjModelJointMatrix* ObjModel_GetJointMatrix(u8* owner, int index) {
    assert(owner == (u8*)&model && index >= 0 && index < 256);
    jointCalls++;
    return &joints[index];
}
static void OSReport(const char* format, int count) {
    (void)format; (void)count;
    assert(!"four-bit matrix count cannot reach the retail diagnostic branch");
}
static void PSMTXConcat(const Mtx a, const Mtx b, Mtx out) {
    Mtx result;
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 4; col++) {
            f32 value = col == 3 ? a[row][3] : 0;
            for (int k = 0; k < 3; k++) value += a[row][k] * b[k][col];
            result[row][col] = value;
        }
    }
    memcpy(out, result, sizeof(result));
}
static void record(char kind, const Mtx matrix, u32 id) {
    assert(eventCount < 36);
    events[eventCount].kind = kind;
    events[eventCount].id = id;
    memcpy(events[eventCount++].matrix, matrix, sizeof(Mtx));
}
static void GXLoadPosMtxImm(const Mtx matrix, u32 id) { record('P', matrix, id); }
static void GXLoadNrmMtxImm(const Mtx matrix, u32 id) { record('N', matrix, id); }
static void GXLoadTexMtxImm(const Mtx matrix, u32 id, int type) {
    assert(type == GX_MTX3x4);
    record('T', matrix, id);
}
'''

CHECKS = r'''
static const Mtx view = {{0, -1, 0, 11}, {1, 0, 0, -7}, {0, 0, 2, 3}};
/* Nonzero translation deliberately distinguishes the two retail normal paths. */
static const Mtx normalScale = {{2, 0, 0, 5}, {0, 3, 0, -2}, {0, 0, 4, 9}};
static void expectedPosition(int index, Mtx out) {
    const f32* joint = (const f32*)&joints[index];
    for (int col = 0; col < 4; col++) {
        out[0][col] = -joint[4 + col] + (col == 3 ? 11 : 0);
        out[1][col] = joint[col] + (col == 3 ? -7 : 0);
        out[2][col] = 2 * joint[8 + col] + (col == 3 ? 3 : 0);
    }
}
static void expectedNormal(const Mtx position, Mtx out, int cached) {
    for (int row = 0; row < 3; row++) {
        out[row][0] = position[row][0] * 2;
        out[row][1] = position[row][1] * 3;
        out[row][2] = position[row][2] * 4;
        out[row][3] = cached ? 0 : position[row][0] * 5 - position[row][1] * 2 + position[row][2] * 9;
    }
}
static void expect(char kind, int slot, const Mtx matrix) {
    assert(eventRead < eventCount);
    struct Event* event = &events[eventRead++];
    assert(event->kind == kind);
    assert(event->id == (slot >= 10 ? 0 : (kind == 'T' ? 30 : 0) + slot * 3));
    assert(memcmp(event->matrix, matrix, sizeof(Mtx)) == 0);
}
static void putBits(u8* bytes, int offset, int width, unsigned value) {
    for (int i = 0; i < width; i++) {
        int bit = offset + i;
        bytes[bit / 8] = (bytes[bit / 8] & ~(1u << (bit % 8))) | (((value >> i) & 1) << (bit % 8));
    }
}
static void check(int full, int state, int total, int count, int offset, int flags) {
    u8 bytes[20], savedBytes[20];
    int indices[12];
    const int choices[12] = {0, 1, 3, 7, 31, 63, 64, 98, 99, 100, 254, 255};
    int nrm = flags & 1, tex = flags & 2, shadow = flags & 4;
    ModelFileHeader file = {(u8)(total - 2), 2};
    ModelRenderInstrsState stream = {bytes, sizeof(bytes), sizeof(bytes) * 8, 1234, offset};
    assert((uintptr_t)bytes > UINT32_MAX && (uintptr_t)&cache > UINT32_MAX);
    memset(&cache, 0xa5, sizeof(cache));
    for (int i = 0; i < 256; i++) {
        const f32 values[16] = {1 + i, 2, 0, 10 + i, 0, 1, -1, 20 - i, 1, 0, 2, -5 + i, 91, 92, 93, 94};
        memcpy(&joints[i], values, sizeof(values));
        if (i < 100) memcpy(cache.bytes + 16 + 0x2700 + i * 64, values, sizeof(values));
    }
    if (state == 2) {
        for (int i = 0; i < 100; i++) {
            Mtx position, normal;
            for (int row = 0; row < 3; row++) {
                for (int col = 0; col < 4; col++) {
                    position[row][col] = i * 16 + row * 4 + col;
                    normal[row][col] = -position[row][col] - 100;
                }
            }
            memcpy(cache.bytes + 16 + i * 48, position, 48);
            memcpy(cache.bytes + 16 + 0x12c0 + i * 48, normal, 48);
        }
    }
    memcpy(&expectedCache, &cache, sizeof(cache));
    memcpy(savedJoints, joints, sizeof(joints));
    if (state == 1) {
        for (int i = 0; i < total; i++) {
            Mtx position, normal;
            expectedPosition(i, position);
            memcpy(expectedCache.bytes + 16 + i * 48, position, 48);
            if (full && !shadow) {
                expectedNormal(position, normal, 1);
                memcpy(expectedCache.bytes + 16 + 0x12c0 + i * 48, normal, 48);
            }
        }
    }
    memset(bytes, 0xa5, sizeof(bytes));
    putBits(bytes, offset, 4, count);
    for (int i = 0; i < count; i++) {
        indices[i] = state == 3 ? choices[i] : choices[i] % total;
        putBits(bytes, offset + 4 + i * 8, 8, indices[i]);
    }
    memcpy(savedBytes, bytes, sizeof(bytes));
    gModelMtxCacheState = state;
    waits = cacheCalls = jointCalls = eventCount = eventRead = 0;
    if (full) renderOpMatrix(&file, &model, &stream, (f32*)normalScale, (f32*)view, nrm, tex, shadow);
    else modelLoadMtxsToGx(&file, &model, &stream, (f32*)view);
    assert(stream.bit == offset + 4 + count * 8);
    assert(stream.instrs == bytes && stream.byteCount == sizeof(bytes));
    assert(stream.bitCount == sizeof(bytes) * 8 && stream.fieldC == 1234);
    assert(gModelMtxCacheState == (state == 1 ? 2 : state));
    assert(waits == (state == 1) && cacheCalls == 1 + (state == 1));
    assert(jointCalls == (state == 3 ? count : 0));
    assert(memcmp(&cache, &expectedCache, sizeof(cache)) == 0);
    assert(memcmp(joints, savedJoints, sizeof(joints)) == 0);
    assert(memcmp(bytes, savedBytes, sizeof(bytes)) == 0);
    for (int i = 0; i < count; i++) {
        Mtx position, normal;
        if (state == 3) {
            expectedPosition(indices[i], position);
            expectedNormal(position, normal, 0);
        } else {
            memcpy(position, expectedCache.bytes + 16 + indices[i] * 48, 48);
            memcpy(normal, expectedCache.bytes + 16 + 0x12c0 + indices[i] * 48, 48);
        }
        expect('P', i, position);
        if (full && !shadow && tex) expect('T', i, normal);
        if (full && !shadow && nrm) expect('N', i, normal);
    }
    assert(eventRead == eventCount);
}
int main(void) {
    const Mtx identity = {{1, 0, 0, 0}, {0, 1, 0, 0}, {0, 0, 1, 0}};
    const char diagnostic[48] = "<renderOpMatrix> ERROR CASE numMatrices = %d\n";
    assert(sizeof(ObjModelJointMatrix) == 64);
    assert(sizeof(gObjJointIdentityMtx) == 48 && sizeof(gObjMatrixCountError) == 48);
    assert(memcmp(gObjJointIdentityMtx, identity, 48) == 0);
    assert(memcmp(gObjMatrixCountError, diagnostic, 48) == 0);
    int cases = 0;
    const int totals[] = {2, 17, 100};
    for (int full = 0; full < 2; full++)
    for (int state = 1; state <= 3; state++)
    for (int t = 0; t < 3; t++)
    for (int count = 0; count <= 12; count++)
    for (int offset = 0; offset < 8; offset++)
    for (int flags = 0; flags < (full ? 8 : 1); flags++) {
        check(full, state, totals[t], count, offset, flags);
        cases++;
    }
    printf("%d matrix-command scenarios passed\n", cases);
    return 0;
}
'''


class ModelMatrixRenderTests(unittest.TestCase):
    def test_matrix_commands(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        with tempfile.TemporaryDirectory(prefix='sfa-matrix-render-') as temporary:
            directory = Path(temporary)
            source = directory / 'matrix_render.c'
            source.write_text(fixture())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    executable = directory / 'matrix_render'
                    result = subprocess.run([compiler, '-std=c99', optimization,
                                             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                             str(source), '-o', str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    print(optimization, result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
