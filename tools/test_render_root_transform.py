#!/usr/bin/env python3
"""Execute the production root decoder with native pointers and an independent oracle.

The fixture adapts the aligned input words to host byte order; the decoder keeps
its target-endian loads. Pointer-bearing animation state uses a minimal host view.
"""

import itertools
import math
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def trunc_div(value, denominator):
    return (1 if value >= 0 else -1) * (abs(value) // denominator)


def cases():
    """All per-axis optional-track combinations, five width patterns and phases."""
    phases = [-1.25, 0.0, 0.5, 0.99993896484375, 3.125]
    for index, (kinds, widths, phase) in enumerate(itertools.product(
            itertools.product(range(4), repeat=3), range(5), phases)):
        rng = random.Random(index)
        descriptors, bits, rotations, positions = [], ['', ''], [], []
        fraction = int((phase - math.floor(phase)) * 16384)

        def track(flags, flag_mask):
            width = [0, 1, 14, 15, rng.randrange(16)][widths]
            base = (rng.randrange(4096) << 4 & ~flag_mask) | flags
            descriptors.append(base | width)
            limit = (1 << width) - 1
            values = [rng.choice([0, limit, limit // 2, rng.randrange(limit + 1)]) for _ in range(2)]
            if width:
                for bank in range(2):
                    bits[bank] += f'{values[bank]:0{width}b}'
            return width, base, *values

        for kind in kinds:
            width, base, first, second = track(0x10 if kind else 0, 0x10)
            delta = (second - first) & 0x3fff
            if delta >= 0x2000:
                delta -= 0x4000
            rotations.append((base + (first + trunc_div(delta * fraction, 16384)) * 4) & 0xffff if width else 0)
            if kind in (2, 3):
                track(0x10 | (0x20 if kind == 3 else 0), 0x30)
            if kind in (1, 3):
                width, base, first, second = track(0, 0x10)
                positions.append((base + first + trunc_div((second - first) * fraction, 16384)) & 0xffff
                                 if width else 0)
            else:
                positions.append(0)
        streams = [int(text.ljust(256, '0'), 2).to_bytes(32, 'big') for text in bits]
        yield dict(index=index, phase=phase, descriptors=descriptors, streams=streams,
                   rotations=rotations, positions=positions, stride=48 + index % 8,
                   bits=len(bits[0]))


PRELUDE = r'''
#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef struct ObjAnimFrameHeader {
    u8 jointCount, frameCount, frameStride, pad03;
    u16 trackDescriptors[];
} ObjAnimFrameHeader;
typedef struct ObjAnimState {
    f32 framePhase;
    u16 frameStreamStride;
    u8* frameStreamCursor;
    ObjAnimFrameHeader* moveFrameData;
} ObjAnimState;
static void render_copyPackedU64Tail(u64* dst, size_t packed);
static void render_copyPackedU64Head(u64* dst, size_t packed);
'''

CHECKS = r'''
typedef struct Case {
    f32 phase;
    u16 stride, descriptors[9];
    u8 streams[2][32];
    u16 position[3], rotation[3];
} Case;
#include "cases.inc"

static u64 readBE(const u8* bytes) {
    u64 value = 0;
    for (int i = 0; i < 8; i++) value = (value << 8) | bytes[i];
    return value;
}
static void hostWords(u8* bytes, int size) {
    /* Production loads a native u64 on the big-endian target. Arrange those
       same numeric words in host memory, including partially consumed words. */
    for (int i = 0; i < size; i += 8) {
        u64 value = readBE(bytes + i);
        memcpy(bytes + i, &value, 8);
    }
}
static int checkCopies(void) {
    union { u64 align; u8 bytes[32]; } storage;
    u8 logical[32];
    int cases = 0;
    for (int pattern = 0; pattern < 8; pattern++) {
        for (int i = 0; i < 32; i++) logical[i] = (i * 37 + pattern * 17) & 255;
        memcpy(storage.bytes, logical, 32);
        hostWords(storage.bytes, 32);
        for (int offset = 0; offset < 8; offset++) {
            u64 initial = UINT64_C(0xcdeffedc12345678) ^ pattern;
            u8 expected[8];
            for (int i = 0; i < 8; i++) expected[i] = initial >> (56 - i * 8);
            memcpy(expected, logical + 8 + offset, 8 - offset);
            u64 value = initial;
            render_copyPackedU64Head(&value, (size_t)(storage.bytes + 8 + offset));
            assert(value == readBE(expected));
            for (int i = 0; i < 8; i++) expected[i] = initial >> (56 - i * 8);
            memcpy(expected + 7 - offset, logical + 8, offset + 1);
            value = initial;
            render_copyPackedU64Tail(&value, (size_t)(storage.bytes + 8 + offset));
            assert(value == readBE(expected));
            value = initial;
            render_copyPackedU64Head(&value, (size_t)(storage.bytes + 8 + offset));
            render_copyPackedU64Tail(&value, (size_t)(storage.bytes + 15 + offset));
            assert(value == readBE(logical + 8 + offset));
            cases += 3;
        }
    }
    return cases;
}
int main(void) {
    int copies = checkCopies(), roots = 0;
    for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        const Case* test = &cases[index];
        for (int offset = 0; offset < 8; offset++) {
            union { u64 align; u8 bytes[144]; } storage;
            u16 headerWords[11] = {0};
            ObjAnimFrameHeader* header = (ObjAnimFrameHeader*)headerWords;
            s16 position[5] = {0x1234, -1, -2, -3, 0x4321};
            s16 rotation[5] = {0x2345, -4, -5, -6, 0x5432};
            ObjAnimState state;
            memset(&state, 0, sizeof(state));
            state.framePhase = test->phase;
            state.frameStreamStride = test->stride;
            state.frameStreamCursor = storage.bytes + 16 + offset;
            state.moveFrameData = header;
            assert((uintptr_t)state.frameStreamCursor > UINT32_MAX);
            assert((uintptr_t)header > UINT32_MAX && (uintptr_t)position > UINT32_MAX);
            memset(storage.bytes, 0xa5, sizeof(storage.bytes));
            memcpy(state.frameStreamCursor, test->streams[0], 32);
            memcpy(state.frameStreamCursor + test->stride, test->streams[1], 32);
            memcpy(header->trackDescriptors, test->descriptors, sizeof(test->descriptors));
            hostWords(storage.bytes, sizeof(storage.bytes));
            u8 savedStorage[sizeof(storage)], savedState[sizeof(state)], savedHeader[sizeof(headerWords)];
            memcpy(savedStorage, &storage, sizeof(storage));
            memcpy(savedState, &state, sizeof(state));
            memcpy(savedHeader, header, sizeof(headerWords));
            modelRenderInterpolateRootTransform(&state, position + 1, rotation + 1);
            for (int axis = 0; axis < 3; axis++) {
                assert((u16)position[1 + axis] == test->position[axis]);
                assert((u16)rotation[1 + axis] == test->rotation[axis]);
            }
            assert(position[0] == 0x1234 && position[4] == 0x4321);
            assert(rotation[0] == 0x2345 && rotation[4] == 0x5432);
            assert(memcmp(savedStorage, &storage, sizeof(storage)) == 0);
            assert(memcmp(savedState, &state, sizeof(state)) == 0);
            assert(memcmp(savedHeader, header, sizeof(headerWords)) == 0);
            roots++;
        }
    }
    printf("%d packed-word checks and %d root-transform scenarios passed\n", copies, roots);
    return 0;
}
'''


def fixture():
    source = (ROOT / 'src/main/render.c').read_text()
    start = source.index('typedef u64 RenderPackedAddress;')
    return PRELUDE + source[start:] + CHECKS


def case_include():
    def array(values):
        return '{' + ','.join(str(v) for v in values) + '}'
    rows = []
    for case in cases():
        rows.append('{' + f"{case['phase']}f,{case['stride']}," + array(case['descriptors']) + ',{' +
                    ','.join(array(s) for s in case['streams']) + '},' + array(case['positions']) + ',' +
                    array(case['rotations']) + '}')
    return 'static const Case cases[] = {\n' + ',\n'.join(rows) + '\n};\n'


class RootTransformTests(unittest.TestCase):
    def test_root_transform(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        with tempfile.TemporaryDirectory(prefix='sfa-root-transform-') as temporary:
            directory = Path(temporary)
            source = directory / 'root_transform.c'
            source.write_text(fixture())
            (directory / 'cases.inc').write_text(case_include())
            for optimization in ['-O0', '-O2']:
                with self.subTest(optimization=optimization):
                    executable = directory / 'root_transform'
                    result = subprocess.run([compiler, '-std=c99', optimization,
                                             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                             str(source), '-lm', '-o', str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    print(optimization, result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
