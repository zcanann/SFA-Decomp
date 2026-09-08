"""Execute production joint-matrix preparation against independent affine results."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


class ModelMatrixInitTests(unittest.TestCase):
    def test_matrix_preparation(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        source = (ROOT / 'src/main/model.c').read_text()
        header = (ROOT / 'include/main/model.h').read_text()
        records = '\n'.join(re.search(r'typedef struct ' + name + r'\s*\{[^}]*\} ' + name + ';',
                                      header).group()
                            for name in ('ModelBone', 'ObjModelJointMatrix'))
        functions = []
        for name in ('modelGetJointMatrixCount', 'modelGetBoneMtx', 'model_multMtxs',
                     'modelInitBoneMtxs', 'modelInitBoneMtxs2'):
            start, end = find_function_body(source, name)
            declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
            functions.append(source[declaration:end + 1])
        fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef float f32;
typedef f32 Mtx[3][4];
typedef f32 (*MtxPtr)[4];
typedef f32 ROMtx[4][3];
typedef f32 (*ROMtxPtr)[3];
''' + records + r'''
/* Host views of pointer-bearing owners: only fields used by these bodies are
   needed. The actual pointer-free bone and joint-matrix records are above. */
typedef struct ModelFileHeader {
    u8 jointCount, extraJointCount;
    u8* jointData;
} ModelFileHeader;
typedef struct ObjModel {
    ModelFileHeader* file;
    u8* jointMatrices[2];
    u16 bufferFlags;
} ObjModel;
static int translateCalls, concatCalls, reorderCalls;
static void PSMTXTrans(Mtx matrix, f32 x, f32 y, f32 z) {
    translateCalls++;
    memset(matrix, 0, sizeof(Mtx));
    for (int i = 0; i < 3; i++) matrix[i][i] = 1;
    matrix[0][3] = x; matrix[1][3] = y; matrix[2][3] = z;
}
static void PSMTXConcat(const Mtx a, const Mtx b, Mtx out) {
    Mtx result;
    concatCalls++;
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 4; col++) {
            f32 value = col == 3 ? a[row][3] : 0;
            for (int k = 0; k < 3; k++) value += a[row][k] * b[k][col];
            result[row][col] = value;
        }
    }
    memcpy(out, result, sizeof(result));
}
static void PSMTXReorder(const Mtx in, ROMtx out) {
    reorderCalls++;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 3; row++) out[col][row] = in[row][col];
    }
}
''' + '\n'.join(functions) + r'''
static f32 matrices[2][257][16], before[2][257][16];
static f32 output[257 * 12 + 2];
static ModelBone bones[255];
static const Mtx world = {{0, -1, 0, 11}, {1, 0, 0, -7}, {0, 0, 2, 3}};

static void check(int count, int extra, int flags, int method) {
    ModelFileHeader file = {(u8)count, (u8)extra, (u8*)bones};
    ObjModel model = {&file, {(u8*)matrices[0], (u8*)matrices[1]}, (u16)flags};
    int active = flags & 1;
    for (int bank = 0; bank < 2; bank++) {
        for (int i = 0; i < 257; i++) {
            const f32 initial[16] = {1, 2, 0, 10 + i + bank * 100,
                                    0, 1, -1, 20 - i,
                                    1, 0, 2, -5 + i,
                                    91, 92, 93, 94};
            memcpy(matrices[bank][i], initial, sizeof(initial));
        }
    }
    for (int i = 0; i < 255; i++) {
        bones[i].tail[0] = i + 1;
        bones[i].tail[1] = 2 - i;
        bones[i].tail[2] = i % 3 - 1;
    }
    memcpy(before, matrices, sizeof(before));
    for (int i = 0; i < 257 * 12 + 2; i++) output[i] = -9999;
    translateCalls = concatCalls = reorderCalls = 0;
    if (method == 0) modelInitBoneMtxs(&model, output + 1);
    if (method == 1) modelInitBoneMtxs2(&model, (f32*)world, output + 1);
    if (method == 2) model_multMtxs(&model, (f32*)world);

    int reordered = method == 2 ? 0 : count;
    int transformed = method == 0 ? 0 : method == 1 && count == 0 ? 1 : count;
    assert(translateCalls == reordered && reorderCalls == reordered);
    assert(concatCalls == reordered + transformed);
    for (int i = 0; i < reordered; i++) {
        const f32* joint = before[active][i];
        /* An inverse bind translation changes only the fourth column. */
        const f32 translation[3] = {
            joint[3] - bones[i].tail[0] - 2 * bones[i].tail[1],
            joint[7] - bones[i].tail[1] + bones[i].tail[2],
            joint[11] - bones[i].tail[0] - 2 * bones[i].tail[2]
        };
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 3; row++) {
                f32 expected = col == 3 ? translation[row] : joint[row * 4 + col];
                assert(output[1 + i * 12 + col * 3 + row] == expected);
            }
        }
    }
    assert(output[0] == -9999);
    for (int i = 1 + reordered * 12; i < 257 * 12 + 2; i++) assert(output[i] == -9999);
    for (int bank = 0; bank < 2; bank++) {
        for (int i = 0; i < 257; i++) {
            for (int word = 0; word < 16; word++) {
                f32 expected = before[bank][i][word];
                if (bank == active && i < transformed && word < 12) {
                    int row = word / 4, col = word % 4;
                    /* World transform: x'=-y+11, y'=x-7, z'=2z+3. */
                    if (row == 0) expected = -before[bank][i][4 + col] + (col == 3 ? 11 : 0);
                    if (row == 1) expected = before[bank][i][col] - (col == 3 ? 7 : 0);
                    if (row == 2) expected = 2 * before[bank][i][8 + col] + (col == 3 ? 3 : 0);
                }
                assert(matrices[bank][i][word] == expected);
            }
        }
    }
}
int main(void) {
    assert(sizeof(ModelBone) == 28 && sizeof(ObjModelJointMatrix) == 64 && sizeof(ROMtx) == 48);
    const int counts[] = {0, 1, 2, 7, 32, 255};
    const int flags[] = {0, 1, 0xfffe, 0xffff};
    int scenarios = 0;
    for (int method = 0; method < 3; method++) {
        for (int count = 0; count < 6; count++) {
            for (int extra = 0; extra < 3; extra += 2) {
                for (int flag = 0; flag < 4; flag++) {
                    check(counts[count], extra, flags[flag], method);
                    scenarios++;
                }
            }
        }
    }
    printf("%d matrix-preparation scenarios passed\n", scenarios);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='sfa-matrix-init-') as temporary:
            directory = Path(temporary)
            path = directory / 'matrix_init.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = directory / 'matrix_init'
                    result = subprocess.run([compiler, '-std=c99', optimization, str(path), '-o', str(executable)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    print(optimization, result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
