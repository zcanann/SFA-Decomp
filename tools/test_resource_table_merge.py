#!/usr/bin/env python3
"""Check complete production table merge/read bodies against a bank-policy oracle.

The host fixture supplies the neighbouring-global MldfTables view as one
allocation and uses host-endian words. Allocated banks include room for the
complete cursor walk. The existing NULL-bank pointer increment is verified
separately as a UBSan failure, not hidden or treated as native-safe behavior.
"""
from pathlib import Path
import os
import random
import re
import struct
import subprocess
import tempfile
import unittest

from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = (
    ('mergeModels', 0x2a, 0x45, 0x800, 'model'),
    ('mergeAnim', 0x2f, 0x49, 3000, 'model'),
    ('mergeTex0', 0x24, 0x4e, 0x1000, 'texture'),
    ('mergeTex1', 0x21, 0x4c, 0x1000, 'texture'),
    ('mergeBlocks', 0x26, 0x48, 0x800, 'block'),
    ('mergeVoxMap', 0x1a, 0x53, 0x800, 'voxel'),
    ('mergeAnimCurv', 0x0e, 0x56, 0x1fd0, 'voxel'),
)
END = 0xffffffff
VALUES = (0, 4, 0x00ffffff, 0x10000024, 0x1f000028, 0x80000030, 0x81000034, 0x90000038)


def expected_merge(a, b, policy):
    """Select bank entries by policy; termination can consume an output row."""
    active = [True, True]
    output = []
    mask = 0x80000000 if policy in ('texture', 'voxel') else 0x10000000
    for left, right in zip(a, b):
        words = (left, right)
        ended = [active[i] and words[i] == END for i in range(2)]
        available = [i for i in range(2) if active[i] and not ended[i]]
        marked = [i for i in available if words[i] & mask]
        chosen = None
        consume_row = False
        if policy in ('texture', 'model'):
            active = [active[i] and not ended[i] for i in range(2)]
        elif policy == 'voxel' or not marked:
            for i in range(2):
                if ended[i]:
                    active[i] = False
                    consume_row = True
                    break
        if not consume_row:
            if marked:
                chosen = marked[0]
                if policy == 'block':
                    other = 1 - chosen
                    active[other] = active[other] and not ended[other]
            else:
                candidates = [i for i in available if active[i] and (policy == 'model' or words[i] != 0)]
                if candidates:
                    chosen = candidates[0]
        result = 0 if chosen is None else words[chosen]
        if chosen is not None and chosen in marked:
            if policy == 'texture' and chosen == 0:
                result = (result & 0x7fffffff) | 0x40000000
            elif policy != 'texture' and chosen == 1:
                result = (result & (0x7fffffff if policy == 'voxel' else 0xffffff)) | 0x20000000
        output.append(result)
    output[-1] = END
    return output


def write_cases(path):
    rng = random.Random(0x534641)
    count = 0
    with path.open('wb') as stream:
        for family, (_, _, _, capacity, policy) in enumerate(FAMILIES):
            variants = []
            for left in VALUES:
                for right in VALUES:
                    variants.append(([left] * capacity, [right] * capacity))
            for end_a in (0, 1, 7, capacity - 1, None):
                for end_b in (0, 1, 7, capacity - 1, None):
                    banks = [[rng.choice(VALUES) for _ in range(capacity)] for _ in range(2)]
                    for bank, end in zip(banks, (end_a, end_b)):
                        if end is not None:
                            bank[end] = END
                    variants.append(tuple(banks))
            for a, b in variants:
                unused_count = (-9, 0, 1, capacity, capacity + 99)[count % 5]
                stream.write(struct.pack('=iii', family, capacity, unused_count))
                for words in (a, b, expected_merge(a, b, policy)):
                    stream.write(struct.pack(f'={capacity}I', *words))
                count += 1
    return count


PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef int16_t s16;
typedef int32_t s32;
typedef uint32_t u32;
typedef struct DVDFileInfo DVDFileInfo;
"""
SERVICES = r"""
static union { struct MldfTables tables; MldfArenaBlock storage; } arena, before;
#define gResourceFileTable ((u8*)&arena)
static int diagnostics, polls, loads, pads, frames, resets, ticks, texts, flushes, errors;
#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
static char sAssetIndexOverflowError[] = "ERROR: asset index overflow ";
static void debugPrintfxy(int x, int y, char* text) {
    assert(x == 20 && y == 40 && text == sAssetIndexOverflowError); diagnostics++;
}
#else
static u32 waitBits;
static u8 gDvdErrorPauseActive;
static u32 loadedFileFlags(void) { polls++; return waitBits; }
static void padUpdate(void) { pads++; }
static void checkReset(void) { resets++; }
static void waitNextFrame(void) { frames++; }
static void loadDataFiles(int unused) { assert(unused == 0); if (++loads == 2) waitBits = 0; }
static void dvdCheckError(void) { errors++; gDvdErrorPauseActive = 1; }
static void mmFreeTick(int unused) { assert(unused == 0); ticks++; }
static void gameTextRun(void) { texts++; }
static void GXFlush_(int a, int b) { assert(a == 1 && b == 0); flushes++; }
#endif
static void resetEvents(void) {
    diagnostics = polls = loads = pads = frames = resets = ticks = texts = flushes = errors = 0;
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
    waitBits = 0; gDvdErrorPauseActive = 0;
#endif
}
"""
CASES = r"""
static void readers(int family, const u32* expected, int capacity) {
    int out = 0;
    u32* merged = mergedTables[family];
    assert(getCurrentDataFile(ids[family][0]) == merged);
    assert(getCurrentDataFile(ids[family][1]) == NULL);
    int indices[] = {-1, 0, capacity / 2, capacity - 1, capacity, 0x7fffffff};
    for (int n = 0; n < 6; n++) {
        int index = indices[n], valid = index >= 0 && index < capacity;
        resetEvents(); out = 0x12345678;
        assert(getTableFileEntry(ids[family][0], index, &out) == valid);
        assert((u32)out == (valid ? expected[index] : 0x12345678u));
#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
        assert(diagnostics == !valid && polls == 0);
#else
        assert(diagnostics == 0 && polls == valid);
#endif
    }
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
    resetEvents(); waitBits = family == 6 ? 0xa0000000u : 0xc;
    assert(getTableFileEntry(ids[family][0], 0, &out) == 1 && (u32)out == expected[0]);
    int waits = family == 0 || family == 6;
    assert(loads == 2 * waits && pads == 2 * waits && resets == 2 * waits && errors == 2 * waits);
    assert(frames == waits && ticks == waits && texts == waits && flushes == waits);
#endif
}
int main(int argc, char** argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "--null") == 0) {
        /* Retail walks these NULL cursors without dereferencing them. C arithmetic is still undefined. */
        mergeTableFiles(arena.tables.mergeModels, 42, 69, 2048);
        return 0;
    }
    FILE* input = fopen(argv[1], "rb"); assert(input);
    int header[3], cases = 0;
    while (fread(header, sizeof(header), 1, input) == 1) {
        int family = header[0], count = header[1];
        assert(family >= 0 && family < 7 && count == capacities[family]);
        u32* bankA = malloc((count + 1) * 4), *bankB = malloc((count + 1) * 4), *expected = malloc(count * 4);
        assert(bankA && bankB && expected && (uintptr_t)bankA > UINT32_MAX && (uintptr_t)bankB > UINT32_MAX);
        assert(fread(bankA, 4, count, input) == (size_t)count);
        assert(fread(bankB, 4, count, input) == (size_t)count);
        assert(fread(expected, 4, count, input) == (size_t)count);
        bankA[count] = bankB[count] = 0xaabbccdd;
        memset(&arena, 0xcc, sizeof(arena));
        arena.tables.ptrs[ids[family][0]] = bankA; arena.tables.ptrs[ids[family][1]] = bankB;
        memcpy(&before, &arena, sizeof(arena));
        assert(mergeTableFiles(mergedTables[family], ids[family][0], ids[family][1], header[2]) == 1);
        assert(memcmp(mergedTables[family], expected, count * 4) == 0);
        assert(bankA[count] == 0xaabbccdd && bankB[count] == 0xaabbccdd);
        size_t start = (u8*)mergedTables[family] - (u8*)&arena, end = start + count * 4;
        assert(memcmp(&arena, &before, start) == 0);
        assert(memcmp((u8*)&arena + end, (u8*)&before + end, sizeof(arena) - end) == 0);
        readers(family, expected, count);
        free(bankA); free(bankB); free(expected); cases++;
    }
    assert(feof(input)); fclose(input);
    u32 preloaded[] = {3, 5, 7};
    arena.tables.ptrs[MLDF_FILEID_TEXPRE_TAB] = preloaded;
    assert(getCurrentDataFile(MLDF_FILEID_TEXPRE_TAB) == preloaded);
    const int otherIds[] = {-1, 0, MLDF_FILEID_TEXPRE_TAB, 87, 88};
    for (int i = 0; i < 5; i++) {
        int out = 123; resetEvents();
        assert(getTableFileEntry(otherIds[i], 0, &out) == 0 && out == 123);
        if (otherIds[i] != MLDF_FILEID_TEXPRE_TAB) assert(getCurrentDataFile(otherIds[i]) == NULL);
    }
    /* Unknown output identity retains the retail write immediately before the supplied pointer. */
    u32 unknown[] = {11, 22, 33};
    arena.tables.ptrs[42] = arena.tables.ptrs[69] = preloaded;
    assert(mergeTableFiles(unknown + 1, 42, 69, 777) == 1);
    assert(unknown[0] == 0xffffffff && unknown[1] == 22 && unknown[2] == 33);
    printf("%d complete merges and regional reader checks passed\n", cases);
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    types = (ROOT / 'include/types.h').read_text()
    parts.append(re.search(r'^#define ARRAY_COUNT[^\n]*', types, re.M)[0])
    parts.append(re.search(r'struct MldfTables \{.*?\n\};', source, re.S)[0])
    start = source.index('typedef u8 MldfArenaBlock')
    parts.append(source[start:source.index('\n};', start) + 3])
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    parts.append(re.search(r'^#define MAPTBLP\b(?:[^\n]*\\\n)*[^\n]*', source, re.M)[0])
    parts.append(SERVICES)
    parts.append('static u32* mergedTables[] = {' + ','.join('arena.tables.' + f[0] for f in FAMILIES) + '};')
    parts.append('static const int ids[][2] = {' + ','.join(f'{{{f[1]},{f[2]}}}' for f in FAMILIES) + '};')
    parts.append('static const int capacities[] = {' + ','.join(str(f[3]) for f in FAMILIES) + '};')
    for name in ('mergeTableFiles', 'getCurrentDataFile', 'getTableFileEntry'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CASES])


class ResourceTableMergeTests(unittest.TestCase):
    def test_policy_examples(self):
        # These rows distinguish the family-specific flags and sentinel ordering.
        for policy, a, b, expected in (
            ('texture', 0x80000012, 0x80000034, 0x40000012),
            ('texture', 0, 0x80000034, 0x80000034),
            ('model', 0, 0x1f000034, 0x20000034),
            ('model', 0, 12, 0),
            ('block', END, 0x10000034, 0x20000034),
            ('voxel', END, 0x80000034, 0),
            ('texture', END, 0x80000034, 0x80000034),
            ('voxel', 0x80000012, END, 0),
            ('block', 0x10000012, END, 0x10000012),
        ):
            self.assertEqual(expected_merge([a, 0], [b, 0], policy)[0], expected)

    def test_native_merge_and_readers(self):
        with tempfile.TemporaryDirectory(prefix='resource-tables-') as directory:
            directory = Path(directory)
            source = directory / 'tables.c'
            source.write_text(harness())
            cases = directory / 'cases.bin'
            self.assertEqual(write_cases(cases), 623)
            for region in ('VERSION_GSAE01', 'VERSION_GSAP01'):
                for optimization in ('-O0', '-O2'):
                    with self.subTest(region=region, optimization=optimization):
                        executable = directory / 'tables'
                        subprocess.run(['clang', '-std=c11', optimization, '-D' + region,
                                        '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                                        '-fsanitize=address,undefined', str(source), '-o', str(executable)],
                                       check=True, timeout=30)
                        environment = {**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'}
                        subprocess.run([str(executable), str(cases)], check=True, timeout=30, env=environment)
                        # Preserve visibility of the existing absent-bank C arithmetic limitation.
                        result = subprocess.run([str(executable), '--null'], capture_output=True, text=True,
                                                timeout=30, env=environment)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('to null pointer', result.stderr)


if __name__ == '__main__':
    unittest.main()
