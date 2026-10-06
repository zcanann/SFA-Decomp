#!/usr/bin/env python3
"""Execute model archive metadata selection, sizing and file initialization.

Production C bodies use host-endian header fixtures. The resource-address
registry is widened at the fixture boundary; production still stores target
u32 addresses there. IO/decompression, interrupts and allocation are spies.
This probes the allocator with pointers above 4 GiB, not native asset decoding.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_model_animation_lifecycle import PRELUDE
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]

SERVICES = r"""
#include <stdlib.h>
static uintptr_t gResourceFileBuffers[0x58];
static volatile int gAssetLoadInFlightFlags;
static int scratch[8], *gModelAnimOffsetTable = scratch;
static _Alignas(16) u8 archives[2][512];
static int disables, restores, tableReads, allocations, invalidations, decompressions;
static int modelId, offsetFlags, absent, allocationBias, expectedBytes, expectedStorage;
static int expectedCached, expectedAnimations;
static size_t requestedBytes;
static u8* allocation;
static ModelFileHeader serialized;
static int OSDisableInterrupts(void) { disables++; return 17; }
static void OSRestoreInterrupts(int state) {
    assert(state == 17 && disables == restores + 1);
    restores++;
    /* Selection must use the captured flags after restoring interrupts. */
    gAssetLoadInFlightFlags ^= 15;
}
static int getTableFileEntry(int file, int id, int* output) {
    assert(file == MLDF_FILEID_MODELS_TAB_A && id == modelId);
    tableReads++;
    if (absent) return 0;
    *output = offsetFlags;
    return 1;
}
static void fileLoadToBufferOffset(int file, void* output, int offset, int size) {
    assert(file == MLDF_FILEID_AMAP_TAB && output == scratch && size == 32);
    assert(offset == (modelId & ~3) * 4 && !expectedCached);
    assert(allocations == 0 && tableReads == 1);
    int index = modelId % 4;
    scratch[index] = 1024;
    scratch[index + 1] = 1024 + expectedStorage;
}
static void* mmAlloc(int bytes, int tag, int flags) {
    assert(tag == 9 && flags == 0 && allocations++ == 0);
    int tail = expectedCached ? (expectedAnimations * 2 + 15) / 8 * 8 :
        (expectedAnimations * (int)sizeof(void*) + 7) / 8 * 8 + expectedStorage;
    assert(bytes == expectedBytes + tail + 500);
    requestedBytes = bytes;
    allocation = malloc(bytes + 64);
    assert(allocation && (uintptr_t)allocation > UINT32_MAX);
    memset(allocation, 0xa5, bytes + 64);
    return allocation + allocationBias;
}
static void* alignedDestination(void) {
    return (void*)(((uintptr_t)(allocation + allocationBias) + 15) & ~(uintptr_t)15);
}
static void DCInvalidateRange(void* pointer, u32 bytes) {
    assert(pointer == alignedDestination() && bytes == requestedBytes);
    assert(allocations == 1 && decompressions == 0 && invalidations++ == 0);
}
static void loadAndDecompressDataFile(int file, void* output, int offset, int bytes,
                                      void* sizeOut, int id, int query) {
    assert(file == MLDF_FILEID_MODELS_BIN_A && output == alignedDestination());
    assert(offset == offsetFlags && bytes == expectedBytes && id == modelId);
    assert(sizeOut == NULL && query == 0 && allocations == 1 && decompressions++ == 0);
#if defined(VERSION_GSAE01)
    assert(invalidations == 0);
#else
    assert(invalidations == 1);
#endif
    memset(output, 0x5a, bytes);
    memcpy(output, &serialized, sizeof(serialized));
}
static void writeWord(u8* destination, size_t offset, s32 value) {
    memcpy(destination + offset, &value, sizeof(value));
}
static void metadata(u8* destination, s32 cached, s32 count, s32 cacheBytes, s32 dataBytes) {
    memset(destination, 0xab, 36);
    writeWord(destination, 4, dataBytes);
    writeWord(destination, 24, cached);
    writeWord(destination, 28, count);
    writeWord(destination, 32, cacheBytes);
}
"""
CASES = r"""
static void checkSelection(void) {
    unsigned cases = 0;
    for (int resident = 0; resident < 4; resident++) {
        for (int busy = 0; busy < 16; busy++) {
            for (int preference = 0; preference < 4; preference++) {
                for (int offset = 0; offset <= 128; offset += 128) {
                    memset(gResourceFileBuffers, 0, sizeof(gResourceFileBuffers));
                    int usableA = (resident & 1) && !(busy & 5);
                    int usableB = (resident & 2) && !(busy & 10);
                    if (resident && !usableA && !usableB) continue; /* Retail requires a usable bank. */
                    gResourceFileBuffers[MLDF_FILEID_MODELS_TAB_A] = resident & 1 ? 0x100 : 0;
                    gResourceFileBuffers[MLDF_FILEID_MODELS_TAB_B] = resident & 2 ? 0x200 : 0;
                    gResourceFileBuffers[MLDF_FILEID_MODELS_BIN_A] = resident & 1 ? (uintptr_t)archives[0] : 0;
                    gResourceFileBuffers[MLDF_FILEID_MODELS_BIN_B] = resident & 2 ? (uintptr_t)archives[1] : 0;
                    metadata(archives[0] + offset, -1, 858, 8512, 54321);
                    metadata(archives[1] + offset, 0, 0, INT32_MAX, -123);
                    int bank = usableB && (preference & 2) ? 1 : usableA ? 0 : 1;
                    int count = 71, cache = 72, cached = 73, bytes = 74;
                    int word = preference * 0x10000000 + offset;
                    disables = restores = 0;
                    gAssetLoadInFlightFlags = busy;
                    loadModelsBin(word, &count, &cache, &cached, &bytes, 999);
                    if (!resident) {
                        assert(count == 71 && cache == 72 && cached == 73 && bytes == 74);
                        assert(disables == 0 && restores == 0);
                    } else {
                        assert(count == (bank ? 0 : 858) && cache == (bank ? INT32_MAX : 8512));
                        assert(cached == (bank ? 0 : -1) && bytes == (bank ? -123 : 54321));
                        assert(disables == 1 && restores == 1);
                        /* Aliased outputs expose the exact retail store order. */
                        gAssetLoadInFlightFlags = busy;
                        int value = 0;
                        loadModelsBin(word, &value, &value, &value, &value, 999);
                        assert(value == bytes);
                    }
                    cases++;
                }
            }
        }
    }
    printf("%u archive bank/metadata cases checked\n", cases);
}
static void checkLoad(int missing, int cached, int count, int cacheBytes, int flags, int bias, int id) {
    modelId = id;
    offsetFlags = 0x20000080;
    absent = missing;
    allocationBias = bias;
    expectedBytes = sizeof(ModelFileHeader) + 128;
    expectedStorage = 37 + id;
    expectedCached = cached;
    expectedAnimations = count;
    allocation = NULL;
    disables = restores = tableReads = allocations = invalidations = decompressions = 0;
    memset(gResourceFileBuffers, 0, sizeof(gResourceFileBuffers));
    gResourceFileBuffers[MLDF_FILEID_MODELS_TAB_B] = 0x200;
    gResourceFileBuffers[MLDF_FILEID_MODELS_BIN_B] = (uintptr_t)archives[1];
    gAssetLoadInFlightFlags = 0;
    metadata(archives[1] + 128, cached, count, cacheBytes, expectedBytes);
    memset(&serialized, 0x69, sizeof(serialized));
    serialized.flags = flags;
    ModelFileHeader expected;
    memcpy(&expected, &serialized, sizeof(expected));
    expected.animationCacheSize = (cacheBytes + 7) / 8 * 8 + 176;
    expected.modelId = id;
    expected.animationCount = count;
    expected.refCount = 1;
    expected.flags &= ~0x40;
    if (!count) expected.flags |= 2;
    if (cached) expected.flags |= 0x40;
    ModelFileHeader* result = ObjModel_LoadModelData(id);
    assert(tableReads == 1);
    if (missing) {
        assert(result == NULL && allocation == NULL && !disables && !allocations && !decompressions);
        return;
    }
    assert(result == alignedDestination() && ((uintptr_t)result & 15) == 0);
    assert(allocations == 1 && decompressions == 1 && disables == 1 && restores == 1);
    assert(memcmp(result, &expected, sizeof(expected)) == 0);
    u8* start = (u8*)result;
    for (u8* p = allocation; p < start; p++) assert(*p == 0xa5);
    for (size_t i = sizeof(expected); i < (size_t)expectedBytes; i++) assert(start[i] == 0x5a);
    for (u8* p = start + expectedBytes; p < allocation + requestedBytes + 64; p++) assert(*p == 0xa5);
    free(allocation);
}
int main(void) {
    checkSelection();
    const int counts[] = {0, 1, 7, 858};
    const int sizes[] = {0, 1, 7, 8, 8512, 14952};
    const int flags[] = {0, 2, 0x40, 0xffff};
    unsigned cases = 0;
    for (int cached = 0; cached <= 1; cached++) for (int n = 0; n < 4; n++)
        for (int s = 0; s < 6; s++) for (int f = 0; f < 4; f++) for (int bias = 0; bias < 16; bias++) {
            checkLoad(0, cached, counts[n], sizes[s], flags[f], bias, bias + 4);
            cases++;
        }
    checkLoad(1, 0, 1, 8, 0, 0, 99);
    printf("%u model allocations plus absent-table return checked\n", cases);
    return 0;
}
"""


def harness():
    model = (ROOT / 'src/main/model.c').read_text()
    header = (ROOT / 'include/main/model.h').read_text()
    pi = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE, 'typedef union ModelTextureEntry ModelTextureEntry;',
             (ROOT / 'include/main/mldf_fileid.h').read_text()]
    for name in ('MODEL_FLAG_CACHED_ANIMATIONS', 'MODEL_FLAG_NO_ANIMATIONS'):
        parts.append(re.search(rf'^#define {name}\s+[^\n]+', header, re.M)[0])
    for source, kind, name in (
        (header, 'struct', 'ModelVtxAnimJob'), (header, 'struct', 'ModelFuzzScaleDef'),
        (header, 'struct', 'ModelFileHeader'), (model, 'union', 'ModelAnimationOffsetScratch'),
        (pi, 'struct', 'ModelArchiveHeaderPrefix'),
    ):
        if name == 'ModelArchiveHeaderPrefix':
            parts.append(re.search(r'struct PackHeader \{.*?\n\};', pi, re.S)[0])
        parts.append(re.search(rf'typedef {kind} {name}\s*\{{.*?\}} {name};', source, re.S)[0])
    parts.append(SERVICES)
    for name in ('roundUpTo8', 'roundUpTo16'):
        parts.append(function((ROOT / 'src/main/mm.c').read_text(), name))
    parts.append(function(pi, 'loadModelsBin'))
    parts.append(function(model, 'modelGetAmapSize'))
    parts.append(function(model, 'ObjModel_LoadModelData'))
    return '\n'.join(parts + [CASES])


class ModelArchiveLoadingTests(unittest.TestCase):
    def test_metadata_and_allocation(self):
        with tempfile.TemporaryDirectory(prefix='model-archive-') as directory:
            source = Path(directory) / 'loading.c'
            source.write_text(harness())
            for version in ('VERSION_GSAE01', 'VERSION_GSAP01'):
                for optimization in ('-O0', '-O2'):
                    with self.subTest(version=version, optimization=optimization):
                        executable = Path(directory) / 'loading'
                        subprocess.run(['clang', '-std=c11', optimization, '-D' + version,
                                        '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                                        '-Wno-unused-parameter', '-fsanitize=address,undefined',
                                        str(source), '-o', str(executable)], check=True, timeout=30)
                        subprocess.run([str(executable)], check=True, timeout=30,
                                       env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
