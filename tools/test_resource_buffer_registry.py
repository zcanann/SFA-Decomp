#!/usr/bin/env python3
"""Exercise the production resident-resource registry and its direct consumers.

Records are host-endian and the registry uses its real pointer declaration.
DVD, cache maintenance, allocation and callback-pool operations are spies.
The separate integer romlist registry and the adjacent-global MldfTables view
are not modeled as a native allocation. Missing-resource intentional crashes
and bank-selection states with no usable bank are not exercised.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
typedef int16_t s16;
typedef struct DVDFileInfo { u32 length; } DVDFileInfo;
"""
SERVICES = r"""
enum { OPEN, ALLOCATE, INVALIDATE, READ, CLOSE, STORE, FREE, PUSH };
static int events[32], eventCount;
static _Alignas(32) u8 resident[2048], disk[2048], output[2048];
static char* sResourceFileNameTable[0x58];
static char sDirBlockTag[] = "DIR", sZlbBlockTag[] = "ZLB";
static int gAssetLoadInFlightFlags, gAssetLoadCompletedFlags;
static void* poolEntry;
static void** gDvdFileInfoPool = &poolEntry;
static int expectedId, expectedSize, expectedOffset, expectedAllocation;
static u32 expectedTag;
static void* allocation;
static int actualAllocation, closed, pushed, freed;
static void event(int kind) { assert(eventCount < 32); events[eventCount++] = kind; }
static void expectEvents(const int* expected, int count) {
    assert(eventCount == count);
    if (count) assert(memcmp(events, expected, count * sizeof(int)) == 0);
}
static int DVDOpen(char* name, DVDFileInfo* file) {
    assert(name == sResourceFileNameTable[expectedId]);
    file->length = expectedSize;
    event(OPEN);
    return 1;
}
static void DVDRead(DVDFileInfo* file, void* destination, int size, int offset) {
    assert(file && size >= 0 && size <= 2048 && offset == expectedOffset);
    assert((uintptr_t)destination > UINT32_MAX);
    memcpy(destination, disk, size);
    event(READ);
}
static void DVDClose(DVDFileInfo* file) { assert(file); closed++; event(CLOSE); }
static void* mmAlloc(int bytes, u32 tag, int flags) {
    assert(bytes == expectedAllocation && tag == expectedTag && flags == 0);
    actualAllocation = bytes;
    allocation = malloc(bytes + 32);
    assert(allocation && (uintptr_t)allocation > UINT32_MAX);
    memset(allocation, 0xa7, bytes + 32);
    event(ALLOCATE);
    return allocation;
}
static void mm_free(void* pointer) {
    assert(pointer == allocation);
    if (actualAllocation >= 0) {
        for (int i = 0; i < 32; i++) assert(((u8*)pointer)[actualAllocation + i] == 0xa7);
        free(pointer);
    }
    freed++;
    event(FREE);
}
static void DCInvalidateRange(void* pointer, u32 size) {
    assert((uintptr_t)pointer > UINT32_MAX && size <= 2048);
    event(INVALIDATE);
}
static void DCStoreRange(void* pointer, u32 size) {
    assert((uintptr_t)pointer > UINT32_MAX && size <= 2048);
    event(STORE);
}
static void AtomicSList_Push(void** pool, DVDFileInfo* file) {
    assert(pool == gDvdFileInfoPool && file && closed == 1);
    pushed++;
    event(PUSH);
}
static int OSDisableInterrupts(void) { return 19; }
static void OSRestoreInterrupts(int value) { assert(value == 19); }
static void reset(void) {
    memset(gResourceFileBuffers, 0, sizeof(gResourceFileBuffers));
    memset(gResourceFileSizes, 0, sizeof(gResourceFileSizes));
    memset(gObjBlockStatus, 0xab, sizeof(gObjBlockStatus));
    for (int i = 0; i < 2048; i++) resident[i] = disk[i] = i * 13 + 7;
    memset(output, 0xcc, sizeof(output));
    for (int i = 0; i < 0x58; i++) sResourceFileNameTable[i] = (char*)&resident[i];
    eventCount = closed = freed = pushed = 0;
    allocation = NULL;
    actualAllocation = -1;
    gAssetLoadInFlightFlags = gAssetLoadCompletedFlags = 0;
    expectedId = 0x2c;
    expectedSize = 96;
    expectedOffset = 0;
    expectedTag = 0x7d7d7d7d;
}
static void word(u8* buffer, int offset, int value) { memcpy(buffer + offset, &value, 4); }
"""
CASES = r"""
static void checkOffset(int hit, int size, int alignment) {
    reset();
    expectedOffset = 64;
    expectedAllocation = (size + 31) / 32 * 32;
    gResourceFileBuffers[expectedId] = hit ? resident : NULL;
    void* destination = output + 32 + alignment;
    assert(fileLoadToBufferOffset(expectedId, destination, 64, size) == size);
    assert(gResourceFileBuffers[expectedId] == (hit ? resident : NULL));
    if (!size) expectEvents(NULL, 0);
    else if (hit) expectEvents((int[]){STORE}, 1);
    else if (alignment || (size & 31)) expectEvents((int[]){OPEN, ALLOCATE, INVALIDATE, READ, FREE, CLOSE, STORE}, 7);
    else expectEvents((int[]){OPEN, INVALIDATE, READ, CLOSE, STORE}, 5);
    assert(memcmp(destination, hit ? resident + 64 : disk, size) == 0);
    for (u8* p = output; p < (u8*)destination; p++) assert(*p == 0xcc);
    for (u8* p = (u8*)destination + size; p < output + sizeof(output); p++) assert(*p == 0xcc);
}
static void checkWhole(int hit, int size) {
    reset(); expectedSize = size;
    gResourceFileBuffers[expectedId] = hit ? resident : NULL;
    gResourceFileSizes[expectedId] = size;
    assert(fileLoadToBuffer(expectedId, output) == size);
    assert(memcmp(output, hit ? resident : disk, size) == 0);
    if (hit) expectEvents((int[]){STORE}, 1);
    else expectEvents((int[]){OPEN, INVALIDATE, READ, CLOSE}, 4);
    assert(gResourceFileBuffers[expectedId] == (hit ? resident : NULL));
}
static void checkAcquire(int hit, int size, int id) {
    reset(); expectedId = id; expectedSize = size; expectedAllocation = size + 32;
    gResourceFileBuffers[id] = hit ? resident : NULL;
    gResourceFileSizes[id] = hit ? size : 0;
    void* result = fileLoad(id, 99);
    assert(result == gResourceFileBuffers[id] && gResourceFileSizes[id] == (u32)size);
    assert(getDataFileSize(id) == size);
    if (hit) { assert(result == resident); expectEvents(NULL, 0); }
    else {
        assert(result == allocation && memcmp(result, disk, size) == 0);
        expectEvents((int[]){OPEN, ALLOCATE, INVALIDATE, READ, CLOSE}, 5);
        for (int i = size; i < size + 64; i++) assert(((u8*)result)[i] == 0xa7);
        free(result);
    }
}
static void checkCallback(int which, int failed, int ready) {
    reset();
    void (*callbacks[])(s32, DVDFileInfo*) = {tex1tab2readCb, tex1tab1readCb, tex0tab2readCb, tex0tab1readCb};
    const int flags[] = {0x8000, 0x4000, 0x800, 0x400};
    const int releaseSlot[] = {78, 78, 78, 36};
    const int statusSlot[] = {76, 33, 78, 36};
    DVDFileInfo info = {0};
    gAssetLoadInFlightFlags = ready ? flags[which] : 0;
    gResourceFileBuffers[releaseSlot[which]] = allocation = resident;
    callbacks[which](failed ? -1 : 0, &info);
    assert(closed == 1 && pushed == 1 && freed == failed);
    assert(gResourceFileBuffers[releaseSlot[which]] == (failed ? NULL : resident));
    assert(gAssetLoadCompletedFlags == (ready ? flags[which] : 0));
    if (failed) expectEvents((int[]){CLOSE, PUSH, FREE}, 3);
    else expectEvents((int[]){CLOSE, PUSH}, 2);
    for (int i = 0; i < 88; i++) {
        int cleared = (failed && i == releaseSlot[which]) || (ready && i == statusSlot[which]);
        assert(gObjBlockStatus[i] == (cleared ? 0u : 0xababababu));
    }
}
static void checkTexture(int kind, int bank, int query, int direct, int fallback, int hasOffsets) {
    reset();
    const int files[3][2] = {{0x23, 0x4d}, {0x20, 0x4b}, {0x4f, 0x4f}};
    const int tables[3][2] = {{0x24, 0x4e}, {0x21, 0x4c}, {0x50, 0x50}};
    void (*readers[])(int,int,int*,int*,int,int*,int) = {tex0GetFrame, tex1GetFrame, texPreGetFrame};
    int offsets[4] = {0, 64, 128, 192}, original[4];
    memcpy(original, offsets, sizeof(offsets));
    int count = query == 2 ? 2 : 1;
    expectedId = files[kind][bank]; expectedOffset = 32; expectedAllocation = 1024; expectedTag = 0x7f7f7fff;
    gResourceFileBuffers[tables[kind][bank]] = resident + 512;
    gResourceFileBuffers[files[kind][bank]] = fallback ? NULL : resident;
    if (fallback) gResourceFileBuffers[files[kind][!bank]] = resident; /* outer guard, select empty bank by flag */
    u8* header = resident + 32;
    memcpy(header, direct ? "DIR\0" : "ZLB\0", 4);
    word(header, 8, 0x123456); word(header, 12, 0x654321);
    word(header, 64 + 8, 0x112233); word(header, 64 + 12, 0x445566);
    memcpy(disk, header, 1024);
    int size = -77, packedSize = -88;
    readers[kind](16 | (bank ? 0x80000000 : 0x40000000), 99, &size, &packedSize, count,
                  hasOffsets ? offsets : NULL, query);
    if (query == 2 && hasOffsets) {
        assert(size == -77 && packedSize == -88 && memcmp(offsets, header, 12) == 0);
        assert(offsets[3] == original[3]);
    } else if (query == 1 && hasOffsets) {
        assert(size == 0x112233 && packedSize == 0x445566);
        assert(memcmp(offsets, original, sizeof(offsets)) == 0);
    } else {
        assert(size == 0x123456 && packedSize == (direct && kind != 0 ? -1 : 0x654321));
    }
    if (fallback) expectEvents((int[]){OPEN, ALLOCATE, READ, CLOSE, STORE, FREE}, 6);
    else expectEvents(NULL, 0);
}
static void checkBlock(int vox, int bank, int present, int validTag, int flagged) {
    reset();
    int file = vox ? (bank ? 0x54 : 0x1b) : (bank ? 0x47 : 0x25);
    int table = vox ? (bank ? 0x53 : 0x1a) : (bank ? 0x48 : 0x26);
    gResourceFileBuffers[file] = present ? resident : NULL;
    gResourceFileBuffers[table] = present ? resident + 512 : NULL;
    memcpy(resident + 32, validTag ? "ZLB\0" : "BAD\0", 4);
    word(resident + 32, 8, 12345); word(resident + 32, 12, 6789);
    int size = -1, packedSize = -1;
    int flags = flagged ? (bank ? 0x20000000 : vox ? 0x80000000 : 0x10000000) : 0;
    if (vox) loadVoxMaps(flags | 32, &packedSize, &size);
    else checkLoadBlock(flags | 32, &packedSize, &size);
    int reads = present && validTag && (!vox || flagged);
    assert(size == (reads ? 12345 : 0) && packedSize == (reads ? 6789 : 0));
}
static void checkMap(int present) {
    reset();
    s16 values[] = {-1234, 2345};
    memcpy(resident + 128 + 28, values, sizeof(values));
    word(resident, 256 + 4, 54321); word(disk, 2 * 4 + 24, 256);
    gResourceFileBuffers[0x1d] = present & 1 ? resident : NULL;
    gResourceFileBuffers[0x1e] = present & 2 ? disk : NULL;
    int a = -1, b = -2, c = -3;
    mapsBinGetRomlistSize(128, &a, &b, &c, 2);
    assert(a == (present == 3 ? -1234 : -1));
    assert(b == (present == 3 ? 2345 : -2));
    assert(c == (present == 3 ? 54321 : -3));
}
int main(void) {
    const int sizes[] = {0, 1, 31, 32, 33, 65, 255};
    for (int hit = 0; hit < 2; hit++) for (int size = 0; size < 7; size++) {
        for (int alignment = 0; alignment < 32; alignment++) checkOffset(hit, sizes[size], alignment);
        checkWhole(hit, sizes[size]);
        checkAcquire(hit, sizes[size], 0); checkAcquire(hit, sizes[size], 87);
    }
    for (int cb = 0; cb < 4; cb++) for (int failure = 0; failure < 2; failure++)
        for (int flag = 0; flag < 2; flag++) checkCallback(cb, failure, flag);
    for (int kind = 0; kind < 3; kind++) for (int bank = 0; bank < 2; bank++)
        for (int query = 0; query < 3; query++) for (int direct = 0; direct < 2; direct++)
            for (int offsets = 0; offsets < 2; offsets++) {
                checkTexture(kind, bank, query, direct, 0, offsets);
                if (kind == 1) checkTexture(kind, bank, query, direct, 1, offsets);
            }
    for (int vox = 0; vox < 2; vox++) for (int bank = 0; bank < 2; bank++)
        for (int present = 0; present < 2; present++) for (int valid = 0; valid < 2; valid++)
            for (int flagged = 0; flagged < 2; flagged++) checkBlock(vox, bank, present, valid, flagged);
    for (int present = 0; present < 4; present++) checkMap(present);
    puts("638 resource registry, IO, metadata and callback cases checked");
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    for name in ('gResourceFileBuffers', 'gResourceFileSizes', 'gObjBlockStatus'):
        parts.append('static ' + re.search(rf'^(?:void\*|u32) {name}\[[^;]+;', source, re.M)[0])
    parts.append(re.search(r'struct ZlbHeader \{.*?\n\};', source, re.S)[0])
    parts.append(re.search(r'^#define ZLB_HDR[^\n]+', source, re.M)[0])
    modes = (ROOT / 'include/main/pi_dolphin_texture_api.h').read_text()
    parts.extend(re.findall(r'^#define TEXTURE_FRAME_QUERY_[^\n]+', modes, re.M))
    parts.append(SERVICES)
    for name in ('tex1tab2readCb', 'tex1tab1readCb', 'tex0tab2readCb', 'tex0tab1readCb',
                 'getDataFileSize', 'fileLoad', 'fileLoadToBuffer', 'fileLoadToBufferOffset',
                 'tex1GetFrame', 'tex0GetFrame', 'texPreGetFrame', 'checkLoadBlock', 'loadVoxMaps',
                 'mapsBinGetRomlistSize'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CASES])


class ResourceBufferRegistryTests(unittest.TestCase):
    def test_native_registry_and_consumers(self):
        with tempfile.TemporaryDirectory(prefix='resource-registry-') as directory:
            source = Path(directory) / 'registry.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / 'registry'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-parameter', '-Wno-null-dereference', '-fsanitize=address,undefined', str(source),
                                    '-o', str(executable)], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
