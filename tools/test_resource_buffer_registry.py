#!/usr/bin/env python3
"""Exercise the production resident-resource registry and its direct consumers.

Records are host-endian and the registry uses its real pointer declaration.
DVD, cache maintenance, allocation and callback-pool operations are spies.
The separate romlist registry and the adjacent-global MldfTables view
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
typedef uint16_t u16; typedef int8_t s8; typedef float f32;
typedef struct DVDFileInfo { u32 length; } DVDFileInfo;
"""
SERVICES = r"""
enum { OPEN, ALLOCATE, INVALIDATE, READ, CLOSE, STORE, FREE, PUSH };
static int events[32], eventCount;
static _Alignas(32) u8 resident[2048], disk[2048], output[2048];
static char* sResourceFileNameTable[0x58];
static char sDirBlockTag[] = "DIR", sZlbBlockTag[] = "ZLB";
static volatile int gAssetLoadInFlightFlags, gAssetLoadCompletedFlags;
static int interruptCalls, restoreFlags;
static DVDFileInfo activeFiles[88];
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
static void* mmAlloc(int bytes, u32 tag, const char* allocationName) {
    assert(bytes == expectedAllocation && tag == expectedTag && allocationName == 0);
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
static int OSDisableInterrupts(void) { interruptCalls++; return 19; }
static void OSRestoreInterrupts(int value) {
    assert(value == 19);
    if (restoreFlags != -1) gAssetLoadInFlightFlags = restoreFlags;
}
static void reset(void) {
    memset(gResourceFileBuffers, 0, sizeof(gResourceFileBuffers));
    memset(gResourceFileSizes, 0, sizeof(gResourceFileSizes));
    memset(&gResourceTableWorkspace, 0xab, sizeof(gResourceTableWorkspace));
    assert((uintptr_t)activeFiles > UINT32_MAX);
    for (int i = 0; i < 88; i++) gResourceTableWorkspace.fileInfo[i] = &activeFiles[i];
    for (int i = 0; i < 2048; i++) resident[i] = disk[i] = i * 13 + 7;
    memset(output, 0xcc, sizeof(output));
    for (int i = 0; i < 0x58; i++) sResourceFileNameTable[i] = (char*)&resident[i];
    eventCount = closed = freed = pushed = interruptCalls = 0;
    restoreFlags = -1;
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
/* Independent callback contract: destination slot, completion bit and release slot.
   Generic callbacks prefer bank A when both bits are set; failed reads leave both
   slots untouched. Texture-table callbacks can complete even on failure, and the
   two TEX1 failures release TEX0 slot B, as in retail. */
static const struct {
    void (*callback)(s32, DVDFileInfo*);
    u32 flags[2];
    int slots[2];
    int releaseSlot;
} callbackCases[] = {
    {animCurvReadCb,    {0x10000000, 0x40000000}, {13, 85}, -1},
    {animCurvTabReadCb, {0x20000000, 0x80000000}, {14, 86}, -1},
    {voxMapReadCb,      {0x01000000, 0x04000000}, {27, 84}, -1},
    {voxMapTabReadCb,   {0x02000000, 0x08000000}, {26, 83}, -1},
    {blocksReadCb,      {0x00010000, 0x00040000}, {37, 71}, -1},
    {blocksTabReadCb,   {0x00020000, 0x00080000}, {38, 72}, -1},
    {tex1ReadCb,        {0x00001000, 0x00002000}, {32, 75}, -1},
    {tex0readCb,        {0x00000100, 0x00000200}, {35, 77}, -1},
    {animReadCb,        {0x00000010, 0x00000020}, {48, 74}, -1},
    {modelsReadCb,      {0x00000001, 0x00000002}, {43, 70}, -1},
    {animTabReadCb,     {0x00000040, 0x00000080}, {47, 73}, -1},
    {modelsTabReadCb,   {0x00000004, 0x00000008}, {42, 69}, -1},
    {tex1tab2readCb,    {0x00008000, 0},          {76, -1}, 78},
    {tex1tab1readCb,    {0x00004000, 0},          {33, -1}, 78},
    {tex0tab2readCb,    {0x00000800, 0},          {78, -1}, 78},
    {tex0tab1readCb,    {0x00000400, 0},          {36, -1}, 36},
};
static void checkCallback(int which, int result, int ready) {
    reset();
    const int released = callbackCases[which].releaseSlot;
    const int failed = result < 0;
    const u32 initialCompleted = 0x00200000, unrelatedFlag = 0x00100000;
    u32 expectedCompleted = initialCompleted;
    DVDFileInfo info = {0};
    struct ResourceTableWorkspace expected;
    memcpy(&expected, &gResourceTableWorkspace, sizeof(expected));
    gAssetLoadInFlightFlags = unrelatedFlag;
    for (int bank = 0; bank < 2; bank++) if (ready & (1 << bank))
        gAssetLoadInFlightFlags |= callbackCases[which].flags[bank];
    u32 inFlight = gAssetLoadInFlightFlags;
    gAssetLoadCompletedFlags = initialCompleted;
    if (released >= 0) {
        gResourceFileBuffers[released] = allocation = resident;
        if (failed) expected.fileInfo[released] = NULL;
    }
    if (!failed || released >= 0) {
        for (int bank = 0; bank < 2; bank++) {
            if (!(ready & (1 << bank))) continue;
            expected.fileInfo[callbackCases[which].slots[bank]] = NULL;
            expectedCompleted |= callbackCases[which].flags[bank];
            break;
        }
    }
    callbackCases[which].callback(result, &info);
    assert(closed == 1 && pushed == 1 && freed == (failed && released >= 0));
    assert((u32)gAssetLoadInFlightFlags == inFlight);
    assert((u32)gAssetLoadCompletedFlags == expectedCompleted);
    if (failed && released >= 0) expectEvents((int[]){CLOSE, PUSH, FREE}, 3);
    else expectEvents((int[]){CLOSE, PUSH}, 2);
    for (int i = 0; i < 88; i++) {
        assert(gResourceFileBuffers[i] == (i == released && !failed ? resident : NULL));
    }
    /* Check the complete pointer width, every untouched slot, all seven tables
       and the load flags, not just the low word of each cleared pointer. */
    assert(memcmp(&gResourceTableWorkspace, &expected, sizeof(expected)) == 0);
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
    memcpy(header + 64, direct ? "DIR!" : "ZLB\0", 4);
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

/* Explicit bank-selection scenarios, independent of the production predicates.
   Request/load bits here are A=1, B=2, not their encoded archive masks. */
static const struct {
    int request, loading, tables, bins, selected, tex1Only;
} textureSelections[] = {
    {0, 0, 3, 3, 0, 0}, /* unflagged, prefer A */
    {0, 0, 2, 3, 1, 0}, /* only B table */
    {0, 1, 3, 3, 1, 0}, /* A is loading */
    {0, 2, 3, 3, 0, 0}, /* B is loading */
    {1, 0, 0, 3, 0, 0}, /* explicit A needs no table */
    {2, 0, 0, 3, 1, 0}, /* explicit B needs no table */
    {3, 0, 3, 3, 1, 0}, /* both request bits prefer B */
    {3, 2, 3, 3, 0, 0}, /* both requested, B loading */
    {1, 1, 3, 3, 1, 0}, /* requested A loading, use B table */
    {2, 2, 3, 3, 0, 0}, /* requested B loading, use A table */
    {0, 0, 3, 2, 1, 1}, /* TEX1 skips absent A bin despite A table */
    {1, 0, 0, 2, 0, 1}, /* TEX1 reads explicit absent A from DVD */
    {2, 0, 0, 1, 1, 1}, /* TEX1 reads explicit absent B from DVD */
    {0, 3, 3, 0, -1, 0}, /* no resident bin: untouched outputs */
    {3, 0, 3, 0, -1, 0},
    {0, 0, 0, 0, -1, 0},
};
static int checkTextureSelection(int kind, int scenario, int query, int hasOffsets, int direct) {
    if (!kind && textureSelections[scenario].tex1Only) return 0;
    reset();
    const int slots[2][2] = {{0x23, 0x4d}, {0x20, 0x4b}};
    const int tabs[2][2] = {{0x24, 0x4e}, {0x21, 0x4c}};
    int selected = textureSelections[scenario].selected;
    int bins = textureSelections[scenario].bins;
    for (int bank = 0; bank < 2; bank++) {
        u8* base = resident + bank * 512;
        gResourceFileBuffers[slots[kind][bank]] = bins & (1 << bank) ? base : NULL;
        gResourceFileBuffers[tabs[kind][bank]] = textureSelections[scenario].tables & (1 << bank) ? output : NULL;
        /* Distinct sizes identify both the selected bank and frame. */
        for (int frame = 0; frame < 2; frame++) {
            u8* header = base + 32 + frame * 64;
            memcpy(header, direct ? "DIR!" : "ZLB\0", 4);
            word(header, 4, 1);
            word(header, 8, 1000 + bank * 100 + frame * 10);
            word(header, 12, 2000 + bank * 100 + frame * 10);
        }
    }
    int fallback = selected >= 0 && !(bins & (1 << selected));
    if (fallback) {
        expectedId = slots[kind][selected]; expectedOffset = 32;
        expectedAllocation = 1024; expectedTag = 0x7f7f7fff;
        memcpy(disk, resident + selected * 512 + 32, 1024);
    }
    gAssetLoadInFlightFlags = textureSelections[scenario].loading << (kind ? 12 : 8);
    /* A completion immediately after restoration must not change the snapshot. */
    restoreFlags = (textureSelections[scenario].loading ^ 3) << (kind ? 12 : 8);
    u32 request = textureSelections[scenario].request;
    int bankWord = 16 | (request & 1 ? 0x40000000u : 0) | (request & 2 ? 0x80000000u : 0);
    int offsets[4] = {0, 64, 128, 192};
    int size = -77, packed = -88;
    void (*reader)(int,int,int*,int*,int,int*,int) = kind ? tex1GetFrame : tex0GetFrame;
    reader(bankWord, 99, &size, &packed, query == 2 ? 2 : 1, hasOffsets ? offsets : NULL, query);
    assert(interruptCalls == (selected >= 0));
    if (selected < 0) {
        assert(size == -77 && packed == -88);
        assert(memcmp(offsets, (int[]){0, 64, 128, 192}, sizeof(offsets)) == 0);
    } else if (query == 2 && hasOffsets) {
        assert(size == -77 && packed == -88);
        assert(memcmp(offsets, resident + selected * 512 + 32, 12) == 0);
        assert(offsets[3] == 192);
    } else {
        int frame = query == 1 && hasOffsets;
        assert(size == 1000 + selected * 100 + frame * 10);
        assert(packed == (kind && direct && !frame ? -1 : 2000 + selected * 100 + frame * 10));
        assert(memcmp(offsets, (int[]){0, 64, 128, 192}, sizeof(offsets)) == 0);
    }
    if (fallback) expectEvents((int[]){OPEN, ALLOCATE, READ, CLOSE, STORE, FREE}, 6);
    else expectEvents(NULL, 0);
    return 1;
}
static void checkTextureAliasedOutputs(int kind, int query, int direct) {
    reset();
    const int slots[] = {0x23, 0x20, 0x4f};
    void (*readers[])(int,int,int*,int*,int,int*,int) = {tex0GetFrame, tex1GetFrame, texPreGetFrame};
    gResourceFileBuffers[slots[kind]] = resident;
    u8* header = resident + 32 + (query == 1 ? 64 : 0);
    memcpy(header, direct ? "DIR!" : "ZLB\0", 4);
    word(header, 8, 1234); word(header, 12, 5678);
    int offsets[] = {0, 64}, result = -77;
    readers[kind](0x40000010, 99, &result, &result, 1, offsets, query);
    /* TEX1 indexed outputs have the reverse store order. */
    assert(result == (kind == 1 && query == 1 ? 1234 : kind && direct && query != 1 ? -1 : 5678));
    expectEvents(NULL, 0);
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
    MapRomListPage* page = (MapRomListPage*)(resident + 128);
    page->objectCount = values[0]; page->unk1E = values[1];
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
    for (int cb = 0; cb < 16; cb++) for (int result = -1; result <= 1; result++)
        for (int flags = 0; flags < (cb < 12 ? 4 : 2); flags++) checkCallback(cb, result, flags);
    for (int kind = 0; kind < 3; kind++) for (int bank = 0; bank < 2; bank++)
        for (int query = 0; query < 3; query++) for (int direct = 0; direct < 2; direct++)
            for (int offsets = 0; offsets < 2; offsets++) {
                checkTexture(kind, bank, query, direct, 0, offsets);
                if (kind == 1) checkTexture(kind, bank, query, direct, 1, offsets);
            }
    int frameCases = 0;
    const int queries[] = {0, 1, 2, 7, -17};
    for (int kind = 0; kind < 2; kind++) for (int scenario = 0; scenario < 16; scenario++)
        for (int query = 0; query < 5; query++) for (int offsets = 0; offsets < 2; offsets++)
            for (int direct = 0; direct < 2; direct++)
                frameCases += checkTextureSelection(kind, scenario, queries[query], offsets, direct);
    for (int kind = 0; kind < 3; kind++) for (int query = 0; query < 2; query++)
        for (int direct = 0; direct < 2; direct++) {
            checkTextureAliasedOutputs(kind, query, direct); frameCases++;
        }
    printf("%d additional texture selection, snapshot and aliased-output cases checked\n", frameCases);
    for (int vox = 0; vox < 2; vox++) for (int bank = 0; bank < 2; bank++)
        for (int present = 0; present < 2; present++) for (int valid = 0; valid < 2; valid++)
            for (int flagged = 0; flagged < 2; flagged++) checkBlock(vox, bank, present, valid, flagged);
    for (int present = 0; present < 4; present++) checkMap(present);
    puts("790 resource registry cases checked, including 168 full-workspace callback checks");
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE, re.search(r'struct ResourceTableWorkspace \{.*?\n\};', source, re.S)[0]]
    parts.append('static ' + re.search(r'^struct ResourceTableWorkspace gResourceTableWorkspace;', source, re.M)[0])
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    for name in ('gResourceFileBuffers', 'gResourceFileSizes'):
        parts.append('static ' + re.search(rf'^(?:void\*|u32) {name}\[[^;]+;', source, re.M)[0])
    parts.append(re.search(r'struct ZlbStreamInfo \{.*?\n\};', source, re.S)[0])
    parts.append(re.search(r'struct ZlbHeader \{.*?\n\};', source, re.S)[0])
    parts.append(re.search(r'^#define ZLB_HDR[^\n]+', source, re.M)[0])
    modes = (ROOT / 'include/main/pi_dolphin_texture_api.h').read_text()
    parts.extend(re.findall(r'^#define TEXTURE_FRAME_QUERY_[^\n]+', modes, re.M))
    bank_header = (ROOT / 'include/main/rcp_dolphin.h').read_text()
    parts.extend(re.findall(r'^#define TEX_TAB_MAP_[^\n]+', bank_header, re.M))
    page_header = (ROOT / 'include/main/map_romlist_page.h').read_text()
    parts.append('typedef struct ObjPlacement ObjPlacement;')
    for name in ('MapRomListOffsets', 'MapRomListPage'):
        parts.append(re.search(rf'typedef struct {name}\s*\{{.*?\}} {name};', page_header, re.S)[0])
    parts.append(re.search(r'struct PackHeader \{.*?\n\};', source, re.S)[0])
    parts.append(SERVICES)
    for name in ('animCurvReadCb', 'animCurvTabReadCb', 'voxMapReadCb', 'voxMapTabReadCb',
                 'blocksReadCb', 'blocksTabReadCb', 'tex1ReadCb', 'tex0readCb',
                 'animReadCb', 'modelsReadCb', 'animTabReadCb', 'modelsTabReadCb', 'tex1tab2readCb', 'tex1tab1readCb', 'tex0tab2readCb', 'tex0tab1readCb',
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
