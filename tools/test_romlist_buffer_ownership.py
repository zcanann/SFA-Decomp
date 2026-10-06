#!/usr/bin/env python3
"""Exercise romlist allocation, startup and map-release ownership at native width.

The complete production bodies use a host allocation for the MldfTables address
view, which spans separate globals in retail. Registry types are checked against
the production declarations. Headers are host-endian; DVD, decompression, table
merging and engine services are spies. No native asset decoding is claimed.
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
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef uint32_t u32;
typedef float f32;
typedef struct DVDFileInfo { u32 length; int slot; } DVDFileInfo;
"""
SERVICES = r"""
static union { struct MldfTables tables; MldfArenaBlock bytes; } arena;
#define gResourceFileTable ((u8*)&arena)
#define gMapRomListBuffers (arena.tables.romList)
#define gResourceFileBuffers (arena.tables.ptrs)
static void* pool;
static void** gDvdFileInfoPool = &pool;
static u32 gRomListLoadInFlight;
static int gAssetLoadInFlightFlags, gAssetLoadCompletedFlags, gPendingDvdReadCount;
static u8 gLoadFilesInitDone, gDvdErrorPauseActive;
static int lbl_803DCC98, gObjLevelLockSlots[2], sMapFileNameIndexRemapTable[75];
static char* sMapFileNameTable[117];
static char* sResourceFileNameTable[88];
static char names[117][16];
static SaveGameCharacterPosition position;
static SaveGameCharacterPosition* getPosition(void) { return &position; }
static struct TestMapEventInterface { SaveGameCharacterPosition* (*getCurCharPos)(void); } interface = {getPosition};
static struct TestMapEventInterface* interfacePointer = &interface;
static struct TestMapEventInterface** gMapEventInterface = &interfacePointer;
static _Alignas(16) u8 maps[256], output[256], marker[16];
static DVDFileInfo files[256];
static int fileCount, openOK, phase, expectedMap, expectedOffset;
static int opens, reads, closes, pushes, asyncs, inflates, stores, frees, merges, mapLoads;
static int heapCalls, waitLoads, waits, frames, createCalls;
static void* allocations[256];
static int allocationSizes[256], allocationFreed[256], allocationCount;
static void (*callbacks[256])(s32, DVDFileInfo*);
static DVDFileInfo* callbackFiles[256];
static int callbackCount;
static int trace[4096], traceCount;
enum { POP=1, OPEN, ALLOC, READ, ASYNC, CLOSE, PUSH, INFLATE, STORE, FREE };
static void event(int value) { assert(traceCount < 4096); trace[traceCount++] = value; }
static void* stackCreate(int count, int size) {
    assert(count == 94 && size == 64); createCalls++; return &pool;
}
static void* AtomicSList_Pop(void** p) {
    assert(p == gDvdFileInfoPool && fileCount < 256); event(POP);
    files[fileCount].slot = fileCount;
    return &files[fileCount++];
}
static void AtomicSList_Push(void** p, DVDFileInfo* file) {
    assert(p == gDvdFileInfoPool && file >= files && file < files + fileCount);
    pushes++; event(PUSH);
}
static int DVDOpen(char* path, DVDFileInfo* file) {
    assert(file >= files && file < files + fileCount);
    if (phase == 1) {
        char expected[64]; snprintf(expected, sizeof(expected), "%s.romlist.zlb", sMapFileNameTable[expectedMap]);
        assert(strcmp(path, expected) == 0);
    }
    file->length = 128; opens++; event(OPEN); return openOK;
}
static void* mmAlloc(int size, u32 tag, int flags) {
    assert(size >= 0 && size <= 256 && tag == 0x7d7d7d7d && flags == 0 && allocationCount < 256);
    void* pointer = malloc(size + 16);
    assert(pointer && (uintptr_t)pointer > UINT32_MAX);
    memset(pointer, 0xa7, size + 16);
    allocations[allocationCount] = pointer; allocationSizes[allocationCount++] = size;
    event(ALLOC); return pointer;
}
static void mm_free(void* pointer) {
    int found = -1;
    for (int i = 0; i < allocationCount; i++) if (allocations[i] == pointer) found = i;
    assert(found >= 0 && !allocationFreed[found]);
    for (int i = 0; i < 16; i++) assert(((u8*)pointer)[allocationSizes[found] + i] == 0xa7);
    allocationFreed[found] = 1; frees++; event(FREE); free(pointer);
}
static void DVDRead(DVDFileInfo* file, void* destination, int size, int offset) {
    assert(file && size == 128 && offset == 0 && (uintptr_t)destination > UINT32_MAX);
    memset(destination, 0x6b, size); reads++; event(READ);
}
static void DVDReadAsyncPrio(DVDFileInfo* file, void* destination, int size, int offset,
                             void (*callback)(s32, DVDFileInfo*), int priority) {
    assert(priority == 2 && callbackCount < 256);
    DVDRead(file, destination, size, offset); asyncs++; event(ASYNC);
    callbacks[callbackCount] = callback; callbackFiles[callbackCount++] = file;
}
static void DVDClose(DVDFileInfo* file) { assert(file); closes++; event(CLOSE); }
static void zlbDecompress(u8* source, int size, u8* destination, int* sizeOut) {
    struct PackHeader* header = (struct PackHeader*)(maps + expectedOffset);
    assert(source == (u8*)gMapRomListBuffers[expectedMap] + 16 && size == 37);
    assert(sizeOut == &header->decompressedSize && *sizeOut == 91);
    assert(destination == output || destination == NULL);
    if (destination) memset(destination, 0x55, 53);
    *sizeOut = 53; inflates++; event(INFLATE);
}
static void DCStoreRange(void* destination, int size) {
    assert((destination == output || destination == NULL) && size == 53 && inflates == 1);
    stores++; event(STORE);
}
static int OSDisableInterrupts(void) { return 23; }
static void OSRestoreInterrupts(int saved) { assert(saved == 23); }
static void mmSetFreeDelay(int delay) { assert(delay == 0 || delay == 2); }
static int mergeTableFiles(void* table, int a, int b, int size) {
    assert(table && a != b && size > 0); merges++; return 1;
}
static int mmSetForceHeap3Only(int value) { assert(value == (heapCalls++ ? 17 : 0)); return 17; }
static void* mapLoadDataFile(int map, int id) {
    assert(map == 5 && (id == MLDF_FILEID_TEX0_BIN_A || id == MLDF_FILEID_TEX0_TAB_A));
    mapLoads++; return NULL;
}
static void padUpdate(void) { waits++; }
static void checkReset(void) {}
static void waitNextFrame(void) { frames++; }
static void loadDataFiles(int ignored) {
    assert(ignored == 0); if (++waitLoads == 2) gAssetLoadInFlightFlags = 0;
}
static void dvdCheckError(void) { gDvdErrorPauseActive = 1; }
static void mmFreeTick(int ignored) { assert(ignored == 0); }
static void gameTextRun(void) {}
static void GXFlush_(int a, int b) { assert(a == 1 && b == 0); }
static void cleanup(void) {
    for (int i = 0; i < allocationCount; i++) if (!allocationFreed[i]) free(allocations[i]);
}
static void reset(void) {
    memset(&arena, 0, sizeof(arena)); memset(&position, 0, sizeof(position));
    memset(maps, 0x93, sizeof(maps)); memset(output, 0xcc, sizeof(output));
    memset(allocationFreed, 0, sizeof(allocationFreed));
    for (int i = 0; i < 117; i++) { snprintf(names[i], sizeof(names[i]), "map%d", i); sMapFileNameTable[i] = names[i]; }
    for (int i = 0; i < 88; i++) { sResourceFileNameTable[i] = names[i]; arena.tables.owners[i] = -1; arena.tables.ids[i] = -1; }
    for (int i = 0; i < 75; i++) sMapFileNameIndexRemapTable[i] = -1;
    fileCount = allocationCount = callbackCount = 0;
    opens = reads = closes = pushes = asyncs = inflates = stores = frees = merges = mapLoads = 0;
    heapCalls = waitLoads = waits = frames = createCalls = traceCount = 0;
    gLoadFilesInitDone = gDvdErrorPauseActive = 0;
    gAssetLoadInFlightFlags = gAssetLoadCompletedFlags = gPendingDvdReadCount = 0;
    gRomListLoadInFlight = 0;
    gObjLevelLockSlots[0] = gObjLevelLockSlots[1] = -2;
    openOK = 1; phase = 0;
}
"""
CASES = r"""
static void checkLoad(int map, int resident, int hasDestination, int magic, int canOpen) {
    reset(); phase = 1; expectedMap = map; expectedOffset = (map % 8) * 16; openOK = canOpen;
    gResourceFileBuffers[0x1d] = maps;
    struct PackHeader* header = (struct PackHeader*)(maps + expectedOffset);
    *header = (struct PackHeader){magic == 0 ? 0xfacefeedu : magic == 1 ? 0xe0e0e0e0u : 0, 91, 123, 37};
    if (resident) gMapRomListBuffers[map] = mmAlloc(128, 0x7d7d7d7d, 0);
    traceCount = 0;
    piRomLoadSection(expectedOffset, map, hasDestination ? output : NULL);
    int opened = !resident;
    int acquired = opened && canOpen;
    int asynchronous = acquired && !hasDestination;
    int unpacked = (resident || (acquired && hasDestination)) && magic == 0;
    assert(opens == opened && reads == acquired && asyncs == asynchronous);
    assert(closes == (acquired && hasDestination) && pushes == closes);
    assert(inflates == unpacked && stores == unpacked);
    assert(gRomListLoadInFlight == (u32)asynchronous);
    assert((gMapRomListBuffers[map] != NULL) == (resident || acquired));
    assert(header->decompressedSize == (unpacked ? 53 : 91));
    for (int i = 0; i < 256; i++) assert(output[i] == (unpacked && hasDestination && i < 53 ? 0x55 : 0xcc));
    int expected[16], n = 0;
    if (opened) { expected[n++] = POP; expected[n++] = OPEN; }
    if (acquired) {
        expected[n++] = ALLOC; expected[n++] = READ;
        if (asynchronous) expected[n++] = ASYNC;
        else { expected[n++] = CLOSE; expected[n++] = PUSH; }
    }
    if (unpacked) { expected[n++] = INFLATE; expected[n++] = STORE; }
    assert(traceCount == n && memcmp(trace, expected, n * sizeof(int)) == 0);
    if (asynchronous) {
        callbacks[0](map & 1 ? -1 : 0, callbackFiles[0]);
        assert(gRomListLoadInFlight == 0 && closes == 1 && pushes == 1 && frees == 0);
        assert(gMapRomListBuffers[map] == allocations[0]);
    }
    cleanup();
}
static void checkStartup(int residentFiles) {
    reset();
    for (int i = 0; i < 120; i++) arena.tables.romList[i] = marker;
    for (int i = 0; i < 88; i++) {
        arena.tables.ptrs[i] = residentFiles ? marker : NULL;
        arena.tables.ids[i] = 77; arena.tables.owners[i] = 77; arena.tables.loadedFlags[i] = 77;
    }
    lbl_803DCC98 = 77;
    assert(initLoadFiles() == 0 && gLoadFilesInitDone == 1 && createCalls == 1);
    int preloads = 0;
    for (int i = 0; i < 117; i++) {
        int preload = i == 5 || i == 67 || i == 73 || i >= 80;
        assert((arena.tables.romList[i] != NULL) == preload);
        if (preload) { assert(arena.tables.romList[i] != marker); preloads++; }
    }
    for (int i = 117; i < 120; i++) assert(arena.tables.romList[i] == marker);
    assert(preloads == 40 && lbl_803DCC98 == 0 && gRomListLoadInFlight == 1);
    const int rootFiles[] = {11,12,15,16,19,20,21,22,23,25,28,29,30,31,34,39,40,41,44,45,46,49,50,51,52,53,55,56,57,58,59,60,61,62,63,64,65,79,80,81,82,87};
    int rootCount = sizeof(rootFiles)/sizeof(rootFiles[0]);
    for (int i = 0; i < 88; i++) {
        int root = 0;
        for (int j = 0; j < rootCount; j++) if (i == rootFiles[j]) root = 1;
        assert((arena.tables.ptrs[i] != NULL) == root);
        if (root) assert((arena.tables.ptrs[i] == marker) == residentFiles);
        assert(arena.tables.owners[i] == -1 && arena.tables.ids[i] == -1 && arena.tables.loadedFlags[i] == 0);
    }
    assert(callbackCount == 40 + (residentFiles ? 0 : rootCount));
    assert(gPendingDvdReadCount == (residentFiles ? 0 : rootCount));
    int allocationsBefore = allocationCount;
    if (residentFiles) { assert(mapLoads == 2); heapCalls = mapLoads = 0; }
    assert(initLoadFiles() == 0 && allocationCount == allocationsBefore && createCalls == 1);
    for (int i = 0; i < callbackCount; i++) callbacks[i](0, callbackFiles[i]);
    assert(gPendingDvdReadCount == 0 && gRomListLoadInFlight == 0);
    gAssetLoadInFlightFlags = gAssetLoadCompletedFlags = 0x500;
    assert(initLoadFiles() == 1 && merges == 5);
    assert(gAssetLoadInFlightFlags == 0 && gAssetLoadCompletedFlags == 0);
    cleanup();
}
static const int slots[] = {43,42,47,48,70,69,73,74,36,35,78,77,33,32,76,75,37,38,71,72,27,26,84,83,13,14,85,86};
static const int masks[] = {1,2,8,4,1,2,8,4,32,16,32,16,128,64,128,64,256,512,256,512,4096,8192,4096,8192,1024,2048,1024,2048};
static void checkUnload(int which, int mode, int owner, int locked, int present, int remap) {
    reset();
    int slot = slots[which], map = 6;
    int flags = mode == 0 ? masks[which] : mode == 1 ? 0x10000000 : mode == 2 ? 0x20000000 : (int)0x80000000u;
    if (locked) gObjLevelLockSlots[locked - 1] = owner;
    position.mapDataFileId = owner;
    arena.tables.ids[slot] = map;
    arena.tables.owners[slot] = owner;
    arena.tables.sizes[slot] = 128;
    if (present) arena.tables.ptrs[slot] = mmAlloc(128, 0x7d7d7d7d, 0);
    void* resource = arena.tables.ptrs[slot];
    if (remap < 75) sMapFileNameIndexRemapTable[remap] = owner;
    arena.tables.romList[remap] = mmAlloc(128, 0x7d7d7d7d, 0);
    void* romlist = arena.tables.romList[remap];
    assert(mapUnload(map, flags) == 1);
    int selected = mode == 3 || (mode == 1 ? owner != map : owner == map);
    int released = present && selected && !locked;
    int romReleased = released && (slot == 38 || slot == 72) && remap != 5 && remap != 67 && remap != 73;
    assert(arena.tables.ptrs[slot] == (released ? NULL : resource));
    assert(arena.tables.owners[slot] == (released ? -1 : owner));
    assert(arena.tables.sizes[slot] == (released ? 0 : 128));
    assert(arena.tables.romList[remap] == (romReleased ? NULL : romlist));
    assert(frees == released + romReleased);
    assert(arena.tables.ids[slot] == (mode == 0 || mode == 2 ? -1 : map));
    assert(position.mapDataFileId == (mode != 0 && selected && !locked ? -1 : owner));
    for (int i = 0; i < 88; i++) if (i != slot) assert(arena.tables.ptrs[i] == NULL && arena.tables.owners[i] == -1);
    for (int i = 0; i < 120; i++) if (i != remap) assert(arena.tables.romList[i] == NULL);
    cleanup();
}
int main(void) {
    for (int map = 0; map < 117; map++) for (int resident = 0; resident < 2; resident++)
        for (int dest = 0; dest < 2; dest++) for (int magic = 0; magic < 3; magic++)
            for (int success = 0; success < 2; success++) checkLoad(map, resident, dest, magic, success);
    checkStartup(0); checkStartup(1);
    for (int slot = 0; slot < 28; slot++) for (int mode = 0; mode < 4; mode++)
        for (int owner = 6; owner < 8; owner++) for (int lock = 0; lock < 3; lock++)
            for (int present = 0; present < 2; present++) checkUnload(slot, mode, owner, lock, present, 10);
    const int remaps[] = {5, 67, 73, 74, 75};
    for (int slot = 17; slot <= 19; slot += 2) for (int i = 0; i < 5; i++) checkUnload(slot, 3, 6, 0, 1, remaps[i]);
    reset(); gAssetLoadInFlightFlags = 2;
    assert(mapUnload(6, 0) == 1 && waits == 2 && frames == 1 && waitLoads == 2);
    cleanup();
    puts("2808 romlist loads, 2 startups, 1354 unloads and 1 wait-loop case checked");
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    for name in ('MldfTables', 'MldfIterators', 'PackHeader'):
        parts.append(re.search(rf'struct {name} \{{.*?\n\}};', source, re.S)[0])
    start = source.index('typedef u8 MldfArenaBlock')
    parts.append(source[start:source.index('\n};', start) + 3])
    state = (ROOT / 'include/main/dll/savegame_state.h').read_text()
    parts.append(re.search(r'typedef struct SaveGameCharacterPosition \{.*?\} SaveGameCharacterPosition;', state, re.S)[0])
    for name in ('gMapRomListBuffers', 'gResourceFileBuffers'):
        parts.append('extern ' + re.search(rf'^\w+\*? {name}\[[^;]+;', source, re.M)[0])
        parts.append(f'_Static_assert(_Generic(&{name}[0], void**: 1, default: 0), "registry pointer type");')
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    for name in ('MAPID_RT', 'MAPPTR_RT', 'MAPOWNER_RT', 'DVD_FI_LENGTH'):
        parts.append(re.search(rf'^#define {name}\b(?:[^\n]*\\\n)*[^\n]*', source, re.M)[0])
    parts.append(re.search(r'^char sRomlistZlbPathFormat[^;]+;', source, re.M)[0])
    parts.append(SERVICES)
    for name in ('romListReadCb', 'initLoadFileReadCb', 'piRomLoadSection', 'initLoadFiles', 'mapUnload'):
        parts.append(function(source, name))
    return '\n'.join(parts + [CASES])


class RomlistBufferOwnershipTests(unittest.TestCase):
    def test_native_buffer_lifetime(self):
        with tempfile.TemporaryDirectory(prefix='romlist-ownership-') as directory:
            source = Path(directory) / 'romlist.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / 'romlist'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-Wno-deprecated-declarations', '-fsanitize=address,undefined', str(source), '-o', str(executable)],
                                   check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
