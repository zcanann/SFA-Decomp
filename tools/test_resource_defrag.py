#!/usr/bin/env python3
"""Exercise the complete resource defragmenter with scripted heap allocations.

The neighbouring-global address view is one host allocation in this fixture.
Heap placement, texture restructuring and interrupt services are spies; copies
use real memory, including sparse windows on opposite sides of a 4 GiB boundary.
This tests relocation policy and ownership, not the allocator implementation.
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
#include <sys/mman.h>
typedef uint8_t u8;
typedef int16_t s16;
typedef uint32_t u32;
typedef struct DVDFileInfo { int unused; } DVDFileInfo;
"""
SERVICES = r"""
static union { struct MldfTables tables; MldfArenaBlock bytes; } arena, expected;
#define gResourceFileTable arena.bytes
enum { BLOCK_COUNT = 24, BLOCK_BYTES = 0x40000 };
static _Alignas(32) u8 storage[BLOCK_COUNT][BLOCK_BYTES];
static struct { u8* pointer; int region, heapBytes, live; } blocks[BLOCK_COUNT];
static int plan[32], planLength, allocations, copies, frees, cases;
static int freeLog[32], copyFrom[32], copyTo[32], allocationForcing[32];
static int freeDelay, delayWrites, forcedHeaps, forceLog[4], forceWrites;
static int textureState, textureLog[4], textureWrites, textureRestructures;
static int interruptDisables, interruptRestores, heapSizeQueries;
static int fileBytes;
static int gAssetLoadInFlightFlags;
static s16 gDefragDelayFrames;
static int blockId(const void* pointer) {
    for (int i = 0; i < BLOCK_COUNT; i++) if (pointer == blocks[i].pointer) return i;
    abort();
}
static int OSDisableInterrupts(void) { interruptDisables++; return 19; }
static void OSRestoreInterrupts(int saved) { assert(saved == 19); interruptRestores++; }
static void mmSetTextureAllocationState(int value) {
    assert(textureWrites < 4); textureLog[textureWrites++] = value; textureState = value;
}
static void texRestructRefs(int mode) { assert(mode == 0); textureRestructures++; }
static int mmSetForceHeaps1and2Only(int value) {
    assert(forceWrites < 4); forceLog[forceWrites++] = value;
    int old = forcedHeaps; forcedHeaps = value; return old;
}
static int mmSetFreeDelay(int value) {
    int old = freeDelay;
    assert(value == (delayWrites % 2 == 0 ? 0 : 7));
    freeDelay = value; delayWrites++; return old;
}
static int mmGetRegionForPtr(void* pointer) {
    int id = blockId(pointer); assert(blocks[id].live); return blocks[id].region;
}
static int getHeapItemSize(void* pointer) {
    int id = blockId(pointer); assert(blocks[id].live);
    heapSizeQueries++; return blocks[id].heapBytes;
}
static void* mmAlloc(int bytes, int tag, int flags) {
    assert(textureState == 2 && bytes == fileBytes + 32 && tag == 0x7d7d7d7d && flags == 0);
    assert(freeDelay == 7 && allocations < 32);
    allocationForcing[allocations] = forcedHeaps;
    int id = allocations < planLength ? plan[allocations] : -1;
    allocations++;
    if (id < 0) return NULL;
    assert(!blocks[id].live && bytes + 32 < BLOCK_BYTES);
    blocks[id].live = 1;
    memset(blocks[id].pointer, 0xa7, bytes + 32);
    return blocks[id].pointer;
}
static void mm_free(void* pointer) {
    int id = blockId(pointer); assert(blocks[id].live && freeDelay == 0 && frees < 32);
    blocks[id].live = 0; freeLog[frees++] = id;
}
static void defragCopy(void* destination, const void* source, size_t bytes) {
    int a = blockId(source), b = blockId(destination);
    assert(blocks[a].live && blocks[b].live && a != b && bytes == (size_t)fileBytes && copies < 32);
    copyFrom[copies] = a; copyTo[copies++] = b;
    memcpy(destination, source, bytes);
}
static void reset(int bytes) {
    memset(&arena, 0xab, sizeof(arena));
    for (int i = 0; i < 88; i++) {
        arena.tables.ptrs[i] = NULL;
        arena.tables.owners[i] = -1;
        arena.tables.sizes[i] = bytes;
    }
    for (int i = 0; i < BLOCK_COUNT; i++) {
        blocks[i].pointer = storage[i]; blocks[i].region = 0;
        blocks[i].heapBytes = bytes + 32; blocks[i].live = 0;
    }
    assert((uintptr_t)&arena > UINT32_MAX && (uintptr_t)storage > UINT32_MAX);
    allocations = copies = frees = planLength = delayWrites = forceWrites = textureWrites = 0;
    textureRestructures = interruptDisables = interruptRestores = heapSizeQueries = 0;
    freeDelay = 7; forcedHeaps = 37; textureState = 39;
    gAssetLoadInFlightFlags = 0; gDefragDelayFrames = 6; fileBytes = bytes;
}
static void resident(int slot, int block, int region) {
    blocks[block].live = 1; blocks[block].region = region;
    arena.tables.ptrs[slot] = blocks[block].pointer; arena.tables.owners[slot] = 23;
    for (int i = 0; i < fileBytes; i++) blocks[block].pointer[i] = (u8)(i * 13 + 7);
}
static void snapshot(int swept) {
    memcpy(&expected, &arena, sizeof(expected));
    if (swept) memset(expected.tables.workspace.loadedFlags, 0, 88);
}
static void check(int mode, int wantedAllocations, int wantedCopies, int wantedFrees, int early) {
    assert(allocations == wantedAllocations && copies == wantedCopies && frees == wantedFrees);
    assert(delayWrites == 2 * frees && freeDelay == 7);
    assert(interruptDisables == 1 && interruptRestores == 1);
    assert(memcmp(&arena, &expected, sizeof(arena)) == 0);
    assert(textureWrites == (early ? 1 : 2) && textureLog[0] == 2);
    assert(textureState == (early ? 2 : 0));
    if (mode && !early) {
        assert(forceWrites == 2 && forceLog[0] == 1 && forceLog[1] == -1 && forcedHeaps == -1);
    } else assert(forceWrites == 0 && forcedHeaps == 37);
    for (int i = 0; i < copies; i++) {
        u8* p = blocks[copyTo[i]].pointer;
        for (int j = 0; j < fileBytes; j++) assert(p[j] == (u8)(j * 13 + 7));
        for (int j = fileBytes; j < fileBytes + 64; j++) assert(p[j] == 0xa7);
    }
    cases++;
}
#define memcpy defragCopy
"""
CASES = r"""
#undef memcpy
static int movableSlot(int slot) {
    static const int slots[] = {13, 27, 35, 37, 43, 48, 70, 71, 74, 77, 84, 85};
    for (int i = 0; i < 12; i++) if (slot == slots[i]) return 1;
    return 0;
}
static void checkEligibility(void) {
    /* Every physical slot, all recognized heaps plus an unknown heap, both
       ownership/presence states, and all three mode behaviors. Allocation fails. */
    for (int mode = 0; mode < 3; mode++) for (int slot = 0; slot < 88; slot++)
        for (int region = -1; region <= 3; region++) for (int owned = 0; owned < 2; owned++)
            for (int present = 0; present < 2; present++) {
                reset(64);
                if (present) resident(slot, 0, region);
                arena.tables.owners[slot] = owned ? 23 : -1;
                snapshot(1);
                int attempts = movableSlot(slot) && region == 0 && owned && present;
                if (attempts && mode && !(mode == 2 && (slot == 35 || slot == 77))) attempts++;
                defragMemory(mode); check(mode, attempts, 0, 0, 0);
                assert(gDefragDelayFrames == 6 && heapSizeQueries == 0);
            }
}
static void checkEarlyReturns(void) {
    for (int mode = 0; mode < 3; mode++) for (int bit = 0; bit < 32; bit++) {
        reset(64); resident(13, 0, 0); gDefragDelayFrames = 0;
        gAssetLoadInFlightFlags = (u32)1 << bit; snapshot(0);
        defragMemory(mode); check(mode, 0, 0, 0, 1);
        assert(gDefragDelayFrames == 0 && textureRestructures == 0);
    }
    reset(64); resident(13, 0, 0); gDefragDelayFrames = 0; snapshot(0);
    defragMemory(0); check(0, 0, 0, 0, 1);
    assert(gDefragDelayFrames == 6 && textureRestructures == 1);
}
static void checkDirection(int bytes, int oldBlock, int newBlock, int accepted) {
    reset(bytes); resident(13, oldBlock, 0); snapshot(1);
    plan[0] = newBlock; planLength = 1;
    if (accepted) expected.tables.ptrs[13] = blocks[newBlock].pointer;
    defragMemory(0); check(0, accepted ? 2 : 1, accepted, 1, 0);
    assert(freeLog[0] == (accepted ? oldBlock : newBlock));
    assert(blocks[oldBlock].live == !accepted && blocks[newBlock].live == accepted);
}
static void checkEviction(void) {
    for (int mode = 1; mode <= 2; mode++) for (int region = 1; region <= 2; region++) {
        reset(64); resident(13, 12, 0); blocks[4].region = region;
        plan[0] = 4; planLength = 1; snapshot(1); expected.tables.ptrs[13] = blocks[4].pointer;
        defragMemory(mode); check(mode, 1, 1, 1, 0);
        assert(freeLog[0] == 12 && blocks[4].live && !blocks[12].live);
        assert(allocationForcing[0] == 1);
    }
    /* TEX0 is excluded only from the eviction phase of mode 2. It still compacts. */
    for (int slot = 35; slot <= 77; slot += 42) {
        reset(64); resident(slot, 4, 0); plan[0] = 12; planLength = 1;
        snapshot(1); expected.tables.ptrs[slot] = blocks[12].pointer;
        defragMemory(2); check(2, 2, 1, 1, 0); assert(freeLog[0] == 4);
        assert(allocationForcing[0] == -1 && allocationForcing[1] == -1);
    }
}
static void checkCompactionFallback(void) {
    /* The heap-0 compaction branch checks address direction, but does not check
       the replacement's heap. Preserve a move to another heap if its address wins. */
    for (int region = 1; region <= 3; region++) {
        reset(64); resident(13, 4, 0); blocks[12].region = region;
        plan[0] = 12; planLength = 1; snapshot(1); expected.tables.ptrs[13] = blocks[12].pointer;
        defragMemory(0); check(0, 1, 1, 1, 0);
        assert(freeLog[0] == 4 && blocks[12].live && !blocks[4].live);
    }
}
static void checkPromotion(int mode, int region, int heapBytes, int resultRegion, int resultBlock) {
    reset(64); resident(13, 0, 0); resident(27, 12, region);
    blocks[12].heapBytes = heapBytes;
    if (resultBlock >= 0) blocks[resultBlock].region = resultRegion;
    if (mode == 2) plan[planLength++] = -1; /* failed eviction of the trigger */
    plan[planLength++] = 1; /* frees space in heap 0 on pass zero */
    plan[planLength++] = -1; /* trigger has no better location on pass one */
    int attempt = mode != 2 && (region == 1 || region == 2) && heapBytes >= 0x3000;
    int accepted = attempt && resultBlock >= 0 && resultRegion == 0;
    if (attempt) plan[planLength++] = resultBlock;
    snapshot(1); expected.tables.ptrs[13] = blocks[1].pointer;
    if (accepted) expected.tables.ptrs[27] = blocks[resultBlock].pointer;
    int rejected = attempt && resultBlock >= 0 && !accepted;
    defragMemory(mode); check(mode, planLength + (accepted ? 2 : 0), 1 + accepted, 1 + accepted + rejected, 0);
    assert(freeLog[0] == 0 && copyFrom[0] == 0 && copyTo[0] == 1);
    if (accepted) assert(freeLog[1] == 12 && copyFrom[1] == 12 && copyTo[1] == resultBlock);
    if (rejected) assert(freeLog[1] == resultBlock);
    assert(heapSizeQueries == (mode != 2 && (region == 1 || region == 2) ? 1 : 0));
}
static void checkPassLimit(void) {
    reset(64); resident(13, 0, 0);
    for (int i = 0; i < 11; i++) plan[planLength++] = i + 1;
    snapshot(1); expected.tables.ptrs[13] = blocks[10].pointer;
    defragMemory(0); check(0, 10, 10, 10, 0);
    for (int i = 0; i < 10; i++) assert(freeLog[i] == i && copyFrom[i] == i && copyTo[i] == i + 1);
    assert(blocks[10].live && !blocks[11].live);
}
static void checkAllArchives(void) {
    reset(64); int block = 0;
    for (int slot = 0; slot < 88; slot++) if (movableSlot(slot)) {
        resident(slot, block, 0); plan[planLength++] = block + 1; block += 2;
    }
    snapshot(1); block = 1;
    for (int slot = 0; slot < 88; slot++) if (movableSlot(slot)) {
        expected.tables.ptrs[slot] = blocks[block].pointer; block += 2;
    }
    defragMemory(0); check(0, 24, 12, 12, 0);
    for (int i = 0; i < 12; i++) assert(freeLog[i] == 2 * i && copyTo[i] == 2 * i + 1);
}
static void checkCrossBoundary(void) {
    size_t span = (size_t)UINT64_C(0x200000000);
    u8* mapping = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(mapping != MAP_FAILED);
    uintptr_t boundary = ((uintptr_t)mapping + UINT64_C(0xffffffff)) & ~UINT64_C(0xffffffff);
    if (boundary - (uintptr_t)mapping < 0x100000) boundary += UINT64_C(0x100000000);
    u8* low = (u8*)(boundary - 0x100000), *high = (u8*)(boundary + 0x100000);
    assert(low >= mapping && high + BLOCK_BYTES <= mapping + span);
    assert(mprotect(low, BLOCK_BYTES, PROT_READ | PROT_WRITE) == 0);
    assert(mprotect(high, BLOCK_BYTES, PROT_READ | PROT_WRITE) == 0);
    assert((uintptr_t)low < (uintptr_t)high && (u32)(uintptr_t)low > (u32)(uintptr_t)high);
    for (int large = 0; large < 2; large++) for (int up = 0; up < 2; up++) {
        reset(large ? 0x33450 : 64);
        blocks[0].pointer = up ? low : high; blocks[1].pointer = up ? high : low;
        resident(13, 0, 0); snapshot(1); plan[0] = 1; planLength = 1;
        int accepted = large != up;
        if (accepted) expected.tables.ptrs[13] = blocks[1].pointer;
        defragMemory(0); check(0, accepted ? 2 : 1, accepted, 1, 0);
        assert(freeLog[0] == (accepted ? 0 : 1));
    }
    assert(munmap(mapping, span) == 0);
}
int main(void) {
    checkEligibility(); checkEarlyReturns();
    const int sizes[] = {0, 1, 0x2fff, 0x3000, 0x3342f, 0x33430, 0x33431, 0x3344f, 0x33450, 0x33451};
    for (int i = 0; i < (int)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        checkDirection(sizes[i], 12, 4, sizes[i] >= 0x33450);
        checkDirection(sizes[i], 12, 20, sizes[i] < 0x33450);
    }
    checkEviction(); checkCompactionFallback();
    for (int mode = 0; mode <= 2; mode += 2) for (int region = 1; region <= 3; region++)
        for (int size = 0x2fff; size <= 0x3001; size++) for (int destRegion = 0; destRegion <= 2; destRegion++) {
            checkPromotion(mode, region, size, destRegion, 4);
            checkPromotion(mode, region, size, destRegion, 20);
        }
    checkPromotion(0, 1, 0x3000, 0, -1);
    checkPassLimit(); checkAllArchives(); checkCrossBoundary();
    printf("%d complete resource defrag cases checked\n", cases);
    return 0;
}
"""


def harness():
    source = (ROOT / 'src/main/pi_dolphin.c').read_text()
    parts = [PRELUDE]
    for name in ('ResourceTableWorkspace', 'MldfTables'):
        parts.append(re.search(rf'struct {name} \{{.*?\n\}};', source, re.S)[0])
    parts.append(re.search(r'typedef u8 MldfArenaBlock[^;]*;', source)[0])
    ids = (ROOT / 'include/main/mldf_fileid.h').read_text()
    parts.append(re.search(r'enum MldfFileId \{.*?\};', ids, re.S)[0])
    mm = (ROOT / 'include/main/mm.h').read_text()
    parts.append(re.search(r'^#define MM_REGION0_LARGE_ALLOCATION_THRESHOLD[^\n]*', mm, re.M)[0])
    parts.extend([SERVICES, function(source, 'loadedFileFlags'), function(source, 'defragMemory'), CASES])
    return '\n'.join(parts)


class ResourceDefragTests(unittest.TestCase):
    def test_native_relocation_policy(self):
        with tempfile.TemporaryDirectory(prefix='resource-defrag-') as directory:
            source = Path(directory) / 'defrag.c'
            source.write_text(harness())
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / 'defrag'
                    subprocess.run(['clang', '-std=c11', optimization, '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', str(source), '-o', str(executable)],
                                   check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    unittest.main()
