#!/usr/bin/env python3
"""Run the production allocator/store path with native 64-bit heap addresses.

Only SDK/game services are stubbed. Target layout assertions remain checked by
the MWCC build; the host fixture uses the same records with native pointers.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
#define STATIC_ASSERT(...)
static void OSReport(const char*, ...);
static u32 OSGetTick(void) { return 123; }
static int saveTicks, waits, flushes, failures;
static int gModelsArchiveLoadCount;
static void SaveGame_updateTransientMapBits(void) { saveTicks++; }
static void waitNextFrame(void) { waits++; }
static void GXFlush_(int a, int b) { assert(a == 1 && b == 0); flushes++; }
static void reportAllocFail(int a, int b, int c, int d, int e, int f,
                           int g, int h, int i, int j, int k) { failures++; }
'''

CHECKS = r'''
/* One arena keeps region comparisons within the same backing allocation. */
enum { HEAP_BYTES = 0x80000, SLOTS = 128 };
static _Alignas(32) u8 arena[HEAP_BYTES * 4];
static const char* lastReport;
static const char* lastName;
static int cases;
static void OSReport(const char* message, ...) {
    lastReport = message;
    if (message == sMmAllocNoFreeSlotsError || message == sMmAllocNoSuitableBlockError) {
        va_list args;
        va_start(args, message);
        lastName = va_arg(args, const char*);
        va_end(args);
    }
    /* Retail's store-space error supplies no arguments for its two %d slots. */
}

static void reset(void) {
    memset(arena, 0xa5, sizeof(arena));
    memset(gMmStoreArray, 0, sizeof(gMmStoreArray));
    memset(gMmRegionTable, 0, sizeof(gMmRegionTable));
    memset(gMmDeferredFreeStack, 0, sizeof(gMmDeferredFreeStack));
    gMmRegionCount = gMmDeferredFreeCount = gMmFreeDelay = gMmNextStoreHandle = 0;
    gMmForceHeaps1and2Only = -1;
    gMmForceHeap3Only = 0;
    gMmRegion0SpawnEnabled = 1;
    gMmNextAllocId = gMmTickCount = gMmOpCount = gMmStatsPrintCounter = 0;
    saveTicks = waits = flushes = failures = 0;
    lastReport = lastName = NULL;
    assert((uintptr_t)arena > UINT32_MAX);
    for (int i = 0; i < 4; i++) {
        u8* start = arena + i * HEAP_BYTES;
        assert(mmInitRegion(start, HEAP_BYTES, SLOTS) == start);
        HeapItem* item = (HeapItem*)start;
        assert(item->loc == start + SLOTS * sizeof(HeapItem));
        assert((uintptr_t)item->loc % 32 == 0);
    }
}

static int used(void) {
    int total = 0;
    for (int i = 0; i < 4; i++) total += gMmRegionTable[i].usedBytes;
    return total;
}

static void checkHeap(void) {
    for (int region = 0; region < 4; region++) {
        MmRegion* heap = &gMmRegionTable[region];
        HeapItem* slots = (HeapItem*)heap->start;
        u8* cursor = heap->start + SLOTS * sizeof(HeapItem);
        int previous = -1, count = 0, allocated = 0;
        for (int index = 0; index != -1; index = slots[index].next) {
            assert(index >= 0 && index < SLOTS && ++count <= SLOTS);
            HeapItem* item = &slots[index];
            assert(item->prev == previous && item->loc == cursor);
            assert(item->size > 0 && item->size % 32 == 0);
            if (item->type) allocated += item->size;
            cursor += item->size;
            previous = index;
        }
        assert(cursor == heap->start + HEAP_BYTES);
        assert(count == heap->slotsUsed && allocated == heap->usedBytes);
    }
}

static void allocationRouting(void) {
    const int sizes[] = {1, 31, 32, 33, 0x3ff, 0x400, 0x2fff, 0x3000, 0x33450};
    for (int forcing = 0; forcing < 3; forcing++) {
        for (int n = 0; n < (int)(sizeof(sizes) / sizeof(*sizes)); n++) {
            reset();
            int size = sizes[n], rounded = (size + 31) & ~31;
            gMmForceHeaps1and2Only = forcing == 1 ? 1 : -1;
            gMmForceHeap3Only = forcing == 2;
            int region = forcing == 1 ? 1 : forcing == 2 ? 3 : size >= 0x3000 ? 0 : size >= 0x400 ? 1 : 2;
            u8* start = gMmRegionTable[region].start;
            void* expected = start + (region == 0 && rounded < 0x33450 ? HEAP_BYTES - rounded : SLOTS * sizeof(HeapItem));
            void* pointer = mmAlloc(size, 14, "native allocation");
            assert(pointer == expected && getHeapItemSize(pointer) == rounded);
            memset(pointer, 0x3c, size);
            assert(used() == rounded);
            checkHeap();
            mm_free(pointer);
            assert(used() == 0 && gMmLastFreeTick == 123);
            checkHeap();
            cases++;
        }
    }
    reset();
    assert(mmAlloc(0, 0, NULL) == NULL && used() == 0);
    /* Exhaust real heaps to exercise all normal fallback paths. */
    const int probes[] = {32, 0x400, 0x3000};
    for (int n = 0; n < 3; n++) {
        reset();
        int first = n == 0 ? 2 : n == 1 ? 1 : 0;
        int second = n == 0 ? 1 : n == 1 ? 2 : 1;
        int third = n < 2 ? 0 : -1;
        HeapItem* head = (HeapItem*)gMmRegionTable[first].start;
        assert(mmAllocFromRegion(first, head->size, 0, NULL));
        void* p = mmAlloc(probes[n], 0, "fallback");
        assert(regionForPtr(p) == second);
        mmFree(p);
        head = (HeapItem*)gMmRegionTable[second].start;
        assert(mmAllocFromRegion(second, head->size, 0, NULL));
        p = mmAlloc(probes[n], 0, "fallback");
        assert(third < 0 ? p == NULL : regionForPtr(p) == third);
        checkHeap();
        cases++;
    }
    reset();
    gMmForceHeap3Only = 1;
    HeapItem* head = (HeapItem*)gMmRegionTable[3].start;
    assert(mmAllocFromRegion(3, head->size, 0, NULL));
    assert(!mmAlloc(32, 0, sMmStoreAllocationTag));
    assert(lastName == sMmStoreAllocationTag && failures == 1);
    gMmRegionTable[3].slotsUsed = SLOTS - 1;
    assert(!mmAlloc(32, 0, sMmStorePtrStoreAllocationTag));
    assert(lastName == sMmStorePtrStoreAllocationTag && lastReport == sMmAllocNoFreeSlotsError);
    cases++;
}

static void storeLifecycle(void) {
    const int sizes[] = {1, 31, 32, 33, 0x3ff, 0x400, 0x800, 0x3000, 0x4000};
    for (int n = 0; n < (int)(sizeof(sizes) / sizeof(*sizes)); n++) {
        reset();
        int size = sizes[n];
        assert(mmCreateMemoryStore(size) == 0); /* Retail starts its handle counter at zero. */
        MmStore* store = gMmStoreArray[0];
        assert(store && store->size == size && store->handle == 0 && gMmNextStoreHandle == 1);
        assert((uintptr_t)store->ptrStore > UINT32_MAX);
        u8* base = store->ptrStore;
        assert(mmAllocateFromFBMemoryStore(0, 0) == base);
        assert(mmAllocateFromFBMemoryStore(0, 1) == base);
        *base = 0x5a;
        assert(mmAllocateFromFBMemoryStore(0, -1) == base + 1); /* In-bounds rewind is unchecked. */
        assert(store->ptrCurrent == base);
        assert(mmAllocateFromFBMemoryStore(0, size) == base);
        memset(base, 0x3c, size);
        assert(mmAllocateFromFBMemoryStore(0, 0) == base + size);
        assert(mmAllocateFromFBMemoryStore(0, 1) == NULL && store->ptrCurrent == base + size);
        assert(lastReport == sMmAllocateFromFBMemoryStoreSpaceError);
        assert(mmAllocateFromFBMemoryStore(-1, 1) == NULL);
        assert(lastReport == sMmAllocateFromFBMemoryStoreMissingHandleError);
        /* Lookup and reset must traverse holes, including the final slot. */
        gMmStoreArray[0] = NULL;
        gMmStoreArray[31] = store;
        mmFreeTick(0);
        assert(saveTicks == 1 && store->ptrCurrent == base);
        assert(mmAllocateFromFBMemoryStore(0, size) == base);
        for (int i = 0; i < size; i++) assert(base[i] == 0x3c);
        int rounded = (size + 31) & ~31;
        for (int i = size; i < rounded; i++) assert(base[i] == 0xa5);
        checkHeap();
        cases++;
    }
    reset();
    for (int size = -1; size <= 0; size++) assert(mmCreateMemoryStore(size) == 0);
    assert(mmCreateMemoryStore(0x4001) == 0 && gMmNextStoreHandle == 0 && used() == 0);
    cases++;
}

static void storeFailures(void) {
    for (int delay = 0; delay <= 2; delay += 2) {
        reset();
        gMmForceHeap3Only = 1;
        HeapItem* first = (HeapItem*)gMmRegionTable[3].start;
        void* fill = mmAllocFromRegion(3, first->size, 0, NULL);
        assert(fill);
        assert(mmCreateMemoryStore(64) == 0 && gMmNextStoreHandle == 0);
        assert(lastReport == sMmCreateMemoryStoreObjectAllocError);
        mmFree(fill);
        /* Leave only one rounded header allocation; force backing-store failure. */
        fill = mmAllocFromRegion(3, first->size - 32, 0, NULL);
        int before = used();
        gMmFreeDelay = delay;
        assert(mmCreateMemoryStore(64) == 0 && gMmNextStoreHandle == 1);
        assert(lastReport == sMmCreateMemoryStorePtrStoreAllocError && !gMmStoreArray[0]);
        assert(used() == before + (delay ? 32 : 0));
        assert(gMmDeferredFreeCount == (delay ? 1 : 0));
        if (delay) {
            mmFreeTick(0);
            assert(used() == before + 32 && gMmDeferredFreeCount == 1);
            mmFreeTick(0);
            assert(used() == before && gMmDeferredFreeCount == 0);
        }
        mmFree(fill);
        assert(used() == 0);
        checkHeap();
        cases++;

        reset();
        gMmFreeDelay = delay;
        for (int i = 0; i < 32; i++) assert(mmCreateMemoryStore(64) == i);
        before = used();
        assert(mmCreateMemoryStore(64) == 0 && gMmNextStoreHandle == 33);
        assert(lastReport == sMmCreateMemoryStoreNoFreeSlotError);
        assert(used() == before + (delay ? 96 : 0));
        assert(gMmDeferredFreeCount == (delay ? 2 : 0));
        if (delay) {
            assert(getHeapItemSize(gMmDeferredFreeStack[0].ptr) == 64);
            assert(getHeapItemSize(gMmDeferredFreeStack[1].ptr) == 32);
            mmFreeTick(0);
            assert(gMmDeferredFreeCount == 2 && used() == before + 96);
            mmFreeTick(0);
            assert(gMmDeferredFreeCount == 0 && used() == before);
        }
        for (int i = 0; i < 32; i++) {
            assert(mmAllocateFromFBMemoryStore(i, 64) == gMmStoreArray[i]->ptrStore);
            memset(gMmStoreArray[i]->ptrStore, i, 64);
        }
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < 64; j++) assert(gMmStoreArray[i]->ptrStore[j] == i);
        }
        checkHeap();
        cases++;
    }
}

int main(void) {
    allocationRouting();
    storeLifecycle();
    storeFailures();
    printf("PASS: %d native allocation/store scenarios; routing, handles, failures, reset and heap accounting\n", cases);
}
'''


def fixture(source):
    header = (ROOT / 'include/main/mm.h').read_text()
    header = re.sub(r'^#include.*\n', '', header, flags=re.M)
    prefix = source[source.index('#define MM_STORE_COUNT'):source.index('static inline int regionForPtr(u8* ptr) {')]
    functions = []
    for name in ('regionForPtr', 'mmInitRegion', 'mmAlloc', 'mmAllocFromRegion',
                 'getHeapItemSize', 'changeHeapSlot', 'heapSpawnSlot', 'heapFree',
                 'mmFree', 'mmFreeDeferred', 'mm_free', 'mmFreeTick',
                 'mmCreateMemoryStore', 'mmAllocateFromFBMemoryStore'):
        start, end = find_function_body(source, name)
        signature = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
        functions.append(source[signature:end + 1])
    return PRELUDE + header + prefix + '\n'.join(functions) + CHECKS


class MemoryStoreTests(unittest.TestCase):
    def test_native_allocation_path(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang is required')
        source = (ROOT / 'src/main/mm.c').read_text()
        with tempfile.TemporaryDirectory(prefix='sfa-mm-stores-') as temporary:
            directory = Path(temporary)
            path = directory / 'stores.c'
            path.write_text(fixture(source))
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    binary = directory / 'stores'
                    subprocess.run([compiler, '-std=c11', optimization, '-g',
                                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                    str(path), '-o', str(binary)], check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
