#include "main/mm.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os.h"
#include "types.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/attract_movie_api.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/os/OSTime.h"
#include "main/pi_dolphin_api.h"
#include "main/pi_flush_api.h"
#include "string.h"
#include "dolphin/os/OSAlloc.h"
#include "dolphin/os/OSInterrupt.h"

#include "main/gameloop_internal.h"
#include "main/pi_dolphin.h"

#define MM_STORE_COUNT            0x20
#define MM_DEFERRED_FREE_CAPACITY 2000
#define MM_REGION_CAPACITY        8
#define MM_NUM_REGIONS            4
//large region size is "everything left over"
#define MM_MEDIUM_REGION_SIZE  0x1c0000 //1.75M
#define MM_SMALL_REGION_SIZE   0x9ffa0  //~640K
#define MM_REGION3_SIZE        0x45ffa0 //~4.37M
#define MM_LARGE_REGION_SLOTS  250
#define MM_MEDIUM_REGION_SLOTS 850
#define MM_SMALL_REGION_SLOTS  850
#define MM_REGION3_SLOTS       580 //typo?

u8 gMmRegionCount;
s16 gMmDeferredFreeCount;
int gMmFreeDelay;
int gMmNextStoreHandle;
int gMmLastFreeTick;
int gMmStatsPrintCounter;
int gMmRegion3Used;
int gMmRegion2Used;
int gMmRegion1Used;
int gMmRegion0Used;
int gMmTickCount;
int gMmRegion0Size;
int gMmOpCount;
u8 gMmTextureAllocationState;
int gMmNextAllocId;
int gMmForceHeap3Only; //when not zero, force using heap 3 only

int gMmRegion0SpawnEnabled = 1;
int gMmForceHeaps1and2Only = -1; //when == 1, force using heaps 1 and 2 only (for texture reregion)
char sMmStoreAllocationTag[] = "mmStore";

typedef struct MmRegion {
    int numSlots;
    int slotsUsed;
    u8* start;
    int size;
    int usedBytes;
} MmRegion;

STATIC_ASSERT(sizeof(MmRegion) == 0x14);

typedef struct HeapItem {
    void* loc;
    int size;
    s16 type;
    s16 prev;
    s16 next;
    s16 stack;
    int tag;
    int allocTick;
    int allocId;
} HeapItem;

STATIC_ASSERT(sizeof(HeapItem) == 0x1C);

typedef struct DeferredFree {
    void* ptr;
    u8 delay;
    u8 pad[3];
} DeferredFree;

STATIC_ASSERT(sizeof(DeferredFree) == 0x8);

typedef struct MmStore {
    void* ptrStore;
    void* ptrCurrent;
    int size;
    int handle;
} MmStore;

STATIC_ASSERT(sizeof(MmStore) == 0x10);

typedef struct StackPool {
    void* freeList;
    void* end;
    u32 unk8;
    s16 itemSize;
    s16 itemCount;
    u16 usedCount;
    u8 pad12[0xe];
} StackPool;

STATIC_ASSERT(sizeof(StackPool) == 0x20);

MmRegion gMmRegionTable[MM_REGION_CAPACITY];
DeferredFree gMmDeferredFreeStack[MM_DEFERRED_FREE_CAPACITY];
MmStore* gMmStoreArray[MM_STORE_COUNT];

static int heapSpawnSlot(int region, int idx, int size, int type, int newType, int itemTag, int tag);

static int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int itemTag, int tag);

static void heapFree(int region, int idx);

static inline int regionForPtr(u8* ptr);

static int mmAllocFromRegion(int region, int size, int type, int tag);

char sMmShowInfoFBMemoryStoreMissingHandleError[] =
    "<mmShowInfoFBMemoryStore> failed to find store with requested handle in MMSTORE_ARRAY\n";
char sMmShowInfoFBMemoryStoreFormat[] = "thisStore 0x%8x thisStore->handle %d thisStore->size %d thisStore->ptrStore "
                                        "0x%8x thisStore->ptrCurrent 0x%8x  end of this store array 0x%8x\n";
char sMmAllocateFromFBMemoryStoreMissingHandleError[] =
    "<mmAllocateFromFBMemoryStore> failed to find store with requested handle in MMSTORE_ARRAY\n";
char sMmAllocateFromFBMemoryStoreSpaceError[] =
    "<mmAllocateFromFBMemoryStore> available space in this store %d size wanted %d\n";
char sMmDestroyMemoryStoreMissingHandleError[] =
    "<mmDestroyMemoryStore> failed to find store with requested handle in MMSTORE_ARRAY\n";
char sMmCreateMemoryStoreZeroSizeError[] = "<mmCreateMemoryStore> failed as size was %d\n";
char sMmCreateMemoryStoreSizeTooLargeError[] =
    "<mmCreateMemoryStore> failed as size %d was greater than MM_MAX_MEM_STORE_SIZE %d\n";
char sMmCreateMemoryStoreObjectAllocError[] = "<mmCreateMemoryStore> failed to allocate mmStore Object\n";
char sMmStorePtrStoreAllocationTag[] = "mmStore->ptrStore";
char sMmCreateMemoryStorePtrStoreAllocError[] = "<mmCreateMemoryStore> failed to allocate mmStore->ptrStore\n";
char sMmCreateMemoryStoreNoFreeSlotError[] = "<mmCreateMemoryStore> failed to find slot in MMSTORE_ARRAY\n";
char sMmAudioHeapName[] = "mm:audioheap";
char sMemStatsFormat[] = "mem %dk/%dk %dk/%dk %dk/%dk %dk/%dk\n\tslot %d/%d %d/%d %d/%d %d/%d\t\n \n";
char sMmSpawnedUnalignedSlotWarning[] =
    "SPAWNED A SLOT NOT ALIGNED TO 32 slot->stack %d slot->loc 0x%x slot->size %d \n";
char sMmFreeMemoryUsageCorruptedError[] = "\n\nERROR<free> memory usage value corrupted \n\n\n";
char sMmStbfStackTooDeepError[] = "\n7: *** mm Error *** ---> stbf stack too deep!\n";
char sMmFreeInvalidLocationError[] = "\n5: *** mm Error *** ---> Can't free ram at this location: %x\n";
char sMmFreeNoMatchError[] = "\n6: *** mm Error *** ---> No match found for mmFree, %08x.\n";
char sMmAllocNoFreeSlotsError[] =
    "1: *** mm Error *** ---> '%s' No more slots available.  region %d used %d avail %d\n";
char sMmAllocMemoryUsageCorruptedError[] = "\n\nERROR<alloc> memory usage value corrupted \n\n\n";
char sMmUniqueAllocationIdTag[] = "mmUniqueIdent";
char sMmAllocNoSuitableBlockError[] = "\n2: *** mm Error *** --->  '%s' region=%d col=%x wantsize=%d "
                                      "largestsize=%d...No suitble block found for allocation.\n";
static inline int regionForPtr(u8* ptr) {
    int i;
    for (i = 0; i < gMmRegionCount; i++) {
        if (ptr > gMmRegionTable[i].start && ptr < gMmRegionTable[i].start + gMmRegionTable[i].size) {
            return i;
        }
    }
    return -1;
}

void* stackCreate(int count, int size) {
    StackPool* stack;
    int prev;
    void** first;
    void** cur;
    u8* next;
    int n;

    n = mmSetForceHeaps1and2Only(2);
    prev = n;
    stack = mmAlloc(size * count + sizeof(StackPool), 0x11, 0);
    mmSetForceHeaps1and2Only(prev);
    stack->itemSize = size;
    stack->itemCount = count;
    stack->usedCount = 0;
    stack->end = (u8*)stack + stack->itemCount * stack->itemSize + sizeof(StackPool);
    first = (void**)(stack + 1);
    cur = first;
    next = (u8*)first + size;
    n = count - 2;
    for (; n > 0; n--) {
        *cur = next;
        cur = (void**)*cur;
        next += size;
    }
    *cur = 0;
    stack->freeList = first;
    cur = stack->freeList;
    while (cur != 0) {
        int ok = 0;
        if (cur >= first && cur < stack->end) {
            ok = 1;
        }
        if (ok == 0) {
            break;
        }
        cur = (void**)*cur;
    }
    return stack;
}

void AtomicSList_Push(void** list, void* node) {
    int intr = OSDisableInterrupts();
    *(void**)node = *list;
    *list = node;
    OSRestoreInterrupts(intr);
}

void* AtomicSList_Pop(void** list) {
    int intr = OSDisableInterrupts();
    void* head = *list;
    if (head == NULL) {
        OSRestoreInterrupts(intr);
        return NULL;
    }
    *list = *(void**)head;
    OSRestoreInterrupts(intr);
    return head;
}

void mmInit(void) {
    int size;
    int t;
    void* p;
    u8* lo;
    gMmRegionCount = 0;
    lo = OSGetArenaLo();
    t = (u8*)OSGetArenaHi() - lo - (MM_MEDIUM_REGION_SIZE + MM_SMALL_REGION_SIZE + MM_REGION3_SIZE + 0xC0);
    //this "+ 0xC0" might be rounding up to 256?
    size = t - 0x720; //XXX where does this number come from?
    gMmRegion0Size = size;

    //large region (all memory not used by anything else)
    p = OSAllocFromHeap(__OSCurrHeap, size);
    DCFlushRange(p, size);
    mmInitRegion(p, size, MM_LARGE_REGION_SLOTS);

    //savegame buffer
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    p = OSAllocFromHeap(__OSCurrHeap, 0x6ec);
    gSaveGameWorkBuffer = p;
#else
    p = OSAllocFromHeap(__OSCurrHeap, 0x6ed);
    gSaveGameWorkBuffer = p;
    gAskProgressiveScanFlag = (u8*)p + 0x6ec;
#endif

    //medium region
    p = OSAllocFromHeap(__OSCurrHeap, MM_MEDIUM_REGION_SIZE);
    DCFlushRange(p, MM_MEDIUM_REGION_SIZE);
    mmInitRegion(p, MM_MEDIUM_REGION_SIZE, MM_MEDIUM_REGION_SLOTS);

    //small region
    p = OSAllocFromHeap(__OSCurrHeap, MM_SMALL_REGION_SIZE);
    DCFlushRange(p, MM_SMALL_REGION_SIZE);
    mmInitRegion(p, MM_SMALL_REGION_SIZE, MM_SMALL_REGION_SLOTS);

    //extra region (need to investigate purpose)
    p = OSAllocFromHeap(__OSCurrHeap, MM_REGION3_SIZE);
    DCFlushRange(p, MM_REGION3_SIZE);
    mmInitRegion(p, MM_REGION3_SIZE, MM_REGION3_SLOTS);

    gMmOpCount++;
    gMmFreeDelay = 2;
    gMmDeferredFreeCount = 0;
}

void* mmInitRegion(u8* buf, int size, int numSlots) {
    int regIdx = gMmRegionCount++;
    int slotsBytes = numSlots * sizeof(HeapItem);
    int after = size - slotsBytes;
    int i;
    HeapItem* slot;
    int freePtr;
    gMmRegionTable[regIdx].numSlots = numSlots;
    gMmRegionTable[regIdx].slotsUsed = 0;
    gMmRegionTable[regIdx].start = buf;
    gMmRegionTable[regIdx].size = size;
    gMmRegionTable[regIdx].usedBytes = 0;
    slot = (HeapItem*)gMmRegionTable[regIdx].start;
    for (i = 0; i < gMmRegionTable[regIdx].numSlots; i++) {
        slot->stack = i;
        slot++;
    }
    slot = (HeapItem*)gMmRegionTable[regIdx].start;
    freePtr = (int)buf + slotsBytes;
    if (freePtr & 0x1f) {
        slot->loc = (void*)((freePtr & ~0x1f) + 0x20);
    } else {
        slot->loc = (void*)freePtr;
    }
    slot->size = after;
    slot->type = 0;
    slot->prev = -1;
    slot->next = -1;
    gMmRegionTable[regIdx].slotsUsed++;
    return gMmRegionTable[regIdx].start;
}

void* mmAlloc(int size, int type, int flag) {
    void* result;
    u8 ok;
    u8 i;

    if (size == 0) {
        return 0;
    }
    ok = 1;
    for (i = 0; ok && i < 100; i++) {
        if (gMmForceHeaps1and2Only == 1) {
            //texture reregion happening. prefer heap 1, fall back to 2.
            result = (void*)mmAllocFromRegion(1, size, type, flag);
            if (result == 0) {
                result = (void*)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0) {
                return result;
            }
        } else if (gMmForceHeap3Only != 0) {
            result = (void*)mmAllocFromRegion(3, size, type, flag);
            if (result == 0) {
                return result;
            }
        } else if (size >= 0x3000) {
            result = (void*)mmAllocFromRegion(0, size, type, flag);
            if (result == 0) {
                result = (void*)mmAllocFromRegion(1, size, type, flag);
            }
        } else if (size >= 0x400) {
            result = (void*)mmAllocFromRegion(1, size, type, flag);
            if (result == 0) {
                result = (void*)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0) {
                result = (void*)mmAllocFromRegion(0, size, type, flag);
            }
        } else {
            result = (void*)mmAllocFromRegion(2, size, type, flag);
            if (result == 0) {
                result = (void*)mmAllocFromRegion(1, size, type, flag);
            }
            if (result == 0) {
                result = (void*)mmAllocFromRegion(0, size, type, flag);
            }
        }
        ok = 0;
    }
    return result;
}

void mmSetTextureAllocationState(int state) {
    gMmTextureAllocationState = state;
}

int getHeapItemSize(void* ptr) {
    int i = regionForPtr(ptr);
    HeapItem* items = (HeapItem*)gMmRegionTable[i].start;
    int idx = 0;
    for (;;) {
        if (items[idx].loc == ptr) {
            return items[idx].size;
        }
        idx = items[idx].next;
        if (idx == -1) {
            return -1;
        }
    }
}

static int mmAllocFromRegion(int region, int size, int type, int tag) {
    int bestIdx;
    int bestSize;
    int idx;
    HeapItem* base;
    HeapItem* it;
    int largestFree0;
    HeapItem* res;
    int largestFree1;
    int largest;

    largest = 0;
    largestFree0 = 0;
    largestFree1 = 0;

    if (gMmRegionTable[region].slotsUsed + 1 == gMmRegionTable[region].numSlots) {
        OSReport(sMmAllocNoFreeSlotsError, tag, region, gMmRegionTable[region].slotsUsed,
                 gMmRegionTable[region].numSlots);
        return 0;
    }

    if (size & 0x1f) {
        size = (size & ~0x1f) + 0x20;
    }

    bestIdx = -1;
    bestSize = 0x7fffffff;
    base = (HeapItem*)gMmRegionTable[region].start;
    idx = 0;

    if (region == 0 && size < MM_REGION0_LARGE_ALLOCATION_THRESHOLD) {
        it = base;
        while (it->next != -1) {
            idx = it->next;
            it = &base[idx];
        }
        do {
            it = &base[idx];
            if (it->type == 0) {
                if (it->size >= size) {
                    if (it->size < bestSize) {
                        bestSize = it->size;
                        bestIdx = idx;
                    }
                } else if (it->size > largest) {
                    largest = it->size;
                }
            }
            idx = it->prev;
        } while (idx != -1);
    } else {
        do {
            it = &base[idx];
            if (it->type == 0) {
                if (it->size >= size) {
                    if (it->size < bestSize) {
                        bestSize = it->size;
                        bestIdx = idx;
                        if (region == 0) {
                            break;
                        }
                    }
                } else if (it->size > largest) {
                    largest = it->size;
                }
            }
            idx = it->next;
        } while (idx != -1);
    }

    if (bestIdx != -1) {
        gMmRegionTable[region].usedBytes += size;
        if (gMmRegionTable[region].usedBytes < 0 || gMmRegionTable[region].usedBytes > gMmRegionTable[region].size) {
            OSReport(sMmAllocMemoryUsageCorruptedError);
        }
        if (gMmRegion0SpawnEnabled != 0 && region == 0 && size < MM_REGION0_LARGE_ALLOCATION_THRESHOLD) {
            bestIdx = heapSpawnSlot(region, bestIdx, size, 1, 0, type, tag);
        } else {
            changeHeapSlot(region, bestIdx, size, 1, 0, type, tag);
        }
        res = &base[bestIdx];
        if (gMmNextAllocId == 0x3ef) {
            OSReport(sMmUniqueAllocationIdTag);
        }
        res->allocId = gMmNextAllocId++;
        gMmOpCount++;
        return (int)res->loc;
    }

    if ((region == 2 && size > 0x3000) || region == 3 || region == 1) {
        HeapItem* b;
        HeapItem* w;
        OSReport(sMmAllocNoSuitableBlockError, tag, region, type, size, largest);
        b = (HeapItem*)gMmRegionTable[0].start;
        w = b;
        while (w->next != -1) {
            w = &b[w->next];
            if (w->size > largestFree0 && w->type == 0) {
                largestFree0 = w->size;
            }
        }
        b = (HeapItem*)gMmRegionTable[1].start;
        w = b;
        while (w->next != -1) {
            w = &b[w->next];
            if (w->size > largestFree1 && w->type == 0) {
                largestFree1 = w->size;
            }
        }
        reportAllocFail(gMmRegionTable[0].size / 1024, gMmRegionTable[0].size / 1024 - gMmRegion0Used / 1024,
                        gMmRegionTable[1].size / 1024, gMmRegionTable[1].size / 1024 - gMmRegion1Used / 1024,
                        gMmRegionTable[2].size / 1024, gMmRegionTable[2].size / 1024 - gMmRegion2Used / 1024,
                        gModelsArchiveLoadCount, gMmTickCount, size, largestFree0, largestFree1);
    }
    return 0;
}

int mmSetFreeDelay(int v) {
    int old = gMmFreeDelay;
    gMmOpCount++;
    gMmFreeDelay = v;
    return old;
}

void mm_free(void* p) {
    if (gMmFreeDelay == 0) {
        mmFree(p);
    } else {
        mmFreeDeferred(p);
    }
}

void mmFreeTick(int arg) {
    int queueIndex;
    DeferredFree* entry;
    int storeIndex;
    MmStore** storeCursor;
    MmStore* store;
    HeapItem* slots;
    HeapItem* slot;
    s16 nextSlotIndex;

    gMmTickCount++;
    gMmOpCount++;

    queueIndex = 0;
    entry = gMmDeferredFreeStack;
    for (; queueIndex < gMmDeferredFreeCount;) {
        entry->delay--;
        if (entry->delay == 0) {
            mmFree(entry->ptr);
            entry->ptr = gMmDeferredFreeStack[gMmDeferredFreeCount - 1].ptr;
            entry->delay = gMmDeferredFreeStack[gMmDeferredFreeCount - 1].delay;
            gMmDeferredFreeCount--;
        } else {
            entry++;
            queueIndex++;
        }
    }

    for (storeIndex = 0, storeCursor = gMmStoreArray; storeIndex < MM_STORE_COUNT; storeCursor++, storeIndex++) {
        store = *storeCursor;
        if (store != NULL) {
            store->ptrCurrent = store->ptrStore;
        }
    }
    SaveGame_updateTransientMapBits();

    gMmRegion0Used = 0;
    gMmRegion2Used = 0;
    gMmRegion1Used = 0;
    gMmRegion3Used = 0;

    if (gMmRegionCount > 1) {
        slots = (HeapItem*)gMmRegionTable[1].start;
        slot = slots;
        do {
            if (slot->type != 0) {
                gMmRegion1Used += slot->size;
            }
            nextSlotIndex = slot->next;
            if (nextSlotIndex != -1) {
                slot = &slots[nextSlotIndex];
            }
        } while (nextSlotIndex != -1);

        slots = (HeapItem*)gMmRegionTable[2].start;
        slot = slots;
        do {
            if (slot->type != 0) {
                gMmRegion2Used += slot->size;
            }
            nextSlotIndex = slot->next;
            if (nextSlotIndex != -1) {
                slot = &slots[nextSlotIndex];
            }
        } while (nextSlotIndex != -1);

        slots = (HeapItem*)gMmRegionTable[3].start;
        slot = slots;
        do {
            if (slot->type != 0) {
                gMmRegion3Used += slot->size;
            }
            nextSlotIndex = slot->next;
            if (nextSlotIndex != -1) {
                slot = &slots[nextSlotIndex];
            }
        } while (nextSlotIndex != -1);
    }

    if (gMmStatsPrintCounter++ % 500 == 0) {
        //gMmRegion0Used gets optimized to constant 0 since
        //it never gets updated
        OSReport(sMemStatsFormat, gMmRegion0Used, gMmRegionTable[0].size, gMmRegion1Used, gMmRegionTable[1].size,
                 gMmRegion2Used, gMmRegionTable[2].size, gMmRegion3Used, gMmRegionTable[3].size,
                 gMmRegionTable[0].slotsUsed, gMmRegionTable[0].numSlots, gMmRegionTable[1].slotsUsed,
                 gMmRegionTable[1].numSlots, gMmRegionTable[2].slotsUsed, gMmRegionTable[2].numSlots,
                 gMmRegionTable[3].slotsUsed, gMmRegionTable[3].numSlots);
    }
}

void mmFree(void* p) {
    int region;
    int i;
    HeapItem* base;
    gMmLastFreeTick = OSGetTick();
    region = regionForPtr(p);
    if (region != -1) {
        base = (HeapItem*)gMmRegionTable[region].start;
        i = 0;
        do {
            if (base[i].loc == p) {
                s16 itemType = base[i].type;
                if (itemType == 1 || itemType == 4) {
                    heapFree(region, i);
                } else {
                    OSReport(sMmFreeInvalidLocationError, p);
                }
                return;
            }
            i = base[i].next;
        } while (i != -1);
    }
    OSReport(sMmFreeNoMatchError, p);
}

void mmFreeDeferred(void* pointer) {
    void* pendingFree = pointer;
    DeferredFree* stack;
    if (gMmDeferredFreeCount == MM_DEFERRED_FREE_CAPACITY) {
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        stack = gMmDeferredFreeStack;
        while (gMmDeferredFreeCount > 0) {
            mmFree(stack[0].ptr);
            pointer = &stack[gMmDeferredFreeCount];
            stack[0].ptr = ((DeferredFree*)pointer)[-1].ptr;
            stack[0].delay = ((DeferredFree*)pointer)[-1].delay;
            gMmDeferredFreeCount--;
        }
        OSReport(sMmStbfStackTooDeepError);
    }
    gMmDeferredFreeStack[gMmDeferredFreeCount].ptr = pendingFree;
    gMmDeferredFreeStack[gMmDeferredFreeCount].delay = gMmFreeDelay;
    gMmDeferredFreeCount++;
}

int mmGetRegionForPtr(u8* ptr) {
    int i;
    for (i = 0; i < gMmRegionCount; i++) {
        if (ptr > gMmRegionTable[i].start && ptr < gMmRegionTable[i].start + gMmRegionTable[i].size) {
            return i;
        }
    }
    return -1;
}

static void heapFree(int region, int idx) {
    s16 next;
    s16 prev;
    HeapItem* base = (HeapItem*)gMmRegionTable[region].start;
    next = base[idx].next;
    prev = base[idx].prev;
    base[idx].type = 0;
    gMmOpCount++;
    gMmRegionTable[region].usedBytes -= base[idx].size;
    if (gMmRegionTable[region].usedBytes < 0 || gMmRegionTable[region].usedBytes > gMmRegionTable[region].size) {
        OSReport(sMmFreeMemoryUsageCorruptedError);
    }
    if (next != -1 && base[next].type == 0) {
        s16 nn;
        base[idx].size += base[next].size;
        nn = base[next].next;
        base[idx].next = nn;
        if (nn != -1) {
            base[nn].prev = idx;
        }
        base[--gMmRegionTable[region].slotsUsed].stack = next;
    }
    if (prev != -1 && base[prev].type == 0) {
        s16 in;
        base[prev].size += base[idx].size;
        in = base[idx].next;
        base[prev].next = in;
        if (in != -1) {
            base[in].prev = prev;
        }
        base[--gMmRegionTable[region].slotsUsed].stack = idx;
    }
}

static int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int itemTag, int tag) {
    int oldSize;
    int ni;
    HeapItem* base;
    base = (HeapItem*)gMmRegionTable[region].start;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = newSize;
    base[idx].tag = itemTag;
    if (oldSize > newSize) {
        s16 oldNext;
        ni = base[gMmRegionTable[region].slotsUsed++].stack;
        base[ni].loc = (char*)base[idx].loc + newSize;
        if ((int)base[ni].loc % 32 != 0) {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].loc, base[ni].size);
        }
        base[ni].size = oldSize - newSize;
        base[ni].type = newType;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1) {
            base[oldNext].prev = ni;
        }
        base[idx].allocTick = gMmTickCount;
        return ni;
    }
    return idx;
}

static int heapSpawnSlot(int region, int idx, int size, int type, int newType, int itemTag, int tag) {
    int ni;
    HeapItem* base;
    int oldSize;
    while (size % 32 != 0) {
        size++;
    }
    base = (HeapItem*)gMmRegionTable[region].start;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = size;
    base[idx].tag = itemTag;
    if (oldSize > size) {
        s16 oldNext;
        ni = base[gMmRegionTable[region].slotsUsed++].stack;
        base[idx].type = newType;
        while ((oldSize - size) % 32 != 0) {
            size++;
        }
        base[idx].size = oldSize - size;
        base[ni].type = type;
        base[ni].loc = (char*)base[idx].loc + oldSize - size;
        if ((int)base[ni].loc % 32 != 0) {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].loc, base[ni].size);
        }
        base[ni].size = size;
        base[ni].tag = itemTag;
        base[ni].allocTick = gMmTickCount;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1) {
            base[oldNext].prev = ni;
        }
        return ni;
    }
    return idx;
}

int roundUpTo32(int x) {
    int r = x & 0x1f;
    if (r > 0) {
        x += 0x20 - r;
    }
    return x;
}

int roundUpTo16(int x) {
    int r = x & 0xf;
    if (r > 0) {
        x += 0x10 - r;
    }
    return x;
}

int roundUpTo8(int x) {
    int r = x & 7;
    if (r > 0) {
        x += 8 - r;
    }
    return x;
}

int roundUpTo4(int x) {
    int r = x & 3;
    if (r > 0) {
        x += 4 - r;
    }
    return x;
}

int alignUp2(int x) {
    int r = x & 1;
    if (r > 0) {
        x += 2 - r;
    }
    return x;
}

int printHeapStats(int wpad0) {
    OSReport(sMemStatsFormat, gMmRegion0Used, gMmRegionTable[0].size, gMmRegion1Used, gMmRegionTable[1].size,
             gMmRegion2Used, gMmRegionTable[2].size, gMmRegion3Used, gMmRegionTable[3].size,
             gMmRegionTable[0].slotsUsed, gMmRegionTable[0].numSlots, gMmRegionTable[1].slotsUsed,
             gMmRegionTable[1].numSlots, gMmRegionTable[2].slotsUsed, gMmRegionTable[2].numSlots,
             gMmRegionTable[3].slotsUsed, gMmRegionTable[3].numSlots);
    return gMmRegion0Used + gMmRegion1Used + gMmRegion2Used + gMmRegion3Used;
}

int mmSetForceHeap3Only(int v) {
    gMmOpCount++;
    {
        int old = gMmForceHeap3Only;
        gMmForceHeap3Only = v;
        return old;
    }
}

int mmSetForceHeaps1and2Only(int v) {
    gMmOpCount++;
    {
        int old = gMmForceHeaps1and2Only;
        gMmForceHeaps1and2Only = v;
        return old;
    }
}

int mmCreateMemoryStore(int size) {
    MmStore* store;
    int i = 0;
    if (size <= 0) {
        OSReport(sMmCreateMemoryStoreZeroSizeError, size);
        return 0;
    }
    if (size > 0x4000) {
        OSReport(sMmCreateMemoryStoreSizeTooLargeError, size, 0x4000);
        return 0;
    }
    store = (MmStore*)mmAlloc(0x10, 0, (int)sMmStoreAllocationTag);
    if (store == NULL) {
        OSReport(sMmCreateMemoryStoreObjectAllocError);
        return 0;
    }
    store->size = size;
    store->handle = gMmNextStoreHandle++;
    store->ptrStore = NULL;
    store->ptrCurrent = NULL;
    store->ptrStore = mmAlloc(store->size, 0, (int)sMmStorePtrStoreAllocationTag);
    if (store->ptrStore == NULL) {
        OSReport(sMmCreateMemoryStorePtrStoreAllocError);
        if (gMmFreeDelay == 0) {
            mmFree(store);
        } else {
            mmFreeDeferred(store);
        }
        return 0;
    }
    store->ptrCurrent = store->ptrStore;
    while (i < 0x20) {
        if (gMmStoreArray[i] == NULL) {
            gMmStoreArray[i] = store;
            break;
        }
        if (++i == 0x20) {
            void* buf;
            OSReport(sMmCreateMemoryStoreNoFreeSlotError);
            buf = store->ptrStore;
            if (gMmFreeDelay == 0) {
                mmFree(buf);
            } else {
                mmFreeDeferred(buf);
            }
            if (gMmFreeDelay == 0) {
                mmFree(store);
            } else {
                mmFreeDeferred(store);
            }
            return 0;
        }
    }
    return store->handle;
}

void* mmAllocateFromFBMemoryStore(int handle, int size) {
    int requestedSize[1];
    MmStore* store;
    int storeIndex;
    requestedSize[0] = size;
    store = NULL;
    storeIndex = 0;
    while (storeIndex < MM_STORE_COUNT) {
        if (gMmStoreArray[storeIndex] != NULL && handle == gMmStoreArray[storeIndex]->handle) {
            store = gMmStoreArray[storeIndex];
            break;
        }
        if (++storeIndex == MM_STORE_COUNT) {
            OSReport(sMmAllocateFromFBMemoryStoreMissingHandleError);
            return 0;
        }
    }
    if (store != NULL) {
        size = store->size - ((int)store->ptrCurrent - (int)store->ptrStore);
        if (size < requestedSize[0]) {
            OSReport(sMmAllocateFromFBMemoryStoreSpaceError);
            return 0;
        }
        store->ptrCurrent = (char*)store->ptrCurrent + requestedSize[0];
        return (void*)((int)store->ptrCurrent - requestedSize[0]);
    }
    return 0;
}

void* getCache(void) {
    if (gAttractMovieState != 4 && gAttractMovieState != 0) {
        return gAttractMovieScratchBuffer;
    }
    return (void*)0xe0000000;
}

void copyToCache(void* dst, void* src, u32 count) {
    if (gAttractMovieState != 4 && gAttractMovieState != 0) {
        size_t len;
        if (count != 0) {
            len = count << 5;
        } else {
            len = 0x1000;
        }
        memcpy(dst, src, len);
    } else {
        LCLoadBlocks(dst, src, count);
    }
}

void cacheQueueWait(int sync) {
    if (gAttractMovieState == 4 || gAttractMovieState == 0) {
        LCQueueWait(sync);
    }
}

void memcpyToCache(void* dst, void* src, u32 count) {
    if (gAttractMovieState != 4 && gAttractMovieState != 0) {
        size_t len;
        if (count != 0) {
            len = count << 5;
        } else {
            len = 0x1000;
        }
        memcpy(dst, src, len);
        DCFlushRange(dst, len);
    } else {
        LCStoreBlocks(dst, src, count);
    }
}
