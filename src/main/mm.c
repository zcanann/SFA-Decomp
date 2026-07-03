#include "ghidra_import.h"
#include "main/gameplay_runtime.h"
#include "main/dll/gameplay.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSArena.h"
#include "sfa_light_decls.h"

u16*
FUN_80017460(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , int param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

u16*
FUN_80017468(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

u32
FUN_80017500(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, int param_9)
{
    return 0;
}

u32
FUN_8001786c(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12)
{
    return 0;
}

u8*
FUN_80017998(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
)
{
    return 0;
}

int roundUpTo4(int x)
{
    int r = x & 3;
    if (r > 0)
    {
        x += 4 - r;
    }
    return x;
}

int roundUpTo8(int x)
{
    int r = x & 7;
    if (r > 0)
    {
        x += 8 - r;
    }
    return x;
}

int roundUpTo16(int x)
{
    int r = x & 0xf;
    if (r > 0)
    {
        x += 0x10 - r;
    }
    return x;
}

int roundUpTo32(int x)
{
    int r = x & 0x1f;
    if (r > 0)
    {
        x += 0x20 - r;
    }
    return x;
}

extern u8 lbl_803DCB10;
extern void* mmAlloc(int size, int type, int flag);

void texFlagFn_80023cbc(int v)
{
    lbl_803DCB10 = v;
}

extern int gMmFreeDelay;
extern int gMmOpCount;
extern int gMmUseHeap3;
extern int gMmUseHeaps1and2;

#pragma dont_inline on
int mmSetFreeDelay(int v)
{
    int old = gMmFreeDelay;
    gMmOpCount++;
    gMmFreeDelay = v;
    return old;
}

int testAndSet_onlyUseHeap3(int v)
{
    gMmOpCount++;
    {
        int old = gMmUseHeap3;
        gMmUseHeap3 = v;
        return old;
    }
}

int testAndSet_onlyUseHeaps1and2(int v)
{
    gMmOpCount++;
    {
        int old = gMmUseHeaps1and2;
        gMmUseHeaps1and2 = v;
        return old;
    }
}

#pragma dont_inline off
int alignUp2(int x)
{
    int r = x & 1;
    if (r > 0)
    {
        x += 2 - r;
    }
    return x;
}

extern int gAttractMovieState;
extern void* gAttractMovieScratchBuffer;

void* getCache(void)
{
    if (gAttractMovieState != 4 && gAttractMovieState != 0)
    {
        return gAttractMovieScratchBuffer;
    }
    return (void*)0xe0000000;
}

extern void LCQueueWait();
extern void mmFree(void* p);
extern void mmFreeDeferred(void* p);

void cacheQueueWait(int sync)
{
    if (gAttractMovieState == 4 || gAttractMovieState == 0)
    {
        LCQueueWait();
    }
}

void mm_free(void* p)
{
    if (gMmFreeDelay == 0)
    {
        mmFree(p);
    }
    else
    {
        mmFreeDeferred(p);
    }
}


extern asm BOOL OSRestoreInterrupts(register BOOL level);

void AtomicSList_Push(void** list, void* node)
{
    int intr = OSDisableInterrupts();
    *(void**)node = *list;
    *list = node;
    OSRestoreInterrupts(intr);
}

typedef f32 Mtx[3][4];
extern u8 gMmRegionCount;

typedef struct
{
    int numSlots;
    int slotCount;
    u8* start;
    int size;
    int usedBytes;
} MmRegion;

MmRegion gMmRegionTable[0xA0 / sizeof(MmRegion)];

typedef struct
{
    void* key;
    int size;
    s16 type;
    s16 prev;
    s16 next;
    s16 stack;
    int tag;
    int allocTick;
    int allocId;
} HeapItem;

int mmGetRegionForPtr(u8* ptr)
{
    int i;
    for (i = 0; i < gMmRegionCount; i++)
    {
        if (ptr > gMmRegionTable[i].start &&
            ptr < gMmRegionTable[i].start + gMmRegionTable[i].size)
        {
            return i;
        }
    }
    return -1;
}

#pragma dont_inline on
void* mmInitRegion(u8* buf, int size, int numSlots)
{
    int regIdx = gMmRegionCount++;
    int slotsBytes = numSlots * 0x1c;
    int after = size - slotsBytes;
    int i;
    HeapItem* slot;
    int freePtr;
    gMmRegionTable[regIdx].numSlots = numSlots;
    gMmRegionTable[regIdx].slotCount = 0;
    gMmRegionTable[regIdx].start = buf;
    gMmRegionTable[regIdx].size = size;
    gMmRegionTable[regIdx].usedBytes = 0;
    slot = (HeapItem*)gMmRegionTable[regIdx].start;
    for (i = 0; i < gMmRegionTable[regIdx].numSlots; i++)
    {
        slot->stack = i;
        slot++;
    }
    slot = (HeapItem*)gMmRegionTable[regIdx].start;
    freePtr = (int)buf + slotsBytes;
    if (freePtr & 0x1f)
    {
        *(int*)&slot->key = (freePtr & ~0x1f) + 0x20;
    }
    else
    {
        *(int*)&slot->key = freePtr;
    }
    slot->size = after;
    slot->type = 0;
    slot->prev = -1;
    slot->next = -1;
    gMmRegionTable[regIdx].slotCount++;
    return gMmRegionTable[regIdx].start;
}


extern void heapFree(int region, int slotIdx);
extern char sMmFreeInvalidLocationError[];
extern char sMmAllocFreeMessageBlock[];
extern int gMmLastFreeTick;
extern void OSReport(const char* msg, ...);

extern int GXFlush_(u8 visible, int unused);
extern char sMmStbfStackTooDeepError[];
extern s16 gMmDeferredFreeCount;

typedef struct
{
    void* ptr;
    u8 delay;
    u8 pad[3];
} DeferredFree;

DeferredFree gMmDeferredFreeStack[0x3E80 / sizeof(DeferredFree)];
extern char sMmShowInfoFBMemoryStoreMessageBlock[];
extern char sMmStoreAllocationTag;
extern int gMmNextStoreHandle;
void* gMmStoreArray[0x20];

typedef struct
{
    void* buf;
    void* bufCur;
    int size;
    int handle;
} MmStore;

#pragma dont_inline off
int mmCreateMemoryStore(int size)
{
    char* msg = sMmShowInfoFBMemoryStoreMessageBlock;
    MmStore* store;
    int i = 0;
    if (size <= 0)
    {
        OSReport(msg + 0x1e8, size);
        return 0;
    }
    if (size > 0x4000)
    {
        OSReport(msg + 0x218, size, 0x4000);
        return 0;
    }
    store = (MmStore*)mmAlloc(0x10, 0, (int)&sMmStoreAllocationTag);
    if (store == NULL)
    {
        OSReport(msg + 0x26c);
        return 0;
    }
    store->size = size;
    store->handle = gMmNextStoreHandle++;
    store->buf = NULL;
    store->bufCur = NULL;
    store->buf = mmAlloc(store->size, 0, (int)(msg + 0x2a8));
    if (store->buf == NULL)
    {
        OSReport(msg + 0x2bc);
        if (gMmFreeDelay == 0)
        {
            mmFree(store);
        }
        else
        {
            mmFreeDeferred(store);
        }
        return 0;
    }
    store->bufCur = store->buf;
    while (i < 0x20)
    {
        if (gMmStoreArray[i] == NULL)
        {
            gMmStoreArray[i] = store;
            break;
        }
        if (++i == 0x20)
        {
            void* buf;
            OSReport(msg + 0x2f8);
            buf = store->buf;
            if (gMmFreeDelay == 0)
            {
                mmFree(buf);
            }
            else
            {
                mmFreeDeferred(buf);
            }
            if (gMmFreeDelay == 0)
            {
                mmFree(store);
            }
            else
            {
                mmFreeDeferred(store);
            }
            return 0;
        }
    }
    return store->handle;
}

void mmFreeDeferred(void* p)
{
    DeferredFree* stack;
    if (gMmDeferredFreeCount == 0x7d0)
    {
        waitNextFrame();
        GXFlush_(1, 0);
        waitNextFrame();
        GXFlush_(1, 0);
        stack = gMmDeferredFreeStack;
        while (gMmDeferredFreeCount > 0)
        {
            DeferredFree* top;
            mmFree(stack[0].ptr);
            top = &stack[gMmDeferredFreeCount];
            stack[0].ptr = top[-1].ptr;
            stack[0].delay = top[-1].delay;
            gMmDeferredFreeCount--;
        }
        OSReport(sMmStbfStackTooDeepError);
    }
    gMmDeferredFreeStack[gMmDeferredFreeCount].ptr = p;
    gMmDeferredFreeStack[gMmDeferredFreeCount].delay = gMmFreeDelay;
    gMmDeferredFreeCount++;
}

typedef struct
{
    void* stores[0x20];
    DeferredFree deferred[2000];
    MmRegion regions[8];
} MmGlobal;

extern int gMmStatsPrintCounter;
extern int gMmTickCount;
extern char sMemStatsFormat[];
extern int gMmRegion0Used;
extern int gMmRegion1Used;
extern int gMmRegion2Used;
extern int gMmRegion3Used;

void mmFreeTick(int arg)
{
    MmGlobal* g = (MmGlobal*)gMmStoreArray;
    int i;
    DeferredFree* d;
    int k;
    HeapItem* base;
    HeapItem* item;
    s16 next;

    gMmTickCount++;
    gMmOpCount++;

    i = 0;
    d = g->deferred;
    for (; i < gMmDeferredFreeCount;)
    {
        d->delay--;
        if (d->delay == 0)
        {
            mmFree(d->ptr);
            {
                char* a = (char*)g + *(volatile s16*)&gMmDeferredFreeCount * 8;
                d->ptr = ((DeferredFree*)(a + 0x78))->ptr;
            }
            {
                char* b = (char*)g + *(volatile s16*)&gMmDeferredFreeCount * 8;
                d->delay = ((DeferredFree*)(b + 0x78))->delay;
            }
            gMmDeferredFreeCount--;
        }
        else
        {
            d++;
            i++;
        }
    }

    {
        MmStore** sp = (MmStore**)gMmStoreArray;
        for (k = 0; k < 0x20; k += 8, sp += 8)
        {
            if (sp[0] != NULL) { sp[0]->bufCur = sp[0]->buf; }
            if (sp[1] != NULL) { sp[1]->bufCur = sp[1]->buf; }
            if (sp[2] != NULL) { sp[2]->bufCur = sp[2]->buf; }
            if (sp[3] != NULL) { sp[3]->bufCur = sp[3]->buf; }
            if (sp[4] != NULL) { sp[4]->bufCur = sp[4]->buf; }
            if (sp[5] != NULL) { sp[5]->bufCur = sp[5]->buf; }
            if (sp[6] != NULL) { sp[6]->bufCur = sp[6]->buf; }
            if (sp[7] != NULL) { sp[7]->bufCur = sp[7]->buf; }
        }
    }
    SaveGame_updateTransientMapBits();

    gMmRegion0Used = 0;
    gMmRegion2Used = 0;
    gMmRegion1Used = 0;
    gMmRegion3Used = 0;

    if (gMmRegionCount > 1)
    {
        base = (HeapItem*)g->regions[1].start;
        item = base;
        do
        {
            if (item->type != 0)
            {
                gMmRegion1Used += item->size;
            }
            next = item->next;
            if (next != -1)
            {
                item = &base[next];
            }
        }
        while (next != -1);

        base = (HeapItem*)g->regions[2].start;
        item = base;
        do
        {
            if (item->type != 0)
            {
                gMmRegion2Used += item->size;
            }
            next = item->next;
            if (next != -1)
            {
                item = &base[next];
            }
        }
        while (next != -1);

        base = (HeapItem*)g->regions[3].start;
        item = base;
        do
        {
            if (item->type != 0)
            {
                gMmRegion3Used += item->size;
            }
            next = item->next;
            if (next != -1)
            {
                item = &base[next];
            }
        }
        while (next != -1);
    }

    if (gMmStatsPrintCounter++ % 500 == 0)
    {
        OSReport(sMemStatsFormat,
                 0, g->regions[0].size,
                 gMmRegion1Used, g->regions[1].size,
                 gMmRegion2Used, g->regions[2].size,
                 gMmRegion3Used, g->regions[3].size,
                 g->regions[0].slotCount, g->regions[0].numSlots,
                 g->regions[1].slotCount, g->regions[1].numSlots,
                 g->regions[2].slotCount, g->regions[2].numSlots,
                 g->regions[3].slotCount, g->regions[3].numSlots);
    }
}

void mmFree(void* p)
{
    int region;
    int i;
    HeapItem* base;
    gMmLastFreeTick = OSGetTick();
    region = mmGetRegionForPtr(p);
    if (region != -1)
    {
        base = (HeapItem*)gMmRegionTable[region].start;
        i = 0;
        do
        {
            if (base[i].key == p)
            {
                s16 t = base[i].type;
                if (t == 1 || t == 4)
                {
                    heapFree(region, i);
                }
                else
                {
                    OSReport(sMmFreeInvalidLocationError, p);
                }
                return;
            }
            i = base[i].next;
        }
        while (i != -1);
    }
    OSReport(sMmAllocFreeMessageBlock, p);
}

extern char sMmAllocateFromFBMemoryStoreMissingHandleError[];
extern char sMmMemoryStoreMessageBlock[];

int mmAllocateFromFBMemoryStore(int handle, int size)
{
    MmStore* found;
    int i;
    int avail;
    found = NULL;
    i = 0;
    while (i < 0x20)
    {
        if (gMmStoreArray[i] != NULL && handle == ((MmStore*)gMmStoreArray[i])->handle)
        {
            found = gMmStoreArray[i];
            break;
        }
        if (++i == 0x20)
        {
            OSReport(sMmAllocateFromFBMemoryStoreMissingHandleError);
            return 0;
        }
    }
    if (found != NULL)
    {
        avail = found->size - ((int)found->bufCur - (int)found->buf);
        if (avail < size)
        {
            OSReport(sMmMemoryStoreMessageBlock);
            return 0;
        }
        found->bufCur = (char*)found->bufCur + size;
        return (int)found->bufCur - size;
    }
    return 0;
}



extern void* OSAllocFromHeap(int heap, int size);
extern int __OSCurrHeap;
extern int gMmRegion0Size;
extern void* lbl_803DD498;
extern void* lbl_803DCAFC;

void mmInit(void)
{
    int size;
    int t;
    void* p;
    u8* lo;
    gMmRegionCount = 0;
    lo = OSGetArenaLo();
    t = (u8*)OSGetArenaHi() - lo - 0x6c0000;
    size = t - 0x720;
    gMmRegion0Size = size;
    p = OSAllocFromHeap(__OSCurrHeap, size);
    DCFlushRange(p, size);
    mmInitRegion(p, size, 0xfa);

    p = OSAllocFromHeap(__OSCurrHeap, 0x6ed);
    lbl_803DD498 = p;
    lbl_803DCAFC = (u8*)p + 0x6ec;

    p = OSAllocFromHeap(__OSCurrHeap, 0x1c0000);
    DCFlushRange(p, 0x1c0000);
    mmInitRegion(p, 0x1c0000, 0x352);

    p = OSAllocFromHeap(__OSCurrHeap, 0x9ffa0);
    DCFlushRange(p, 0x9ffa0);
    mmInitRegion(p, 0x9ffa0, 0x352);

    p = OSAllocFromHeap(__OSCurrHeap, 0x45ffa0);
    DCFlushRange(p, 0x45ffa0);
    mmInitRegion(p, 0x45ffa0, 0x244);

    gMmOpCount++;
    gMmFreeDelay = 2;
    gMmDeferredFreeCount = 0;
}

extern char sMmSpawnedUnalignedSlotWarning[];

int printHeapStats(void)
{
    OSReport(sMemStatsFormat,
             gMmRegion0Used, gMmRegionTable[0].size,
             gMmRegion1Used, gMmRegionTable[1].size,
             gMmRegion2Used, gMmRegionTable[2].size,
             gMmRegion3Used, gMmRegionTable[3].size,
             gMmRegionTable[0].slotCount, gMmRegionTable[0].numSlots,
             gMmRegionTable[1].slotCount, gMmRegionTable[1].numSlots,
             gMmRegionTable[2].slotCount, gMmRegionTable[2].numSlots,
             gMmRegionTable[3].slotCount, gMmRegionTable[3].numSlots);
    return gMmRegion0Used + (gMmRegion1Used + gMmRegion2Used + gMmRegion3Used);
}

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int itemTag, int tag);
int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int itemTag, int tag);
extern void reportAllocFail(int, int, int, int, int, int, int, int, int, int, int);
extern int gMmRegion0SpawnEnabled;
extern int gMmNextAllocId;
extern int lbl_803DCC7C;

int mmAllocFromRegion(int region, int size, int type, int tag)
{
    char* msg = sMmShowInfoFBMemoryStoreMessageBlock;
    int bestIdx;
    HeapItem* it;
    int idx;
    HeapItem* base;
    int bestSize;
    int largestFree0;
    HeapItem* res;
    int largestFree1;
    int largest;

    largest = 0;
    largestFree0 = 0;
    largestFree1 = 0;

    if (gMmRegionTable[region].slotCount + 1 == gMmRegionTable[region].numSlots)
    {
        OSReport(msg + 0x4b8, tag, region);
        return 0;
    }

    if (size & 0x1f)
    {
        size = (size & ~0x1f) + 0x20;
    }

    bestIdx = -1;
    bestSize = 0x7fffffff;
    base = (HeapItem*)gMmRegionTable[region].start;
    idx = 0;

    if (region == 0 && size < 0x33450)
    {
        it = base;
        while (it->next != -1)
        {
            idx = it->next;
            it = &base[idx];
        }
        do
        {
            it = &base[idx];
            if (it->type == 0)
            {
                if (it->size >= size)
                {
                    if (it->size < bestSize)
                    {
                        bestSize = it->size;
                        bestIdx = idx;
                    }
                }
                else if (it->size > largest)
                {
                    largest = it->size;
                }
            }
            idx = it->prev;
        }
        while (idx != -1);
    }
    else
    {
        do
        {
            it = &base[idx];
            if (it->type == 0)
            {
                if (it->size >= size)
                {
                    if (it->size < bestSize)
                    {
                        bestSize = it->size;
                        bestIdx = idx;
                        if (region == 0)
                        {
                            break;
                        }
                    }
                }
                else if (it->size > largest)
                {
                    largest = it->size;
                }
            }
            idx = it->next;
        }
        while (idx != -1);
    }

    if (bestIdx != -1)
    {
        gMmRegionTable[region].usedBytes += size;
        if (gMmRegionTable[region].usedBytes < 0 || gMmRegionTable[region].usedBytes > gMmRegionTable[region].size)
        {
            OSReport(msg + 0x50c);
        }
        if (gMmRegion0SpawnEnabled != 0 && region == 0 && size < 0x33450)
        {
            bestIdx = heapSpawnSlot(region, bestIdx, size, 1, 0, type, tag);
        }
        else
        {
            changeHeapSlot(region, bestIdx, size, 1, 0, type, tag);
        }
        res = &base[bestIdx];
        if (gMmNextAllocId == 0x3ef)
        {
            OSReport(msg + 0x53c);
        }
        res->allocId = gMmNextAllocId++;
        gMmOpCount++;
        return (int)res->key;
    }

    if ((region == 2 && size > 0x3000) || region == 3 || region == 1)
    {
        HeapItem* b0;
        HeapItem* b1;
        HeapItem* w;
        OSReport(msg + 0x54c, tag, region, type, size);
        b0 = (HeapItem*)gMmRegionTable[0].start;
        w = b0;
        while (w->next != -1)
        {
            w = &b0[w->next];
            if (w->size > largestFree0 && w->type == 0)
            {
                largestFree0 = w->size;
            }
        }
        b1 = (HeapItem*)gMmRegionTable[1].start;
        w = b1;
        while (w->next != -1)
        {
            w = &b1[w->next];
            if (w->size > largestFree1 && w->type == 0)
            {
                largestFree1 = w->size;
            }
        }
        reportAllocFail(
            gMmRegionTable[0].size / 1024,
            gMmRegionTable[0].size / 1024 - gMmRegion0Used / 1024,
            gMmRegionTable[1].size / 1024,
            gMmRegionTable[1].size / 1024 - gMmRegion1Used / 1024,
            gMmRegionTable[2].size / 1024,
            gMmRegionTable[2].size / 1024 - gMmRegion2Used / 1024,
            lbl_803DCC7C,
            gMmTickCount,
            size, largestFree0, largestFree1);
    }
    return 0;
}

int heapSpawnSlot(int region, int idx, int size, int type, int newType, int itemTag, int tag)
{
    int ni;
    HeapItem* base;
    int oldSize;
    while (size % 32 != 0)
    {
        size++;
    }
    base = (HeapItem*)gMmRegionTable[region].start;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = size;
    base[idx].tag = itemTag;
    if (oldSize > size)
    {
        s16 oldNext;
        ni = base[gMmRegionTable[region].slotCount++].stack;
        base[idx].type = newType;
        while ((oldSize - size) % 32 != 0)
        {
            size++;
        }
        base[idx].size = oldSize - size;
        base[ni].type = type;
        base[ni].key = (char*)base[idx].key + oldSize - size;
        if ((int)base[ni].key % 32 != 0)
        {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].key, base[ni].size);
        }
        base[ni].size = size;
        base[ni].tag = itemTag;
        base[ni].allocTick = gMmTickCount;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1)
        {
            base[oldNext].prev = ni;
        }
        return ni;
    }
    return idx;
}

int changeHeapSlot(int region, int idx, int newSize, int type, int newType, int itemTag, int tag)
{
    int oldSize;
    int ni;
    HeapItem* base;
    base = (HeapItem*)gMmRegionTable[region].start;
    base[idx].type = type;
    oldSize = base[idx].size;
    base[idx].size = newSize;
    base[idx].tag = itemTag;
    if (oldSize > newSize)
    {
        s16 oldNext;
        ni = base[gMmRegionTable[region].slotCount++].stack;
        base[ni].key = (char*)base[idx].key + newSize;
        if ((int)base[ni].key % 32 != 0)
        {
            OSReport(sMmSpawnedUnalignedSlotWarning, base[ni].stack, base[ni].key, base[ni].size);
        }
        base[ni].size = oldSize - newSize;
        base[ni].type = newType;
        oldNext = base[idx].next;
        base[ni].next = oldNext;
        base[ni].prev = idx;
        base[idx].next = ni;
        if (oldNext != -1)
        {
            base[oldNext].prev = ni;
        }
        base[idx].allocTick = gMmTickCount;
        return ni;
    }
    return idx;
}

extern char sMmFreeMemoryUsageCorruptedError[];

void heapFree(int region, int idx)
{
    s16 next;
    s16 prev;
    HeapItem* base = (HeapItem*)gMmRegionTable[region].start;
    next = base[idx].next;
    prev = base[idx].prev;
    base[idx].type = 0;
    gMmOpCount++;
    gMmRegionTable[region].usedBytes -= base[idx].size;
    if (gMmRegionTable[region].usedBytes < 0 || gMmRegionTable[region].usedBytes > gMmRegionTable[region].size)
    {
        OSReport(sMmFreeMemoryUsageCorruptedError);
    }
    if (next != -1 && base[next].type == 0)
    {
        s16 nn;
        base[idx].size += base[next].size;
        nn = base[next].next;
        base[idx].next = nn;
        if (nn != -1)
        {
            base[nn].prev = idx;
        }
        base[--gMmRegionTable[region].slotCount].stack = next;
    }
    if (prev != -1 && base[prev].type == 0)
    {
        s16 in;
        base[prev].size += base[idx].size;
        in = base[idx].next;
        base[prev].next = in;
        if (in != -1)
        {
            base[in].prev = prev;
        }
        base[--gMmRegionTable[region].slotCount].stack = idx;
    }
}

int getHeapItemSize(void* ptr)
{
    int i = mmGetRegionForPtr(ptr);
    HeapItem* items = (HeapItem*)gMmRegionTable[i].start;
    int idx = 0;
    for (;;)
    {
        if (items[idx].key == ptr)
        {
            return items[idx].size;
        }
        idx = items[idx].next;
        if (idx == -1)
        {
            return -1;
        }
    }
}

void* AtomicSList_Pop(void** list)
{
    int intr = OSDisableInterrupts();
    void* head = *list;
    if (head == NULL)
    {
        OSRestoreInterrupts(intr);
        return NULL;
    }
    *list = *(void**)head;
    OSRestoreInterrupts(intr);
    return head;
}

extern void* memcpy(void* dst, const void* src, int n);

void copyToCache(void* dst, void* src, u32 count)
{
    if (gAttractMovieState != 4 && gAttractMovieState != 0)
    {
        int len;
        if (count != 0)
        {
            len = count << 5;
        }
        else
        {
            len = 0x1000;
        }
        memcpy(dst, src, len);
    }
    else
    {
        LCLoadBlocks(dst, src, count);
    }
}

void memcpyToCache(void* dst, void* src, u32 count)
{
    if (gAttractMovieState != 4 && gAttractMovieState != 0)
    {
        int len;
        if (count != 0)
        {
            len = count << 5;
        }
        else
        {
            len = 0x1000;
        }
        memcpy(dst, src, len);
        DCFlushRange(dst, len);
    }
    else
    {
        LCStoreBlocks(dst, src, count);
    }
}

void* stackCreate(int count, int size)
{
    u8* s;
    int prev;
    void** first;
    void** cur;
    u8* next;
    int n;

    n = testAndSet_onlyUseHeaps1and2(2);
    prev = n;
    s = mmAlloc(size * count + 0x20, 0x11, 0);
    testAndSet_onlyUseHeaps1and2(prev);
    *(s16*)(s + 0xc) = size;
    *(s16*)(s + 0xe) = count;
    *(u16*)(s + 0x10) = 0;
    *(int*)(s + 4) = (int)s + *(s16*)(s + 0xe) * *(s16*)(s + 0xc) + 0x20;
    first = (void**)(s + 0x20);
    cur = first;
    next = (u8*)first + size;
    n = count - 2;
    for (; n > 0; n--)
    {
        *cur = next;
        cur = (void**)*cur;
        next += size;
    }
    *cur = 0;
    *(void**)s = first;
    cur = *(void***)s;
    while (cur != 0)
    {
        int ok = 0;
        if (cur >= first && cur < *(void***)(s + 4))
        {
            ok = 1;
        }
        if (ok == 0)
        {
            break;
        }
        cur = (void**)*cur;
    }
    return s;
}

void* mmAlloc(int size, int type, int flag)
{
    void* result;
    u8 ok;
    u8 i;

    if (size == 0)
    {
        return 0;
    }
    ok = 1;
    for (i = 0; ok && i < 100; i++)
    {
        if (gMmUseHeaps1and2 == 1)
        {
            result = (void*)mmAllocFromRegion(1, size, type, flag);
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0)
            {
                return result;
            }
        }
        else if (gMmUseHeap3 != 0)
        {
            result = (void*)mmAllocFromRegion(3, size, type, flag);
            if (result == 0)
            {
                return result;
            }
        }
        else if (size >= 0x3000)
        {
            result = (void*)mmAllocFromRegion(0, size, type, flag);
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(1, size, type, flag);
            }
        }
        else if (size >= 0x400)
        {
            result = (void*)mmAllocFromRegion(1, size, type, flag);
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(2, size, type, flag);
            }
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(0, size, type, flag);
            }
        }
        else
        {
            result = (void*)mmAllocFromRegion(2, size, type, flag);
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(1, size, type, flag);
            }
            if (result == 0)
            {
                result = (void*)mmAllocFromRegion(0, size, type, flag);
            }
        }
        ok = 0;
    }
    return result;
}

/* dtk-split chunk of MWCC's pooled OSReport format strings (truncated at the symbol boundary), so it is emitted as raw bytes. */
char sMmMemoryStoreMessageBlock[] =
{
    0x3C, 0x6D, 0x6D, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x46,
    0x72, 0x6F, 0x6D, 0x46, 0x42, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6C, 0x61,
    0x62, 0x6C, 0x65, 0x20, 0x73, 0x70, 0x61, 0x63, 0x65, 0x20, 0x69, 0x6E,
    0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74, 0x6F, 0x72, 0x65, 0x20,
    0x25, 0x64, 0x20, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x77, 0x61, 0x6E, 0x74,
    0x65, 0x64, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x3C, 0x6D, 0x6D, 0x44,
    0x65, 0x73, 0x74, 0x72, 0x6F, 0x79, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79,
    0x53, 0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65,
    0x64, 0x20, 0x74, 0x6F, 0x20, 0x66, 0x69, 0x6E, 0x64, 0x20, 0x73, 0x74,
    0x6F, 0x72, 0x65, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x72, 0x65, 0x71,
    0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x68, 0x61, 0x6E, 0x64, 0x6C,
    0x65, 0x20, 0x69, 0x6E, 0x20, 0x4D, 0x4D, 0x53, 0x54, 0x4F, 0x52, 0x45,
    0x5F, 0x41, 0x52, 0x52, 0x41, 0x59, 0x0A, 0x00, 0x3C, 0x6D, 0x6D, 0x43,
    0x72, 0x65, 0x61, 0x74, 0x65, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64,
    0x20, 0x61, 0x73, 0x20, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x77, 0x61, 0x73,
    0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x6D, 0x6D, 0x43,
    0x72, 0x65, 0x61, 0x74, 0x65, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64,
    0x20, 0x61, 0x73, 0x20, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x25, 0x64, 0x20,
    0x77, 0x61, 0x73, 0x20, 0x67, 0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20,
    0x74, 0x68, 0x61, 0x6E, 0x20, 0x4D, 0x4D, 0x5F, 0x4D, 0x41, 0x58, 0x5F,
    0x4D, 0x45, 0x4D, 0x5F, 0x53, 0x54, 0x4F, 0x52, 0x45, 0x5F, 0x53, 0x49,
    0x5A, 0x45, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x3C, 0x6D, 0x6D, 0x43,
    0x72, 0x65, 0x61, 0x74, 0x65, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64,
    0x20, 0x74, 0x6F, 0x20, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65,
    0x20, 0x6D, 0x6D, 0x53, 0x74, 0x6F, 0x72, 0x65, 0x20, 0x4F, 0x62, 0x6A,
    0x65, 0x63, 0x74, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x6D, 0x53, 0x74,
    0x6F, 0x72, 0x65, 0x2D, 0x3E, 0x70, 0x74, 0x72, 0x53, 0x74, 0x6F, 0x72,
    0x65, 0x00, 0x00, 0x00, 0x3C, 0x6D, 0x6D, 0x43, 0x72, 0x65, 0x61, 0x74,
    0x65, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53, 0x74, 0x6F, 0x72, 0x65,
    0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20,
    0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x20, 0x6D, 0x6D, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x2D, 0x3E, 0x70, 0x74, 0x72, 0x53, 0x74, 0x6F,
    0x72, 0x65, 0x0A, 0x00, 0x3C, 0x6D, 0x6D, 0x43, 0x72, 0x65, 0x61, 0x74,
    0x65, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53, 0x74, 0x6F, 0x72, 0x65,
    0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20,
};

/* Additional dtk-split chunks of mm's pooled OSReport format strings
   (embedded NULs / boundary truncation), emitted as raw bytes. */

char sMmShowInfoFBMemoryStoreMessageBlock[] =
{
    0x3C, 0x6D, 0x6D, 0x53, 0x68, 0x6F, 0x77, 0x49, 0x6E, 0x66, 0x6F, 0x46,
    0x42, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53, 0x74, 0x6F, 0x72, 0x65,
    0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20,
    0x66, 0x69, 0x6E, 0x64, 0x20, 0x73, 0x74, 0x6F, 0x72, 0x65, 0x20, 0x77,
    0x69, 0x74, 0x68, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65,
    0x64, 0x20, 0x68, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x20, 0x69, 0x6E, 0x20,
    0x4D, 0x4D, 0x53, 0x54, 0x4F, 0x52, 0x45, 0x5F, 0x41, 0x52, 0x52, 0x41,
    0x59, 0x0A, 0x00, 0x00, 0x74, 0x68, 0x69, 0x73, 0x53, 0x74, 0x6F, 0x72,
    0x65, 0x20, 0x30, 0x78, 0x25, 0x38, 0x78, 0x20, 0x74, 0x68, 0x69, 0x73,
    0x53, 0x74, 0x6F, 0x72, 0x65, 0x2D, 0x3E, 0x68, 0x61, 0x6E, 0x64, 0x6C,
    0x65, 0x20, 0x25, 0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x53, 0x74, 0x6F,
    0x72, 0x65, 0x2D, 0x3E, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x25, 0x64, 0x20,
    0x74, 0x68, 0x69, 0x73, 0x53, 0x74, 0x6F, 0x72, 0x65, 0x2D, 0x3E, 0x70,
    0x74, 0x72, 0x53, 0x74, 0x6F, 0x72, 0x65, 0x20, 0x30, 0x78, 0x25, 0x38,
    0x78, 0x20, 0x74, 0x68, 0x69, 0x73, 0x53, 0x74, 0x6F, 0x72, 0x65, 0x2D,
    0x3E, 0x70, 0x74, 0x72, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x20,
    0x30, 0x78, 0x25, 0x38, 0x78, 0x20, 0x20, 0x65, 0x6E, 0x64, 0x20, 0x6F,
    0x66, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74, 0x6F, 0x72, 0x65,
    0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x30, 0x78, 0x25, 0x38, 0x78,
    0x0A, 0x00, 0x00, 0x00,
};

char sMmAllocateFromFBMemoryStoreMissingHandleError[] =
{
    0x3C, 0x6D, 0x6D, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x46,
    0x72, 0x6F, 0x6D, 0x46, 0x42, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x53,
    0x74, 0x6F, 0x72, 0x65, 0x3E, 0x20, 0x66, 0x61, 0x69, 0x6C, 0x65, 0x64,
    0x20, 0x74, 0x6F, 0x20, 0x66, 0x69, 0x6E, 0x64, 0x20, 0x73, 0x74, 0x6F,
    0x72, 0x65, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x72, 0x65, 0x71, 0x75,
    0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x68, 0x61, 0x6E, 0x64, 0x6C, 0x65,
    0x20, 0x69, 0x6E, 0x20, 0x4D, 0x4D, 0x53, 0x54, 0x4F, 0x52, 0x45, 0x5F,
    0x41, 0x52, 0x52, 0x41, 0x59, 0x0A, 0x00,
};

char lbl_802CA908[] =
{
    0x66, 0x69, 0x6E, 0x64, 0x20, 0x73, 0x6C, 0x6F, 0x74, 0x20, 0x69, 0x6E,
    0x20, 0x4D, 0x4D, 0x53, 0x54, 0x4F, 0x52, 0x45, 0x5F, 0x41, 0x52, 0x52,
    0x41, 0x59, 0x0A, 0x00, 0x6D, 0x6D, 0x3A, 0x61, 0x75, 0x64, 0x69, 0x6F,
    0x68, 0x65, 0x61, 0x70, 0x00, 0x00, 0x00, 0x00,
};

char sMemStatsFormat[] =
{
    0x6D, 0x65, 0x6D, 0x20, 0x25, 0x64, 0x6B, 0x2F, 0x25, 0x64, 0x6B, 0x20,
    0x25, 0x64, 0x6B, 0x2F, 0x25, 0x64, 0x6B, 0x20, 0x25, 0x64, 0x6B, 0x2F,
    0x25, 0x64, 0x6B, 0x20, 0x25, 0x64, 0x6B, 0x2F, 0x25, 0x64, 0x6B, 0x0A,
    0x09, 0x73, 0x6C, 0x6F, 0x74, 0x20, 0x25, 0x64, 0x2F, 0x25, 0x64, 0x20,
    0x25, 0x64, 0x2F, 0x25, 0x64, 0x20, 0x25, 0x64, 0x2F, 0x25, 0x64, 0x20,
    0x25, 0x64, 0x2F, 0x25, 0x64, 0x09, 0x0A, 0x20, 0x0A, 0x00,
};

char sMmSpawnedUnalignedSlotWarning[] =
{
    0x53, 0x50, 0x41, 0x57, 0x4E, 0x45, 0x44, 0x20, 0x41, 0x20, 0x53, 0x4C,
    0x4F, 0x54, 0x20, 0x4E, 0x4F, 0x54, 0x20, 0x41, 0x4C, 0x49, 0x47, 0x4E,
    0x45, 0x44, 0x20, 0x54, 0x4F, 0x20, 0x33, 0x32, 0x20, 0x73, 0x6C, 0x6F,
    0x74, 0x2D, 0x3E, 0x73, 0x74, 0x61, 0x63, 0x6B, 0x20, 0x25, 0x64, 0x20,
    0x73, 0x6C, 0x6F, 0x74, 0x2D, 0x3E, 0x6C, 0x6F, 0x63, 0x20, 0x30, 0x78,
    0x25, 0x78, 0x20, 0x73, 0x6C, 0x6F, 0x74, 0x2D, 0x3E, 0x73, 0x69, 0x7A,
    0x65, 0x20, 0x25, 0x64, 0x20, 0x0A, 0x00,
};

char sMmFreeMemoryUsageCorruptedError[] =
{
    0x0A, 0x0A, 0x45, 0x52, 0x52, 0x4F, 0x52, 0x3C, 0x66, 0x72, 0x65, 0x65,
    0x3E, 0x20, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x20, 0x75, 0x73, 0x61,
    0x67, 0x65, 0x20, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x20, 0x63, 0x6F, 0x72,
    0x72, 0x75, 0x70, 0x74, 0x65, 0x64, 0x20, 0x0A, 0x0A, 0x0A, 0x00,
};

char sMmStbfStackTooDeepError[] =
{
    0x0A, 0x37, 0x3A, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x6D, 0x6D, 0x20, 0x45,
    0x72, 0x72, 0x6F, 0x72, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x2D, 0x2D, 0x2D,
    0x3E, 0x20, 0x73, 0x74, 0x62, 0x66, 0x20, 0x73, 0x74, 0x61, 0x63, 0x6B,
    0x20, 0x74, 0x6F, 0x6F, 0x20, 0x64, 0x65, 0x65, 0x70, 0x21, 0x0A, 0x00,
};

char sMmFreeInvalidLocationError[] =
{
    0x0A, 0x35, 0x3A, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x6D, 0x6D, 0x20, 0x45,
    0x72, 0x72, 0x6F, 0x72, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x2D, 0x2D, 0x2D,
    0x3E, 0x20, 0x43, 0x61, 0x6E, 0x27, 0x74, 0x20, 0x66, 0x72, 0x65, 0x65,
    0x20, 0x72, 0x61, 0x6D, 0x20, 0x61, 0x74, 0x20, 0x74, 0x68, 0x69, 0x73,
    0x20, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x25,
    0x78, 0x0A, 0x00,
};

char sMmAllocFreeMessageBlock[] =
{
    0x0A, 0x36, 0x3A, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x6D, 0x6D, 0x20, 0x45,
    0x72, 0x72, 0x6F, 0x72, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x2D, 0x2D, 0x2D,
    0x3E, 0x20, 0x4E, 0x6F, 0x20, 0x6D, 0x61, 0x74, 0x63, 0x68, 0x20, 0x66,
    0x6F, 0x75, 0x6E, 0x64, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x6D, 0x6D, 0x46,
    0x72, 0x65, 0x65, 0x2C, 0x20, 0x25, 0x30, 0x38, 0x78, 0x2E, 0x0A, 0x00,
    0x31, 0x3A, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x6D, 0x6D, 0x20, 0x45, 0x72,
    0x72, 0x6F, 0x72, 0x20, 0x2A, 0x2A, 0x2A, 0x20, 0x2D, 0x2D, 0x2D, 0x3E,
    0x20, 0x27, 0x25, 0x73, 0x27, 0x20, 0x4E, 0x6F, 0x20, 0x6D, 0x6F, 0x72,
    0x65, 0x20, 0x73, 0x6C, 0x6F, 0x74, 0x73, 0x20, 0x61, 0x76, 0x61, 0x69,
    0x6C, 0x61, 0x62, 0x6C, 0x65, 0x2E, 0x20, 0x20, 0x72, 0x65, 0x67, 0x69,
    0x6F, 0x6E, 0x20, 0x25, 0x64, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x25,
    0x64, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6C, 0x20, 0x25, 0x64, 0x0A, 0x00,
    0x0A, 0x0A, 0x45, 0x52, 0x52, 0x4F, 0x52, 0x3C, 0x61, 0x6C, 0x6C, 0x6F,
    0x63, 0x3E, 0x20, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x20, 0x75, 0x73,
    0x61, 0x67, 0x65, 0x20, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x20, 0x63, 0x6F,
    0x72, 0x72, 0x75, 0x70, 0x74, 0x65, 0x64, 0x20, 0x0A, 0x0A, 0x0A, 0x00,
    0x6D, 0x6D, 0x55, 0x6E, 0x69, 0x71, 0x75, 0x65, 0x49, 0x64, 0x65, 0x6E,
    0x74, 0x00, 0x00, 0x00, 0x0A, 0x32, 0x3A, 0x20, 0x2A, 0x2A, 0x2A, 0x20,
    0x6D, 0x6D, 0x20, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x2A, 0x2A, 0x2A,
    0x20, 0x2D, 0x2D, 0x2D, 0x3E, 0x20, 0x20, 0x27, 0x25, 0x73, 0x27, 0x20,
    0x72, 0x65, 0x67, 0x69, 0x6F, 0x6E, 0x3D, 0x25, 0x64, 0x20, 0x63, 0x6F,
    0x6C, 0x3D, 0x25, 0x78, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x73, 0x69, 0x7A,
    0x65, 0x3D, 0x25, 0x64, 0x20, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74,
    0x73, 0x69, 0x7A, 0x65, 0x3D, 0x25, 0x64, 0x2E, 0x2E, 0x2E, 0x4E, 0x6F,
    0x20, 0x73, 0x75, 0x69, 0x74, 0x62, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F,
    0x63, 0x6B, 0x20, 0x66, 0x6F, 0x75, 0x6E, 0x64, 0x20, 0x66, 0x6F, 0x72,
    0x20, 0x61, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2E,
    0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
