#include <dolphin.h>
#include <dolphin/os.h>

#define ALIGNMENT 32
#define MINOBJSIZE 64

typedef struct Cell Cell;
typedef struct HeapDesc HeapDesc;

struct Cell {
    Cell* prev;
    Cell* next;
    s32 size;
};

struct HeapDesc {
    s32 size;
    Cell* free;
    Cell* allocated;
};

void* ArenaEnd;
void* ArenaStart;
int NumHeaps;
HeapDesc* HeapArray;
volatile int __OSCurrHeap = -1;

static inline Cell* DLAddFront(Cell* neighbor, Cell* cell) {
    cell->next = neighbor;
    cell->prev = NULL;
    if (neighbor != NULL) {
        neighbor->prev = cell;
    }
    return cell;
}

static inline Cell* DLExtract(Cell* list, Cell* cell) {
    if (cell->next != NULL) {
        cell->next->prev = cell->prev;
    }
    if (cell->prev == NULL) {
        list = cell->next;
    } else {
        cell->prev->next = cell->next;
    }
    return list;
}

static Cell* DLInsert(Cell* list, Cell* cell, void* unused) {
    Cell* before;
    Cell* after;

    (void)unused;
    before = NULL;
    after = list;
    while (after != NULL) {
        if (cell <= after) {
            break;
        }
        before = after;
        after = after->next;
    }

    cell->next = after;
    cell->prev = before;
    if (after != NULL) {
        after->prev = cell;
        if ((u8*)cell + cell->size == (u8*)after) {
            cell->size += after->size;
            after = after->next;
            cell->next = after;
            if (after != NULL) {
                after->prev = cell;
            }
        }
    }

    if (before != NULL) {
        before->next = cell;
        if ((u8*)before + before->size == (u8*)cell) {
            before->size += cell->size;
            before->next = after;
            if (after != NULL) {
                after->prev = before;
            }
        }
        return list;
    }
    return cell;
}

void* OSAllocFromHeap(int heap, u32 size) {
    HeapDesc* hd;
    Cell* cell;
    s32 sizeAligned;
    u32 leftoverSpace;

    hd = &HeapArray[heap];
    sizeAligned = (size + ALIGNMENT + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);

    for (cell = hd->free; cell != NULL; cell = cell->next) {
        if (sizeAligned <= cell->size) {
            break;
        }
    }

    if (cell == NULL) {
        return NULL;
    }

    leftoverSpace = cell->size - sizeAligned;
    if (leftoverSpace < MINOBJSIZE) {
        hd->free = DLExtract(hd->free, cell);
    } else {
        Cell* newCell;

        newCell = (void*)((u8*)cell + sizeAligned);
        cell->size = sizeAligned;
        newCell->size = leftoverSpace;
        newCell->prev = cell->prev;
        newCell->next = cell->next;
        if (newCell->next != NULL) {
            newCell->next->prev = newCell;
        }
        if (newCell->prev != NULL) {
            newCell->prev->next = newCell;
        } else {
            hd->free = newCell;
        }
    }

    hd->allocated = DLAddFront(hd->allocated, cell);
    return (u8*)cell + ALIGNMENT;
}

void OSFreeToHeap(int heap, void* ptr) {
    Cell* cell;
    HeapDesc* hd;
    Cell* list;

    cell = (void*)((u8*)ptr - ALIGNMENT);
    hd = &HeapArray[heap];
    list = hd->allocated;

    if (cell->next != NULL) {
        cell->next->prev = cell->prev;
    }
    if (cell->prev == NULL) {
        list = cell->next;
    } else {
        cell->prev->next = cell->next;
    }

    hd->allocated = list;
    hd->free = DLInsert(hd->free, cell, list);
}

int OSSetCurrentHeap(int heap) {
    int old;

    old = __OSCurrHeap;
    __OSCurrHeap = heap;
    return old;
}

void* OSInitAlloc(void* arenaStart, void* arenaEnd, int maxHeaps) {
    u32 totalSize;
    int i;

    totalSize = maxHeaps * sizeof(HeapDesc);
    HeapArray = arenaStart;
    NumHeaps = maxHeaps;

    for (i = 0; i < NumHeaps; i++) {
        HeapDesc* hd;

        hd = &HeapArray[i];
        hd->size = -1;
        hd->free = hd->allocated = NULL;
    }

    __OSCurrHeap = -1;

    arenaStart = (u8*)HeapArray + totalSize;
    arenaStart = (void*)(((u32)arenaStart + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1));
    ArenaStart = arenaStart;
    ArenaEnd = (void*)((u32)arenaEnd & ~(ALIGNMENT - 1));
    return arenaStart;
}

int OSCreateHeap(void* start, void* end) {
    int i;
    Cell* cell;

    cell = (void*)(((u32)start + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1));
    end = (void*)((u32)end & ~(ALIGNMENT - 1));

    for (i = 0; i < NumHeaps; i++) {
        HeapDesc* hd;

        hd = &HeapArray[i];
        if (hd->size < 0) {
            hd->size = (u8*)end - (u8*)cell;
            cell->prev = NULL;
            cell->next = NULL;
            cell->size = hd->size;
            hd->free = cell;
            hd->allocated = NULL;
            return i;
        }
    }

    return -1;
}
