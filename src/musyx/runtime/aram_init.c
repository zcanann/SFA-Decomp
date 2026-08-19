#include "musyx/aram.h"
#include "musyx/aram_queue.h"
#include "musyx/sal_dsp.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/ar.h"

extern AramTransferQueues aramNormalPriorityQueue;

u32 aramWrite;
u32 aramTop;

/*
 * Initializes the AR-side audio data buffer: allocates a 0x500-byte
 * scratch buffer in main RAM, zeroes it (640 halfwords = 1280 bytes),
 * DMAs it to AR memory at the base address, then sets up the global
 * allocator pointers.
 */
void aramInit(u32 extraSize)
{
    AramTransferQueues* queues;
    volatile u8* pendingCount;
    u16* clear;
    u8* buf;
    u32 arBase;
    int i;

    queues = &aramNormalPriorityQueue;
    arBase = ARGetBaseAddress();
    buf = salMalloc(0x500);
    clear = (u16*)buf;
    for (i = 0; i < 640; i++)
    {
        clear[i] = 0;
    }
    DCFlushRange(buf, 0x500);
    *(pendingCount = &queues->normalPriority.count) = 0;
    queues->normalPriority.head = 0;
    queues->highPriority.count = 0;
    queues->highPriority.head = 0;
    aramUploadData(buf, arBase, 0x500, 0, 0, 0);
    while (*pendingCount != 0)
    {
    }
    salFree(buf);
    aramTop = arBase + extraSize;
    if (aramTop > ARGetSize())
    {
        aramTop = ARGetSize();
    }
    aramWrite = arBase + 0x500;
    aramUploadCallback = NULL;
    aramInitStreamBuffers();
}

/*
 * Empty stub (4 bytes: just blr).
 */
void aramExit(void)
{
}

/*
 * Returns AR base address.
 */
u32 aramGetBaseAddress(void)
{
    return ARGetBaseAddress();
}

AramTransferQueue aramHighPriorityQueue;
