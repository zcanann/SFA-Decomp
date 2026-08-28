#include "musyx/aram.h"
#include "musyx/aram_queue.h"
#include "dolphin/os/OSCache.h"

typedef struct AramStreamBufferEntry
{
    struct AramStreamBufferEntry* next;
    u32 address;
    u32 position;
    u32 state;
} AramStreamBufferEntry;

#define ARAM_STREAM_BUFFER_COUNT 64

STATIC_ASSERT(sizeof(AramStreamBufferEntry) == 0x10);

typedef struct AramRuntimeStorage {
    AramTransferQueues transferQueues;
    AramStreamBufferEntry streamBuffers[ARAM_STREAM_BUFFER_COUNT];
} AramRuntimeStorage;

STATIC_ASSERT(offsetof(AramRuntimeStorage, streamBuffers) == 0x508);

extern AramTransferQueues aramNormalPriorityQueue;


AramStreamBufferEntry* aramStreamFreeList;
u32 aramQueueValid;
u32 aramQueueWrite;
u32 aramUploadChunkSize;
AramUploadCallback aramUploadCallback;
u32 aramStream;
extern AramStreamBufferEntry aramStreamBuffers[ARAM_STREAM_BUFFER_COUNT];

/*
 * Allocate+DMA: copies `size` bytes from `src` into the audio
 * memory pool, returning the pre-write cursor. With a registered
 * chunking callback, copies in pieces of at most aramUploadChunkSize bytes.
 */
u32 aramStoreData(void* src, u32 size)
{
    u32 chunk;
    u32 startPos;
    void* piece;
    u32 alignedSize;

    alignedSize = (size + 0x1f) & ~0x1f;
    startPos = aramWrite;

    if (aramUploadCallback == NULL)
    {
        DCFlushRange(src, alignedSize);
        aramUploadData(src, aramWrite, alignedSize, 0, 0, 0);
        aramWrite += alignedSize;
        return startPos;
    }

    while (alignedSize != 0)
    {
        chunk = (alignedSize >= aramUploadChunkSize) ? aramUploadChunkSize : alignedSize;
        piece = aramUploadCallback((u32)src, chunk);
        DCFlushRange(piece, chunk);
        aramUploadData(piece, aramWrite, chunk, 0, 0, 0);
        alignedSize -= chunk;
        src = (u8*)src + chunk;
        aramWrite += chunk;
    }
    return startPos;
}

/*
 * Rewind cursor by aligned size.
 */
void aramRemoveData(void* unused, u32 size)
{
    u32 aligned = (size + 0x1f) & ~0x1f;
    aramWrite -= aligned;
}

/*
 * Initialize the 64-element stream-buffer free list at aramStreamBuffers.
 * The allocator uses the first word of each 0x10-byte entry as the next
 * pointer, and the setup loop links eight entries per iteration.
 */
void aramInitStreamBuffers(void)
{
    u8* base = (u8*)&aramNormalPriorityQueue;
    AramStreamBufferEntry* buffers;
    u32 i;

    aramQueueWrite = 0;
    aramQueueValid = 0;
    buffers = (AramStreamBufferEntry*)(base + offsetof(AramRuntimeStorage, streamBuffers));
    aramStreamFreeList = buffers;

    for (i = 1; i < ARAM_STREAM_BUFFER_COUNT; i++)
    {
        ((AramStreamBufferEntry*)(base + offsetof(AramRuntimeStorage, streamBuffers)))[i - 1].next =
            &((AramStreamBufferEntry*)(base + offsetof(AramRuntimeStorage, streamBuffers)))[i];
    }
    ((AramStreamBufferEntry*)(base + offsetof(AramRuntimeStorage, streamBuffers)))[i - 1].next = NULL;
    aramStream = aramTop;
}

/*
 * Look up stream-buffer metadata; if outPos != NULL, store the current
 * position, and return the ARAM address.
 */
u32 aramGetStreamBufferAddress(u8 idx, u32* outPos)
{
    if (outPos != NULL)
    {
        *outPos = aramStreamBuffers[idx].position;
    }
    return aramStreamBuffers[idx].address;
}

u8 lbl_803D4868[0x18];
AramStreamBufferEntry aramStreamBuffers[ARAM_STREAM_BUFFER_COUNT];
