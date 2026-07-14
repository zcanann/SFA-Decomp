#include "ghidra_import.h"

#pragma exceptions on
typedef struct AramStreamBufferEntry
{
    struct AramStreamBufferEntry* next;
    u32 address;
    u32 position;
    u32 state;
} AramStreamBufferEntry;

typedef struct AramStreamBufferTable
{
    AramStreamBufferEntry entries[65];
    u8 reserved[8];
} AramStreamBufferTable;

extern u8 lbl_803D3F60[];
extern u32 aramTop;
extern u32 aramWrite;
extern u32 aramStream;
extern void* (*aramChunkCallback)(void* src, u32 chunk);
extern u32 aramChunkSize;
extern u32 aramQueueWrite;
extern u32 aramQueueValid;
extern AramStreamBufferEntry* aramStreamFreeList;
extern AramStreamBufferTable lbl_803D4468;

/*
 * Allocate+DMA: copies `size` bytes from `src` into the audio
 * memory pool, returning the pre-write cursor. With a registered
 * chunking callback, copies in pieces of at most aramChunkSize bytes.
 */
u32 aramStoreData(void* src, u32 size)
{
    u32 chunk;
    u32 startPos;
    void* piece;
    u32 alignedSize;

    alignedSize = (size + 0x1f) & ~0x1f;
    startPos = aramWrite;

    if (aramChunkCallback == NULL)
    {
        DCFlushRange(src, alignedSize);
        aramUploadData((u32)src, aramWrite, alignedSize, 0, 0, 0);
        aramWrite += alignedSize;
        return startPos;
    }

    while (alignedSize != 0)
    {
        chunk = (alignedSize >= aramChunkSize) ? aramChunkSize : alignedSize;
        piece = aramChunkCallback(src, chunk);
        DCFlushRange(piece, chunk);
        aramUploadData((u32)piece, aramWrite, chunk, 0, 0, 0);
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
 * Initialize the 64-element stream-buffer free list at lbl_803D4468.
 * The allocator uses the first word of each 0x10-byte entry as the next
 * pointer, and the setup loop links eight entries per iteration.
 */
void aramInitStreamBuffers(void)
{
    u8* base = lbl_803D3F60;
    AramStreamBufferEntry* buffers;
    u32 i;

    aramQueueWrite = 0;
    aramQueueValid = 0;
    buffers = (AramStreamBufferEntry*)(base + 0x508);
    aramStreamFreeList = buffers;

    for (i = 1; i < 64; i++)
    {
        ((AramStreamBufferEntry*)(base + 0x508))[i - 1].next = &((AramStreamBufferEntry*)(base + 0x508))[i];
    }
    ((AramStreamBufferEntry*)(base + 0x508))[i - 1].next = NULL;
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
        *outPos = lbl_803D4468.entries[idx].position;
    }
    return lbl_803D4468.entries[idx].address;
}

AramStreamBufferTable lbl_803D4468;
