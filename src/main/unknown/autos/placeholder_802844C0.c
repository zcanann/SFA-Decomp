#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802844C0.h"
#include "dolphin/os/OSCache.h"

extern void aramUploadData(void *src, void *dst, u32 size, int mode, int callback,
                           int callbackArg);

typedef struct AramStreamBufferEntry {
    struct AramStreamBufferEntry *next;
    u32 address;
    u32 position;
    u32 state;
} AramStreamBufferEntry;

extern u8 lbl_803D3F60[];
extern u32 aramTop;
extern u32 aramWrite;
extern u32 aramStream;
extern void *(*aramChunkCallback)(void *src, u32 chunk);
extern u32 aramChunkSize;
extern u32 aramQueueWrite;
extern u32 aramQueueValid;
extern AramStreamBufferEntry *aramStreamFreeList;
extern AramStreamBufferEntry lbl_803D4468[];

/*
 * Allocate+DMA: copies `size` bytes from `src` into the audio
 * memory pool, returning the pre-write cursor. With a registered
 * chunking callback, copies in pieces of at most aramChunkSize bytes.
 *
 * EN v1.0 Address: 0x80284468
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802844C0
 * EN v1.1 Size: 240b
 */
u32 aramStoreData(void *src, u32 size)
{
    u32 alignedSize = (size + 0x1f) & ~0x1f;
    u32 startPos = aramWrite;
    void *piece;
    u32 chunk;

    if (aramChunkCallback == NULL) {
        DCFlushRange(src, alignedSize);
        aramUploadData(src, (void *)aramWrite, alignedSize, 0, 0, 0);
        aramWrite += alignedSize;
        return startPos;
    }

    while (alignedSize != 0) {
        chunk = aramChunkSize;
        if (alignedSize < chunk) {
            chunk = alignedSize;
        }
        piece = aramChunkCallback(src, chunk);
        DCFlushRange(piece, chunk);
        aramUploadData(piece, (void *)aramWrite, chunk, 0, 0, 0);
        alignedSize -= chunk;
        src = (u8 *)src + chunk;
        aramWrite += chunk;
    }
    return startPos;
}

/*
 * Rewind cursor by aligned size.
 *
 * EN v1.1 Address: 0x80284558
 * EN v1.1 Size: 24b
 */
void aramRemoveData(void *unused, u32 size)
{
    u32 aligned = (size + 0x1f) & ~0x1f;
    aramWrite -= aligned;
}

/*
 * Initialize the 64-element stream-buffer free list at lbl_803D4468.
 * The allocator uses the first word of each 0x10-byte entry as the next
 * pointer, and the setup loop links eight entries per iteration.
 *
 * EN v1.1 Address: 0x80284570
 * EN v1.1 Size: 196b
 */
void aramInitStreamBuffers(void)
{
    u8 *base = lbl_803D3F60;
    AramStreamBufferEntry *buffers = (AramStreamBufferEntry *)(base + 0x508);
    AramStreamBufferEntry *node;
    int i;

    aramQueueWrite = 0;
    aramQueueValid = 0;
    aramStreamFreeList = buffers;

    node = &buffers[1];
    for (i = 1; i < 57; i += 8) {
        node[-1].next = node;
        node[0].next = node + 1;
        node[1].next = node + 2;
        node[2].next = node + 3;
        node[3].next = node + 4;
        node[4].next = node + 5;
        node[5].next = node + 6;
        node[6].next = node + 7;
        node += 8;
    }

tail_loop:
    if (i < 64) {
        node[-1].next = node;
        node++;
        i++;
        goto tail_loop;
    }
    buffers[i - 1].next = NULL;
    aramStream = aramTop;
}

void fn_80284634(void)
{
}

/*
 * Look up stream-buffer metadata; if outPos != NULL, store the current
 * position, and return the ARAM address.
 *
 * EN v1.1 Address: 0x80284638
 * EN v1.1 Size: 56b
 */
u32 aramGetStreamBufferAddress(u8 idx, u32 *outPos)
{
    if (outPos != NULL) {
        *outPos = lbl_803D4468[idx].position;
    }
    return lbl_803D4468[idx].address;
}
