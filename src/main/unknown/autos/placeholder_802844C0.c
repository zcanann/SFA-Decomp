#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802844C0.h"
#include "dolphin/os/OSCache.h"

extern void aramUploadData(void *src, void *dst, u32 size, int mode, int callback,
                           int callbackArg);

extern u8 lbl_803D3F60[];
extern u8 lbl_803D4468[];
extern u32 aramTop;
extern u32 aramWrite;
extern u32 aramStream;
extern void *(*aramChunkCallback)(void *src, u32 chunk);
extern u32 aramChunkSize;
extern u32 aramQueueWrite;
extern u32 aramQueueValid;
extern void *aramStreamFreeList;

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

    if (aramChunkCallback == NULL) {
        DCFlushRange(src, alignedSize);
        aramUploadData(src, (void *)aramWrite, alignedSize, 0, 0, 0);
        aramWrite += alignedSize;
        return startPos;
    }

    while (alignedSize != 0) {
        u32 chunk = aramChunkSize;
        void *piece;
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
 * Initialize the 64-element doubly-linked free list at lbl_803D3F60.
 * Layout: 0x80-byte stride, with each entry's "next" at +0 and the
 * unrolled body sets up 8 entries per outer iteration.
 *
 * EN v1.1 Address: 0x80284570
 * EN v1.1 Size: 196b
 */
void aramInitStreamBuffers(void)
{
    u8 *base = lbl_803D3F60;
    int i;

    aramQueueWrite = 0;
    aramQueueValid = 0;
    aramStreamFreeList = base + 0x508;

    for (i = 1; i < 64; i++) {
        u8 *node = base + i * 0x10 + 0x508;
        *(u8 **)(node - 0x10) = node;
    }
    *(u32 *)(base + i * 0x10 + 0x4f8) = 0;
    aramStream = aramTop;
}

void fn_80284634(void)
{
}

/*
 * Look up entry at lbl_803D4468[idx*16]; if outPos != NULL, store
 * the entry's offset-8 word; return the entry's offset-4 word.
 *
 * EN v1.1 Address: 0x80284638
 * EN v1.1 Size: 56b
 */
u32 aramGetStreamBufferAddress(u8 idx, u32 *outPos)
{
    u8 *entry;
    if (outPos != NULL) {
        entry = lbl_803D4468 + idx * 16;
        *outPos = *(u32 *)(entry + 8);
    }
    entry = lbl_803D4468 + idx * 16;
    return *(u32 *)(entry + 4);
}
