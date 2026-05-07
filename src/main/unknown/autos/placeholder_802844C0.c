#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802844C0.h"
#include "dolphin/os/OSCache.h"

extern int aramUploadData(void *src, void *dst, u32 size, int p4, int p5, int p6);

extern u8 lbl_803D3F60[];
extern u8 lbl_803D4468[];
extern u32 lbl_803DE380;
extern u32 lbl_803DE384;
extern u32 lbl_803DE388;
extern void *(*lbl_803DE38C)(void *src, u32 chunk);
extern u32 lbl_803DE390;
extern u32 lbl_803DE394;
extern u32 lbl_803DE398;
extern void *lbl_803DE39C;

/*
 * Allocate+DMA: copies `size` bytes from `src` into the audio
 * memory pool, returning the pre-write cursor. With a registered
 * chunking callback (lbl_803DE38C), copies in pieces of at most
 * lbl_803DE390 bytes per call.
 *
 * EN v1.0 Address: 0x80284468
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802844C0
 * EN v1.1 Size: 240b
 */
u32 aramStoreData(void *src, u32 size)
{
    u32 alignedSize = (size + 0x1f) & ~0x1f;
    u32 startPos = lbl_803DE384;

    if (lbl_803DE38C == NULL) {
        DCFlushRange(src, alignedSize);
        aramUploadData(src, (void *)lbl_803DE384, alignedSize, 0, 0, 0);
        lbl_803DE384 += alignedSize;
        return startPos;
    }

    while (alignedSize != 0) {
        u32 chunk = lbl_803DE390;
        void *piece;
        if (alignedSize < chunk) {
            chunk = alignedSize;
        }
        piece = lbl_803DE38C(src, chunk);
        DCFlushRange(piece, chunk);
        aramUploadData(piece, (void *)lbl_803DE384, chunk, 0, 0, 0);
        alignedSize -= chunk;
        src = (u8 *)src + chunk;
        lbl_803DE384 += chunk;
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
    lbl_803DE384 -= aligned;
}

/*
 * Initialize the 64-element doubly-linked free list at lbl_803D3F60.
 * Layout: 0x80-byte stride, with each entry's "next" at +0 and the
 * unrolled body sets up 8 entries per outer iteration.
 *
 * EN v1.1 Address: 0x80284570
 * EN v1.1 Size: 196b
 */
void InitStreamBuffers(void)
{
    u8 *base = lbl_803D3F60;
    int i;

    lbl_803DE394 = 0;
    lbl_803DE398 = 0;
    lbl_803DE39C = base + 0x508;

    for (i = 1; i < 64; i++) {
        u8 *node = base + i * 0x10 + 0x508;
        *(u8 **)(node - 0x10) = node;
    }
    *(u32 *)(base + i * 0x10 + 0x4f8) = 0;
    lbl_803DE388 = lbl_803DE380;
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
