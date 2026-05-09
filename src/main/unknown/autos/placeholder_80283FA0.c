#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283FA0.h"
#include "dolphin/os.h"

extern void ARQPostRequest(void *req, u32 owner, u32 type, u32 prio, u32 src, u32 dst, u32 size, void (*cb)(void *));

extern u8 lbl_803D3F60[];
extern u8 lbl_803D41E4[];

/*
 * ARQ DMA completion callback dispatcher: walks the 16-slot ring
 * queue at lbl_803D3F60 (or lbl_803D41E4 for the secondary pool)
 * and invokes any pending entry's callback whose request handle
 * matches `req`. Decrements the count when done.
 *
 * EN v1.0 Address: 0x80283FA0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283FA0
 * EN v1.1 Size: 152b
 */
void aramQueueCallback(void *req)
{
    u8 *base;
    u8 *slot;
    int i;

    if (*(u32 *)((u8 *)req + 0xc) == 1) {
        base = lbl_803D41E4;
    } else {
        base = lbl_803D3F60;
    }
    slot = base;
    for (i = 0; i < 0x10; i++) {
        if (req == slot) {
            void (*cb)(void *) = *(void (**)(void *))(slot + 0x20);
            if (cb != NULL) {
                cb(*(void **)(slot + 0x24));
            }
        }
        slot += 0x28;
    }
    base[0x281] = base[0x281] - 1;
}

/*
 * Submit an ARQ DMA request: locks interrupts, finds the next free
 * slot in the 16-entry ring, fills in the request fields, calls
 * ARQPostRequest, then bumps the head/count and restores interrupts.
 * If the queue is full, just unlocks and retries (busy-loop).
 *
 * EN v1.0 Address: 0x8028401C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80284038
 * EN v1.1 Size: 464b
 */
void aramUploadData(u32 src, u32 dst, u32 size, u32 mode, u32 callback, u32 callbackArg)
{
    u8 *base;
    u8 *slot;
    BOOL irq;

    if (mode != 0) {
        base = lbl_803D41E4;
    } else {
        base = lbl_803D3F60;
    }

    while (1) {
        irq = OSDisableInterrupts();
        if (base[0x281] < 0x10) {
            slot = base + base[0x280] * 0x28;
            *(u32 *)(slot + 0x4) = 0x2a;
            *(u32 *)(slot + 0x8) = 0;
            *(u32 *)(slot + 0xc) = (mode != 0) ? 1 : 0;
            *(u32 *)(slot + 0x10) = src;
            *(u32 *)(slot + 0x14) = dst;
            *(u32 *)(slot + 0x18) = size;
            *(u32 *)(slot + 0x1c) = (u32)aramQueueCallback;
            *(u32 *)(slot + 0x20) = callback;
            *(u32 *)(slot + 0x24) = callbackArg;
            ARQPostRequest((void *)(base + base[0x280] * 0x28),
                           *(u32 *)(base + base[0x280] * 0x28 + 0x4),
                           *(u32 *)(base + base[0x280] * 0x28 + 0x8),
                           *(u32 *)(base + base[0x280] * 0x28 + 0xc),
                           *(u32 *)(base + base[0x280] * 0x28 + 0x10),
                           *(u32 *)(base + base[0x280] * 0x28 + 0x14),
                           *(u32 *)(base + base[0x280] * 0x28 + 0x18),
                           *(void (**)(void *))(base + base[0x280] * 0x28 + 0x1c));
            base[0x281] += 1;
            base[0x280] = (base[0x280] + 1) & 0xf;
            OSRestoreInterrupts(irq);
            return;
        }
        OSRestoreInterrupts(irq);
    }
}

/*
 * Wait until ARQ count drops to zero.
 *
 * EN v1.1 Address: 0x8028420C
 * EN v1.1 Size: 20b
 */
void aramSyncTransferQueue(void)
{
    while (lbl_803D3F60[0x281] != 0) {
    }
}
