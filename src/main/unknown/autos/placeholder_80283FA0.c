#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283FA0.h"
#include "dolphin/os.h"

extern void ARQPostRequest(void *req, u32 owner, u32 type, u32 prio, u32 src, u32 dst, u32 size, void (*cb)(void *));

extern u8 lbl_803D3F60[];
extern u8 lbl_803D41E4[];

typedef struct AramQueueSlot {
    u32 request;
    u32 owner;
    u32 type;
    u32 priority;
    u32 src;
    u32 dst;
    u32 size;
    void (*arqCallback)(void *);
    void (*callback)(void *);
    void *callbackArg;
} AramQueueSlot;

typedef struct AramTransferQueue {
    AramQueueSlot slots[16];
    volatile u8 head;
    volatile u8 count;
} AramTransferQueue;

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
#pragma scheduling off
void aramQueueCallback(void *req)
{
    AramTransferQueue *queue;
    AramQueueSlot *slot;
    AramQueueSlot *callbackSlot;
    u32 i;

    queue = (*(u32 *)((u8 *)req + 0xc) == 1) ? (AramTransferQueue *)lbl_803D41E4 : (AramTransferQueue *)lbl_803D3F60;
    i = 0;
    callbackSlot = &queue->slots[i];
    slot = queue->slots;
    for (; i < 0x10; i++) {
        if (req == slot) {
            void (*cb)(void *) = slot->callback;
            if (cb != NULL) {
                cb(callbackSlot->callbackArg);
            }
        }
        slot++;
        callbackSlot++;
    }
    queue->count = queue->count - 1;
}
#pragma scheduling reset

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
    AramTransferQueue *queue;
    BOOL irq;

    queue = (mode != 0) ? (AramTransferQueue *)lbl_803D41E4 : (AramTransferQueue *)lbl_803D3F60;

    while (1) {
        irq = OSDisableInterrupts();
        if (queue->count < 0x10) {
            queue->slots[queue->head].owner = 0x2a;
            queue->slots[queue->head].type = 0;
            queue->slots[queue->head].priority = (mode != 0) ? 1 : 0;
            queue->slots[queue->head].src = src;
            queue->slots[queue->head].dst = dst;
            queue->slots[queue->head].size = size;
            queue->slots[queue->head].arqCallback = aramQueueCallback;
            queue->slots[queue->head].callback = (void (*)(void *))callback;
            queue->slots[queue->head].callbackArg = (void *)callbackArg;
            ARQPostRequest(&queue->slots[queue->head],
                           queue->slots[queue->head].owner,
                           queue->slots[queue->head].type,
                           queue->slots[queue->head].priority,
                           queue->slots[queue->head].src,
                           queue->slots[queue->head].dst,
                           queue->slots[queue->head].size,
                           queue->slots[queue->head].arqCallback);
            queue->count += 1;
            queue->head = (queue->head + 1) % 0x10;
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
    while (((volatile u8 *)lbl_803D3F60)[0x281] != 0) {
    }
}
