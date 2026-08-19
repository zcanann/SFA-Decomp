#include "musyx/aram_queue.h"
#include "dolphin/os/OSInterrupt.h"


AramTransferQueue aramNormalPriorityQueue;

/*
 * ARQ DMA completion callback dispatcher: walks the 16-slot ring
 * queue at aramNormalPriorityQueue (or aramHighPriorityQueue for
 * high-priority requests)
 * and invokes any pending entry's callback whose request handle
 * matches `req`. Decrements the count when done.
 */
static void aramQueueCallback(u32 requestAddress)
{
    ARQRequest* request;
    AramTransferQueue* queue;
    u32 i;

    request = (ARQRequest*)requestAddress;
    queue = (request->priority == ARQ_PRIORITY_HIGH) ? &aramHighPriorityQueue : &aramNormalPriorityQueue;
    for (i = 0; i < ARAM_TRANSFER_QUEUE_CAPACITY; i++)
    {
        if (request == &queue->slots[i].request && queue->slots[i].completionCallback != NULL)
        {
            queue->slots[i].completionCallback(queue->slots[i].callbackArg);
        }
    }
    queue->count = queue->count - 1;
}

/*
 * Submit an ARQ DMA request: locks interrupts, finds the next free
 * slot in the 16-entry ring, fills in the request fields, calls
 * ARQPostRequest, then bumps the head/count and restores interrupts.
 * If the queue is full, just unlocks and retries (busy-loop).
 */
void aramUploadData(void* src, u32 dst, u32 size, u32 mode, void (*callback)(u32), u32 callbackArg) {
    AramTransferQueue* queue = mode != 0 ? &aramHighPriorityQueue : &aramNormalPriorityQueue;

    while (1) {
        BOOL irq = OSDisableInterrupts();
        if (queue->count < ARAM_TRANSFER_QUEUE_CAPACITY) {
            queue->slots[queue->head].request.owner = 0x2a;
            queue->slots[queue->head].request.type = ARQ_TYPE_MRAM_TO_ARAM;
            queue->slots[queue->head].request.priority = (mode != 0) ? ARQ_PRIORITY_HIGH : ARQ_PRIORITY_LOW;
            queue->slots[queue->head].request.source = (u32)src;
            queue->slots[queue->head].request.dest = dst;
            queue->slots[queue->head].request.length = size;
            queue->slots[queue->head].request.callback = aramQueueCallback;
            queue->slots[queue->head].completionCallback = callback;
            queue->slots[queue->head].callbackArg = callbackArg;
            ARQPostRequest(&queue->slots[queue->head].request, queue->slots[queue->head].request.owner,
                           queue->slots[queue->head].request.type, queue->slots[queue->head].request.priority,
                           queue->slots[queue->head].request.source, queue->slots[queue->head].request.dest,
                           queue->slots[queue->head].request.length, queue->slots[queue->head].request.callback);
            queue->count += 1;
            queue->head = (queue->head + 1) % ARAM_TRANSFER_QUEUE_CAPACITY;
            OSRestoreInterrupts(irq);
            return;
        }
        OSRestoreInterrupts(irq);
    }
}

/*
 * Wait until ARQ count drops to zero.
 */
void aramSyncTransferQueue(void)
{
    while (aramNormalPriorityQueue.count != 0)
    {
    }
}
