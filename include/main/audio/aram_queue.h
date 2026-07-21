#ifndef MAIN_AUDIO_ARAM_QUEUE_H_
#define MAIN_AUDIO_ARAM_QUEUE_H_

#include "global.h"
#include "dolphin/ar.h"

#define ARAM_TRANSFER_QUEUE_CAPACITY 16

typedef struct AramQueueSlot
{
    ARQRequest request;
    void (*completionCallback)(u32);
    u32 callbackArg;
} AramQueueSlot;

STATIC_ASSERT(sizeof(AramQueueSlot) == 0x28);
STATIC_ASSERT(offsetof(AramQueueSlot, completionCallback) == 0x20);
STATIC_ASSERT(offsetof(AramQueueSlot, callbackArg) == 0x24);

typedef struct AramTransferQueue
{
    AramQueueSlot slots[ARAM_TRANSFER_QUEUE_CAPACITY];
    volatile u8 head;
    volatile u8 count;
    u8 pad282[2];
} AramTransferQueue;

STATIC_ASSERT(offsetof(AramTransferQueue, head) == 0x280);
STATIC_ASSERT(offsetof(AramTransferQueue, count) == 0x281);
STATIC_ASSERT(sizeof(AramTransferQueue) == 0x284);

typedef struct AramTransferQueues
{
    AramTransferQueue normalPriority;
    AramTransferQueue highPriority;
} AramTransferQueues;

STATIC_ASSERT(offsetof(AramTransferQueues, highPriority) == 0x284);
STATIC_ASSERT(sizeof(AramTransferQueues) == 0x508);

void aramQueueCallback(u32 requestAddress);
void aramUploadData(void *src, u32 dst, u32 size, u32 mode,
                    void (*callback)(u32), u32 callbackArg);
void aramSyncTransferQueue(void);

#endif /* MAIN_AUDIO_ARAM_QUEUE_H_ */
