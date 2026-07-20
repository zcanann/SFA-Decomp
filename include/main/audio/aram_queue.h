#ifndef MAIN_AUDIO_ARAM_QUEUE_H_
#define MAIN_AUDIO_ARAM_QUEUE_H_

#include "global.h"
#include "dolphin/ar.h"

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
    AramQueueSlot slots[16];
    volatile u8 head;
    volatile u8 count;
    u8 pad282[2];
} AramTransferQueue;

STATIC_ASSERT(offsetof(AramTransferQueue, head) == 0x280);
STATIC_ASSERT(offsetof(AramTransferQueue, count) == 0x281);
STATIC_ASSERT(sizeof(AramTransferQueue) == 0x284);

void aramQueueCallback(u32 requestAddress);
void aramUploadData(void *src, u32 dst, u32 size, u32 mode,
                    void (*callback)(u32), u32 callbackArg);
void aramSyncTransferQueue(void);

#endif /* MAIN_AUDIO_ARAM_QUEUE_H_ */
