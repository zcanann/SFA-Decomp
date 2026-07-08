#ifndef MAIN_AUDIO_ARAM_QUEUE_H_
#define MAIN_AUDIO_ARAM_QUEUE_H_

#include "ghidra_import.h"

typedef struct AramQueueSlot
{
    u32 request;
    u32 owner;
    u32 type;
    u32 priority;
    u32 src;
    u32 dst;
    u32 size;
    void (*arqCallback)(void*);
    void (*callback)(void*);
    void* callbackArg;
} AramQueueSlot;

typedef struct AramTransferQueue
{
    AramQueueSlot slots[16];
    volatile u8 head;
    volatile u8 count;
} AramTransferQueue;

void aramQueueCallback(void* req);
void aramUploadData(u32 src, u32 dst, u32 size, u32 mode, u32 callback, u32 callbackArg);
void aramSyncTransferQueue(void);

#endif /* MAIN_AUDIO_ARAM_QUEUE_H_ */
