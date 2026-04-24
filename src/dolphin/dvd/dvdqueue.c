#include <dolphin.h>
#include <dolphin/dvd.h>

#include "dolphin/dvd/__dvd.h"

typedef struct DVDWaitingQueue {
    /* 0x00 */ DVDCommandBlock* next;
    /* 0x04 */ DVDCommandBlock* prev;
} DVDWaitingQueue;

static DVDWaitingQueue WaitingQueue_803AEC38[4];

static inline DVDCommandBlock* PopWaitingQueuePrio(s32 prio) {
    DVDCommandBlock* tmp;
    BOOL enabled;
    DVDCommandBlock* q;

    enabled = OSDisableInterrupts();
    q = (DVDCommandBlock*)&WaitingQueue_803AEC38[prio];
    tmp = q->next;
    q->next = tmp->next;
    tmp->next->prev = q;
    OSRestoreInterrupts(enabled);
    tmp->next = NULL;
    tmp->prev = NULL;
    return tmp;
}

void __DVDClearWaitingQueue(void) {
    u32 i;
    DVDCommandBlock* q;

    for(i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue_803AEC38[i].next;
        q->next = q;
        q->prev = q;
    }
}

int __DVDPushWaitingQueue(s32 prio, DVDCommandBlock* block) {
    BOOL enabled = OSDisableInterrupts();
    DVDCommandBlock* q = (DVDCommandBlock*)&WaitingQueue_803AEC38[prio];

    q->prev->next = block;
    block->prev = q->prev;
    block->next = q;
    q->prev = block;
    OSRestoreInterrupts(enabled);
    return 1;
}

DVDCommandBlock* __DVDPopWaitingQueue(void) {
    u32 i;
    BOOL enabled;
    DVDCommandBlock* q;

    enabled = OSDisableInterrupts();
    for (i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue_803AEC38[i];
        if (q->next != q) {
            OSRestoreInterrupts(enabled);
            return PopWaitingQueuePrio(i);
        }
    }

    OSRestoreInterrupts(enabled);
    return NULL;
}

int __DVDCheckWaitingQueue(void) {
    u32 i;
    BOOL enabled;
    DVDCommandBlock* q;

    enabled = OSDisableInterrupts();
    for (i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue_803AEC38[i];
        if (q->next != q) {
            OSRestoreInterrupts(enabled);
            return 1;
        }
    }

    OSRestoreInterrupts(enabled);
    return 0;
}

int __DVDDequeueWaitingQueue(DVDCommandBlock* block) {
    BOOL enabled;
    DVDCommandBlock* prev;
    DVDCommandBlock* next;

    enabled = OSDisableInterrupts();
    prev = block->prev;
    next = block->next;
    if (prev == NULL || next == NULL) {
        OSRestoreInterrupts(enabled);
        return 0;
    }
    prev->next = next;
    next->prev = prev;
    OSRestoreInterrupts(enabled);
    return 1;
}
