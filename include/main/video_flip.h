#ifndef MAIN_VIDEO_FLIP_H_
#define MAIN_VIDEO_FLIP_H_

#include "dolphin/os/OSThread.h"
#include "main/model_engine.h"

#define VIDEO_FLIP_QUEUE_CAPACITY 10

typedef struct VideoFlipToken {
    void* fifoWritePointer;
    u32 reserved; /* Written as zero; no reader identified. */
    void* frameBuffer;
} VideoFlipToken;

STATIC_ASSERT(sizeof(VideoFlipToken) == 0xC);
STATIC_ASSERT(offsetof(VideoFlipToken, fifoWritePointer) == 0x0);
STATIC_ASSERT(offsetof(VideoFlipToken, reserved) == 0x4);
STATIC_ASSERT(offsetof(VideoFlipToken, frameBuffer) == 0x8);

extern OSThreadQueue gVideoFlipWaitQueue;
extern RingBufferQueue gVideoFlipQueue;
extern VideoFlipToken gVideoFlipQueueBuffer[VIDEO_FLIP_QUEUE_CAPACITY];

#endif /* MAIN_VIDEO_FLIP_H_ */
