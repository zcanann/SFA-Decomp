#ifndef MAIN_THP_VIDEO_DECODE_H_
#define MAIN_THP_VIDEO_DECODE_H_

#include "global.h"
#include "dolphin/os/OSMessage.h"
#include "dolphin/os/OSThread.h"

#define THP_VIDEO_BUFFER_COUNT 3
#define THP_VIDEO_STACK_SIZE   0x1000

typedef struct AttractMovieVideoMessageStorage {
    OSMessage decoded[THP_VIDEO_BUFFER_COUNT];
    OSMessage free[THP_VIDEO_BUFFER_COUNT];
} AttractMovieVideoMessageStorage;

STATIC_ASSERT(sizeof(AttractMovieVideoMessageStorage) == 0x18);
STATIC_ASSERT(offsetof(AttractMovieVideoMessageStorage, decoded) == 0);
STATIC_ASSERT(offsetof(AttractMovieVideoMessageStorage, free) == 0xC);

OSMessage PopDecodedTextureSet(s32 flags);
void PushFreeTextureSet(OSMessage msg);
void VideoDecodeThreadCancel(void);
void VideoDecodeThreadStart(void);
BOOL CreateVideoDecodeThread(OSPriority priority, void* onMemoryData);

#endif /* MAIN_THP_VIDEO_DECODE_H_ */
