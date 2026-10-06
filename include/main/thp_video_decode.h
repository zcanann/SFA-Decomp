#ifndef MAIN_THP_VIDEO_DECODE_H_
#define MAIN_THP_VIDEO_DECODE_H_

#include "global.h"
#include "dolphin/os/OSMessage.h"
#include "dolphin/os/OSThread.h"

OSMessage PopDecodedTextureSet(s32 flags);
void PushFreeTextureSet(OSMessage msg);
void VideoDecodeThreadCancel(void);
void VideoDecodeThreadStart(void);
BOOL CreateVideoDecodeThread(OSPriority priority, void* onMemoryData);

#endif /* MAIN_THP_VIDEO_DECODE_H_ */
