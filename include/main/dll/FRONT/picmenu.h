#ifndef MAIN_DLL_FRONT_PICMENU_H_
#define MAIN_DLL_FRONT_PICMENU_H_

#include "dolphin/os.h"
#include "dolphin/dvd.h"
#include "dolphin/thp/THPPlayer.h"

BOOL movieLoad(const char* fileName, void* param2);
void AttractMovieAudio_Shutdown(void);
BOOL AttractMovieAudio_Init(int audioMode);
void PushReadedBuffer2(OSMessage msg);
OSMessage PopReadedBuffer2(void);
void PushFreeReadBuffer(OSMessage msg);
OSMessage PopReadedBuffer(void);
void THPRead_Reader(void);
void ReadThreadCancel(void);
void ReadThreadStart(void);
BOOL CreateReadThread(OSPriority priority);
OSMessage PopDecodedTextureSet(s32 flags);
void PushFreeTextureSet(OSMessage msg);
void AttractMovieVideo_Decode(void* param);
void AttractMovieVideo_DecoderForOnMemory(void* param);
void AttractMovieVideo_Decoder(void);
void VideoDecodeThreadCancel(void);
void VideoDecodeThreadStart(void);
BOOL CreateVideoDecodeThread(int param_1, int param_2);

#endif /* MAIN_DLL_FRONT_PICMENU_H_ */
