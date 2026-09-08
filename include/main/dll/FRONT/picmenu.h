#ifndef MAIN_DLL_FRONT_PICMENU_H_
#define MAIN_DLL_FRONT_PICMENU_H_

#include "dolphin/os.h"
#include "dolphin/dvd.h"
#include "main/thp_video_decode.h"

BOOL movieLoad(const char* fileName, void* param2);
void AttractMovieAudio_Shutdown(void);
BOOL AttractMovieAudio_Init(int audioMode);
void PushReadedBuffer2(OSMessage msg);
OSMessage PopReadedBuffer2(void);
void PushFreeReadBuffer(OSMessage msg);
OSMessage PopReadedBuffer(void);
void ReadThreadCancel(void);
void ReadThreadStart(void);
BOOL CreateReadThread(OSPriority priority);

#endif /* MAIN_DLL_FRONT_PICMENU_H_ */
