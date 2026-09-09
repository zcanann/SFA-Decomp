#ifndef MAIN_DLL_FRONT_PICMENU_H_
#define MAIN_DLL_FRONT_PICMENU_H_

#include "dolphin/os.h"
#include "dolphin/dvd.h"
#include "main/thp_video_decode.h"
#include "main/thp_read.h"

BOOL movieLoad(const char* fileName, void* param2);
void AttractMovieAudio_Shutdown(void);
BOOL AttractMovieAudio_Init(int audioMode);

#endif /* MAIN_DLL_FRONT_PICMENU_H_ */
