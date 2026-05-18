#ifndef MAIN_DLL_FRONT_DLL_3B_H_
#define MAIN_DLL_FRONT_DLL_3B_H_

#include "ghidra_import.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/title_menu.h"

void TitleMenu_initialise(void);
void *PopDecodedAudioBuffer(int flags);
void PushFreeAudioBuffer(void *message);
void AttractMovieAudio_Decode(void *cursor);
void *AudioDecoderForOnMemory(void *param);
void *AudioDecoder(void *param);
void AudioDecodeThreadCancel(void);
void AudioDecodeThreadStart(void);

#endif /* MAIN_DLL_FRONT_DLL_3B_H_ */
