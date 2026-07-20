#ifndef MAIN_AUDIO_SND_SERVICE_H_
#define MAIN_AUDIO_SND_SERVICE_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u16 sndRand(void);
s16 sndSin(u32 packed);
void* sndBSearch(void* key, void* base, int count, u32 stride, s32 (*cmp)(void*, void*));
void sndConvertMs(u32* value);
void sndConvertTicks(u32* value, McmdVoiceState* state);
u32 sndConvert2Ms(u32 value);

#endif /* MAIN_AUDIO_SND_SERVICE_H_ */
