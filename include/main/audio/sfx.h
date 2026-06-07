#ifndef MAIN_AUDIO_SFX_H_
#define MAIN_AUDIO_SFX_H_

#include "ghidra_import.h"

s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
void Sfx_PlayFromObject(u32 obj, u16 sfxId);

#endif /* MAIN_AUDIO_SFX_H_ */
