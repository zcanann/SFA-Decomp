#ifndef MAIN_AUDIO_SFX_LEGACY_H_
#define MAIN_AUDIO_SFX_LEGACY_H_

#include "types.h"

void Sfx_PlayFromObject(int obj, int sfxId);
void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
void Sfx_StopFromObject(int obj, int sfxId);
int Sfx_IsPlayingFromObject(int obj, u16 sfxId);
void Sfx_PlayAtPositionFromObject(int obj, int sfxId, f32 x, f32 y, f32 z);

#endif /* MAIN_AUDIO_SFX_LEGACY_H_ */
