#ifndef MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_

#include "types.h"

u32 Sfx_PlayFromObjectLimited(u32 obj, u16 sfxId, int limit);
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);

#endif /* MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_ */
