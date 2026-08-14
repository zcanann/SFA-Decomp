#ifndef MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_

#include "game/objects/object.h"

u32 Sfx_PlayFromObjectLimited(GameObject* obj, u16 sfxId, int limit);
void Sfx_KeepAliveLoopedObjectSoundLimited(GameObject* obj, u16 sfxId, u16 limit);

#endif /* MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_ */
