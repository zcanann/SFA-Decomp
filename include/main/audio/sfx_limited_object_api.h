#ifndef MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_

#include "main/audio/sfx_looped_object_api.h"
#include "game/objects/object.h"

u32 Sfx_PlayFromObjectLimited(GameObject* obj, u16 sfxId, int limit);

#endif /* MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_ */
