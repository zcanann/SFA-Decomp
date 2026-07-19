#ifndef MAIN_NEWSHADOWS_AUDIO_API_H_
#define MAIN_NEWSHADOWS_AUDIO_API_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim.h"

int audioPickSoundEffect_8006ed24(u8 surfaceType, u8 soundId);
void objAudioFn_8006edcc(GameObject* obj, int eventMask, u8 type, void* points, void* state, f32 unused,
                         f32 scale);
void objAudioFn_8006ef38(GameObject* obj, ObjAnimEventList* events, u8 type, void* points, void* state, f32 unused,
                         f32 scale);

#endif /* MAIN_NEWSHADOWS_AUDIO_API_H_ */
