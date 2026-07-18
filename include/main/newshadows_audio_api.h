#ifndef MAIN_NEWSHADOWS_AUDIO_API_H_
#define MAIN_NEWSHADOWS_AUDIO_API_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim.h"

u16 audioPickSoundEffect_8006ed24(s8 surfaceType, u8 soundId);
void objAudioFn_8006edcc(GameObject* obj, int eventMask, u8 type, void* points, void* state, f32 unused,
                         f32 scale);
void objAudioFn_8006ef38(GameObject* obj, ObjAnimEventList* events, u8 type, void* points, void* state, f32 unused,
                         f32 scale);

#define audioPickSoundEffectIntLegacy(surfaceType, soundId)                                                      \
    (((int (*)(u8, int))audioPickSoundEffect_8006ed24)((surfaceType), (soundId)))
#define audioPickSoundEffectU16Legacy(surfaceType, soundId)                                                      \
    (((u16 (*)(u8, int))audioPickSoundEffect_8006ed24)((surfaceType), (soundId)))

#endif /* MAIN_NEWSHADOWS_AUDIO_API_H_ */
