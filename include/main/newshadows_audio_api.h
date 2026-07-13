#ifndef MAIN_NEWSHADOWS_AUDIO_API_H_
#define MAIN_NEWSHADOWS_AUDIO_API_H_

#include "global.h"

u16 audioPickSoundEffect_8006ed24(s8 surfaceType, u8 soundId);

#define audioPickSoundEffectIntLegacy(surfaceType, soundId)                                                      \
    (((int (*)(u8, int))audioPickSoundEffect_8006ed24)((surfaceType), (soundId)))
#define audioPickSoundEffectU16Legacy(surfaceType, soundId)                                                      \
    (((u16 (*)(u8, int))audioPickSoundEffect_8006ed24)((surfaceType), (soundId)))

#endif /* MAIN_NEWSHADOWS_AUDIO_API_H_ */
