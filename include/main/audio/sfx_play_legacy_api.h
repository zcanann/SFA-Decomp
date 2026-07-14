#ifndef MAIN_AUDIO_SFX_PLAY_LEGACY_API_H_
#define MAIN_AUDIO_SFX_PLAY_LEGACY_API_H_

#include "types.h"

void Sfx_PlayFromObject(int obj, int sfxId);

#define Sfx_PlayFromObjectPtrU32Legacy(obj, sfxId)                                                       \
    ((void (*)(void*, u32))Sfx_PlayFromObject)((void*)(obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_PLAY_LEGACY_API_H_ */
