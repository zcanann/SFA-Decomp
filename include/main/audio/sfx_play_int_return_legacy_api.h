#ifndef MAIN_AUDIO_SFX_PLAY_INT_RETURN_LEGACY_API_H_
#define MAIN_AUDIO_SFX_PLAY_INT_RETURN_LEGACY_API_H_

#include "main/audio/sfx_play_pointer_legacy_api.h"

#define Sfx_PlayFromObjectIntReturnLegacy(obj, sfxId)                                                        \
    ((int (*)(int, int))Sfx_PlayFromObject)((obj), (sfxId))

#define Sfx_PlayFromObjectPtrIntReturnLegacy(obj, sfxId)                                                     \
    ((int (*)(void*, int))Sfx_PlayFromObject)((void*)(obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_PLAY_INT_RETURN_LEGACY_API_H_ */
