#ifndef MAIN_AUDIO_SFX_OBJECT_QUERY_API_H_
#define MAIN_AUDIO_SFX_OBJECT_QUERY_API_H_

#include "types.h"

s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);

#define Sfx_IsPlayingFromObjectIntLegacy(obj, sfxId)                                                     \
    ((int (*)(int, int))Sfx_IsPlayingFromObject)((obj), (sfxId))

#define Sfx_IsPlayingFromObjectIntU16Legacy(obj, sfxId)                                                  \
    ((int (*)(int, u16))Sfx_IsPlayingFromObject)((obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_OBJECT_QUERY_API_H_ */
