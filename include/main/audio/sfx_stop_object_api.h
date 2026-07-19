#ifndef MAIN_AUDIO_SFX_STOP_OBJECT_API_H_
#define MAIN_AUDIO_SFX_STOP_OBJECT_API_H_

#include "types.h"

void Sfx_StopFromObject(u32 obj, u32 sfxId);

#define Sfx_StopFromObjectIntLegacy(obj, sfxId)                                                          \
    ((void (*)(int, int))Sfx_StopFromObject)((obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_STOP_OBJECT_API_H_ */
