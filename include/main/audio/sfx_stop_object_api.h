#ifndef MAIN_AUDIO_SFX_STOP_OBJECT_API_H_
#define MAIN_AUDIO_SFX_STOP_OBJECT_API_H_

#include "types.h"

void Sfx_StopFromObject(u32 obj, u32 sfxId);

#define Sfx_StopFromObjectIntLegacy(obj, sfxId)                                                          \
    ((void (*)(int, int))Sfx_StopFromObject)((obj), (sfxId))

#define Sfx_StopFromObjectIntReturnLegacy(obj, sfxId)                                                    \
    ((int (*)(int, int))Sfx_StopFromObject)((obj), (sfxId))

#define Sfx_StopFromObjectPtrU16Legacy(obj, sfxId)                                                       \
    ((void (*)(void*, u16))Sfx_StopFromObject)((void*)(obj), (sfxId))

#define Sfx_StopFromObjectPtrU32Legacy(obj, sfxId)                                                       \
    ((void (*)(void*, u32))Sfx_StopFromObject)((void*)(obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_STOP_OBJECT_API_H_ */
