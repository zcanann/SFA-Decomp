#ifndef MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_

#include "types.h"

u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);

#define Sfx_PlayFromObjectLimitedIntReturnLegacy(obj, sfxId, limit)                                      \
    ((int (*)(int, int, int))Sfx_PlayFromObjectLimited)((obj), (sfxId), (limit))

#define Sfx_PlayFromObjectLimitedPtrVoidLegacy(obj, sfxId, limit)                                        \
    ((void (*)(void*, int, int))Sfx_PlayFromObjectLimited)((void*)(obj), (sfxId), (limit))

#define Sfx_PlayFromObjectLimitedU32U16Legacy(obj, sfxId, limit)                                         \
    ((u32 (*)(u32, u16, int))Sfx_PlayFromObjectLimited)((obj), (sfxId), (limit))

#define Sfx_KeepAliveLoopedObjectSoundLimitedPtrIntLegacy(obj, sfxId, limit)                              \
    ((void (*)(void*, int, int))Sfx_KeepAliveLoopedObjectSoundLimited)((void*)(obj), (sfxId), (limit))

#endif /* MAIN_AUDIO_SFX_LIMITED_OBJECT_API_H_ */
