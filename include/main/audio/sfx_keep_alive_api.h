#ifndef MAIN_AUDIO_SFX_KEEP_ALIVE_API_H_
#define MAIN_AUDIO_SFX_KEEP_ALIVE_API_H_

#include "types.h"

void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);

#define Sfx_KeepAliveLoopedObjectSoundPtrU16Legacy(obj, sfxId)                                                \
    ((void (*)(void*, u16))Sfx_KeepAliveLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_KeepAliveLoopedObjectSoundPtrIntLegacy(obj, sfxId)                                                \
    ((void (*)(void*, int))Sfx_KeepAliveLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_KeepAliveLoopedObjectSoundIntLegacy(obj, sfxId)                                                   \
    ((void (*)(int, int))Sfx_KeepAliveLoopedObjectSound)((obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_KEEP_ALIVE_API_H_ */
