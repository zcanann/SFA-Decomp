#ifndef MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_

#include "types.h"

void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);

#define Sfx_AddLoopedObjectSoundIntLegacy(obj, sfxId)                                                   \
    ((void (*)(int, int))Sfx_AddLoopedObjectSound)((obj), (sfxId))

#define Sfx_AddLoopedObjectSoundIntReturnLegacy(obj, sfxId)                                             \
    ((int (*)(int, int))Sfx_AddLoopedObjectSound)((obj), (sfxId))

#define Sfx_AddLoopedObjectSoundPtrIntLegacy(obj, sfxId)                                                \
    ((void (*)(void*, int))Sfx_AddLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_AddLoopedObjectSoundPtrU16Legacy(obj, sfxId)                                                \
    ((void (*)(void*, u16))Sfx_AddLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_RemoveLoopedObjectSoundIntLegacy(obj, sfxId)                                                \
    ((void (*)(int, int))Sfx_RemoveLoopedObjectSound)((obj), (sfxId))

#define Sfx_RemoveLoopedObjectSoundPtrIntLegacy(obj, sfxId)                                             \
    ((void (*)(void*, int))Sfx_RemoveLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, sfxId)                                             \
    ((void (*)(void*, u16))Sfx_RemoveLoopedObjectSound)((void*)(obj), (sfxId))

#define Sfx_RemoveLoopedObjectSoundForObjectPtrLegacy(obj)                                              \
    ((void (*)(void*))Sfx_RemoveLoopedObjectSoundForObject)((void*)(obj))

#endif /* MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_ */
