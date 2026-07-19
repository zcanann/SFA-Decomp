#ifndef MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_

#include "types.h"

void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);

#define Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, sfxId)                                             \
    ((void (*)(void*, u16))Sfx_RemoveLoopedObjectSound)((void*)(obj), (sfxId))

#endif /* MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_ */
