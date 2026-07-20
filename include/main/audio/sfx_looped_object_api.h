#ifndef MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_

#include "types.h"

void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);

#endif /* MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_ */
