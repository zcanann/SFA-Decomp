#ifndef MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_
#define MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_

#include "types.h"

struct GameObject;

void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_KeepAliveLoopedObjectSound(struct GameObject* obj, u16 sfxId);
void Sfx_KeepAliveLoopedObjectSoundLimited(struct GameObject* obj, u16 sfxId, u16 limit);
void Sfx_AddLoopedObjectSound(struct GameObject* obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(struct GameObject* obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(struct GameObject* obj);

#endif /* MAIN_AUDIO_SFX_LOOPED_OBJECT_API_H_ */
