#ifndef MAIN_AUDIO_SFX_OBJECT_SYSTEM_API_H_
#define MAIN_AUDIO_SFX_OBJECT_SYSTEM_API_H_

#include "types.h"

void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_SetObjectSoundsPaused(s32 paused);
void Sfx_InitObjectChannels(void);

#endif /* MAIN_AUDIO_SFX_OBJECT_SYSTEM_API_H_ */
