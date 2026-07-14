#ifndef MAIN_AUDIO_SFX_H_
#define MAIN_AUDIO_SFX_H_

#include "global.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_stop_object_api.h"

void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_SetObjectSoundsPaused(s32 paused);
void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u16 sfxId);
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId);
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u16 sfxId);
void Sfx_InitObjectChannels(void);

#endif /* MAIN_AUDIO_SFX_H_ */
