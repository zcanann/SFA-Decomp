#ifndef MAIN_AUDIO_SFX_H_
#define MAIN_AUDIO_SFX_H_

#include "global.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_stop_object_api.h"

s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_SetObjectSoundsPaused(s32 paused);
void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u16 sfxId);
u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId);
void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u16 sfxId);
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u16 sfxId);
void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);
void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);
void Sfx_InitObjectChannels(void);

#endif /* MAIN_AUDIO_SFX_H_ */
