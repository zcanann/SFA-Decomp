#ifndef MAIN_AUDIO_SFX_H_
#define MAIN_AUDIO_SFX_H_

#include "global.h"

s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);
void Sfx_ClearLoopedObjectSounds(void);
void Sfx_UpdateLoopedObjectSounds(void);
void Sfx_SetObjectSoundsPaused(s32 paused);
void Sfx_PlayFromObject(u32 obj, u16 sfxId);
u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u16 sfxId);
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u16 sfxId);
void Sfx_StopFromObject(u32 obj, u32 sfxId);
void Sfx_StopObjectChannel(u32 obj, u32 channel);
void Sfx_SetObjectChannelVolume(u32 obj, u32 channel, u8 volume, f32 volumeScale);
void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);
void Sfx_AddLoopedObjectSound(u32 obj, u16 sfxId);
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId);
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj);


/* extern-cleanup: consolidated prototypes */
void subtitleUpdateAndDraw(int a);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
s32 isTalkingToNpc(void);
void setShowWorldMapHud(u8 param);

#endif /* MAIN_AUDIO_SFX_H_ */
