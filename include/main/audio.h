#ifndef MAIN_AUDIO_H_
#define MAIN_AUDIO_H_

#include "types.h"

extern u8 gAudioStreamDvdState;
extern u8 gAudioStreamPlaying;
extern s32 gAudioStreamCurrentId;
extern u32 gAudioStreamPlayAddrCallbackResult;
extern u8 gAudioStreamPlayAddrCallbackDone;

void audioReset(void);
int audioIsResetting(void);
void audioStopAll(void);
void audioUpdate(void);
u32 audioFlagFn_8000a188(u32 mask);
void audioFree(void* ptr);
void* _audioAlloc(u32 size);
u8 AudioStream_IsPreparing(void);
void AudioStream_CancelPrepared(void);
void AudioStream_StartPrepared(void);
void AudioStream_StopCurrent(void);
void AudioStream_StopAll(void);
u32 AudioStream_GetMusicFadeFlagA(void);
u32 AudioStream_GetMusicFadeFlagB(void);
u32 AudioStream_GetCurrentId(void);
void AudioStream_SetVolume(u8 volume);
void AudioStream_SetDefaultVolume(u8 volume);
void AudioStream_Init(void);
void AudioStream_PrepareCallback(void);
void AudioStream_PlayAddrCallback(u32 result);
int AudioStream_Play(int id, void (*preparedCallback)(void));
void audioStopByMask(int mask);
void streamFn_8000a380(int a, int b, int c);
void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag);
s32 Music_GetActivePriority(void);
void Music_Trigger(int id, int arg);
void Music_PlayTrackByIndex(int index);

#endif /* MAIN_AUDIO_H_ */
