#ifndef MAIN_AUDIO_STREAM_API_H_
#define MAIN_AUDIO_STREAM_API_H_

#include "types.h"
#include "dolphin/dvd.h"

extern u8 gAudioStreamDvdState;
extern u8 gAudioStreamPlaying;
extern s32 gAudioStreamCurrentId;
extern u32 gAudioStreamPlayAddrCallbackResult;
extern u8 gAudioStreamPlayAddrCallbackDone;

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
void AudioStream_PrepareCallback(s32 result, DVDFileInfo* fileInfo);
void AudioStream_PlayAddrCallback(u32 result);
int AudioStream_Play(int id, void (*preparedCallback)(void));
void streamFn_8000a380(int mask, int mode, int time);

#define AudioStream_GetCurrentIdLegacy() ((int (*)())AudioStream_GetCurrentId)()

#endif /* MAIN_AUDIO_STREAM_API_H_ */
