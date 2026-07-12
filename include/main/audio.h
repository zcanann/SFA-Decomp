#ifndef MAIN_AUDIO_H_
#define MAIN_AUDIO_H_

#include "types.h"

extern u8 gAudioStreamDvdState;
extern u8 gAudioStreamPlaying;
extern s32 gAudioStreamCurrentId;
extern u32 gAudioStreamPlayAddrCallbackResult;
extern u8 gAudioStreamPlayAddrCallbackDone;
extern f32 lbl_803DE5D4;
extern f32 lbl_803DE568;
extern f32 lbl_803DE550;
extern f32 lbl_803DE554;
extern f32 lbl_803DE558;
extern f32 lbl_803DE55C;

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
void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, f32* vector);
f32 Sfx_GetListenerRelativeDistance(f32* soundPos, f32* outDelta);
int return0x64_8000A378(void);
void doNothing_8000CF54(void);
void audioFn_8000b694(u32 value);
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third);
void fn_80009008(void);
void MIDIWADLoadedCallback(int status, void* fileInfo);
int musicInitMidiWad(void);
void poolDataMLoadedCallback(int status, void* fileInfo);
void poolDataSLoadedCallback(int status, void* fileInfo);
void projectDataMLoadedCallback(int status, void* fileInfo);
void projectDataSLoadedCallback(int status, void* fileInfo);
void sampleBufferMLoadedCallback(int status, void* fileInfo);
void sampleBufferSLoadedCallback(int status, void* fileInfo);
void sampleDirectoryMLoadedCallback(int status, void* fileInfo);
void sampleDirectorySLoadedCallback(int status, void* fileInfo);
void sfxTriggersLoadedCallback(int status, void* fileInfo);
void musicTriggersLoadedCallback(int status, void* fileInfo);
void streamsLoadedCallback(int status, void* fileInfo);
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 callback, u32 callbackArg1, u32 callbackArg2,
                          u32 callbackArg3);
void audioSetSoundMode(int mode, u8 forceFlag);
void audioLoadTriggerData(void);
int audioInit(void);

#endif /* MAIN_AUDIO_H_ */
