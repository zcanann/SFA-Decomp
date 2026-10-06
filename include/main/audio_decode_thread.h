#ifndef MAIN_AUDIO_DECODE_THREAD_H_
#define MAIN_AUDIO_DECODE_THREAD_H_

#include "types.h"
#include "dolphin/os/OSThread.h"

BOOL CreateAudioDecodeThread(OSPriority priority, void* param);
void AudioDecodeThreadStart(void);
void AudioDecodeThreadCancel(void);
void PushFreeAudioBuffer(void* message);
void* PopDecodedAudioBuffer(int flags);

#endif /* MAIN_AUDIO_DECODE_THREAD_H_ */
