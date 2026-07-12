#ifndef MAIN_AUDIO_H_
#define MAIN_AUDIO_H_

#include "types.h"

u8 AudioStream_IsPreparing(void);
void AudioStream_CancelPrepared(void);
void AudioStream_StartPrepared(void);
void AudioStream_StopCurrent(void);
void audioStopByMask(int mask);
void streamFn_8000a380(int a, int b, int c);

#endif /* MAIN_AUDIO_H_ */
