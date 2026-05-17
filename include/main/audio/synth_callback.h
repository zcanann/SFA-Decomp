#ifndef MAIN_AUDIO_SYNTH_CALLBACK_H_
#define MAIN_AUDIO_SYNTH_CALLBACK_H_

#include "ghidra_import.h"

typedef struct SynthCallbackLink SynthCallbackLink;
typedef struct SynthVoice SynthVoice;

void synthRecycleVoiceCallbacks(SynthVoice *voice);
SynthCallbackLink *synthAllocCallback(s32 triggerValue, u8 controllerIndex);
s32 synthUpdateCallbacks(void);
void synthFlushCallbacks(void);
void synthFreeCallback(SynthCallbackLink *callback);
u32 synthAssignHandle(s32 voiceIndex);
u32 synthResolveHandle(u32 handle);

#endif /* MAIN_AUDIO_SYNTH_CALLBACK_H_ */
