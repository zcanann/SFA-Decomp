#ifndef MAIN_AUDIO_SYNTH_VOICE_H_
#define MAIN_AUDIO_SYNTH_VOICE_H_

#include "global.h"
#include "main/audio/mcmd.h"
#include "main/dll/synthfade_struct.h"

typedef struct SynthDelayedNode SynthDelayedNode;

void synthQueueDelayedUpdate(SynthDelayedNode* fade, int mode, u32 delay);
void synthStartSynthJobHandling(McmdVoiceState *voice);
void synthQueueVoicePrimaryUpdates(McmdVoiceState *voice);
void synthQueueVoiceInputUpdate(McmdVoiceState *voice);
void synthDispatchFadeAction(SynthFade* fade);
void synthHandle(u32 deltaTime);
u32 synthFXStart(u16 fxId, u8 volume, u8 pan, u8 studio, u32 studioAux);

#endif /* MAIN_AUDIO_SYNTH_VOICE_H_ */
