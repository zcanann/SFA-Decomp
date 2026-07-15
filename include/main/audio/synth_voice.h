#ifndef MAIN_AUDIO_SYNTH_VOICE_H_
#define MAIN_AUDIO_SYNTH_VOICE_H_

#include "global.h"
#include "main/dll/synthfade_struct.h"

typedef struct SynthDelayedNode SynthDelayedNode;

void synthQueueDelayedUpdate(SynthDelayedNode* fade, int mode, u32 delay);
void synthDispatchFadeAction(SynthFade* fade);
void synthHandle(u32 deltaTime);
int synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u32 studioAux);

#endif /* MAIN_AUDIO_SYNTH_VOICE_H_ */
