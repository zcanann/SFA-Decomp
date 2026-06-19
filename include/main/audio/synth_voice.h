#ifndef MAIN_AUDIO_SYNTH_VOICE_H_
#define MAIN_AUDIO_SYNTH_VOICE_H_

#include "global.h"
#include "main/audio/inp_ctrl.h"
#include "main/dll/synthfade_struct.h"
#include "util/carry.h"
#include "main/audio/synth_channel.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/voice_id.h"
#include "main/audio/synth_queue.h"

void synthQueueDelayedUpdate(SynthDelayedNode* fade, int mode, u32 delay);
void synthDispatchFadeAction(SynthFade* fade);


/* extern-cleanup: defining-file public prototypes */
int synthFXStart(u32 fxId, u8 volume, u8 pan, u8 studio, u32 studioAux);

#endif
