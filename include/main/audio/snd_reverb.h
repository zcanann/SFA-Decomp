#ifndef MAIN_AUDIO_SND_REVERB_H_
#define MAIN_AUDIO_SND_REVERB_H_

#include "dolphin/axfx.h"
#include "main/audio/snd_types.h"

typedef AXFX_REVERBSTD ReverbState;

void salFree(void *ptr);
void sndAuxCallbackReverbSTD(u8 mode, SynthAuxInfo* info, void* user);
void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState *state);

#endif /* MAIN_AUDIO_SND_REVERB_H_ */
