#ifndef MAIN_AUDIO_SYNTH_CONFIG_H_
#define MAIN_AUDIO_SYNTH_CONFIG_H_

#include "ghidra_import.h"

typedef struct SynthConfiguration {
    u32 sampleRate;
    u32 unk04;
    u8 unk08[0x208];
    u8 voiceCount;
    u8 musicVoiceCount;
    u8 fxVoiceCount;
    u8 studioCount;
} SynthConfiguration;

extern u8 lbl_803BD150[];

#define SYNTH_CONFIGURATION ((SynthConfiguration*)lbl_803BD150)

#endif /* MAIN_AUDIO_SYNTH_CONFIG_H_ */
