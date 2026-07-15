#ifndef MAIN_AUDIO_SYNTH_CONFIG_H_
#define MAIN_AUDIO_SYNTH_CONFIG_H_

#include "ghidra_import.h"

typedef struct SynthInfo {
    u32 sampleRate;
    u32 numSamples;
    u8 playbackInfo[0x208];
    u8 voiceCount;
    u8 musicVoiceCount;
    u8 fxVoiceCount;
    u8 studioCount;
} SynthInfo;

typedef SynthInfo SynthConfiguration;

extern SynthInfo synthInfo;

#define SYNTH_CONFIGURATION (&synthInfo)

#endif /* MAIN_AUDIO_SYNTH_CONFIG_H_ */
