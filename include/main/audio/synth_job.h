#ifndef MAIN_AUDIO_SYNTH_JOB_H_
#define MAIN_AUDIO_SYNTH_JOB_H_

#include "ghidra_import.h"

#define SYNTH_JOB_STRIDE 0x64

typedef void (*SynthJobCallback)(u32, u32, u32, u32, u32);

typedef struct SynthJob {
    u8 unk00[4];
    u32 flags;
    u8 state;
    u8 format;
    u8 unk0A[2];
    SynthJobCallback callback;
    u8 unk10[0x38];
    u32 voice;
    u32 callbackUser;
    u8 unk50[5];
    u8 volume;
    u8 pan;
    u8 surroundPan;
    u8 leftVolume;
    u8 rightVolume;
    u8 savedPan;
    u8 savedSurroundPan;
    u8 unk5C[8];
} SynthJob;

#endif /* MAIN_AUDIO_SYNTH_JOB_H_ */
