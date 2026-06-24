#ifndef MAIN_AUDIO_SYNTH_JOB_H_
#define MAIN_AUDIO_SYNTH_JOB_H_

#include "ghidra_import.h"

#define SYNTH_JOB_STRIDE 0x64

typedef void (*SynthJobCallback)(u32, u32, u32, u32, u32);

typedef struct SynthJobAdpcm {
    u8 unk00[2];
    u8 initialPS;
    u8 loopPS;
    u8 unk04[0x24];
} SynthJobAdpcm;

typedef struct SynthJob {
    u8 unk00[4];
    u32 flags;
    u8 state;
    u8 format;
    u8 unk0A[2];
    SynthJobCallback callback;
    u8* buffer;
    u32 size;
    u32 bytes;
    u32 last;
    SynthJobAdpcm adpcm;
    u32 voice;
    u32 callbackUser;
    u32 frq;
    u8 unk54;
    u8 volume;
    u8 pan;
    u8 surroundPan;
    u8 leftVolume;
    u8 rightVolume;
    u8 savedPan;
    u8 savedSurroundPan;
    u8 studio;
    u8 streamHandle;
    u8 unk5E[6];
} SynthJob;

/* SynthJob.state - stream playback job lifecycle */
#define SYNTH_JOB_STATE_FREE 0    /* unused slot */
#define SYNTH_JOB_STATE_PENDING 1 /* queued; start playback next service */
#define SYNTH_JOB_STATE_PLAYING 2 /* voice started; streaming */
#define SYNTH_JOB_STATE_DONE 3    /* cancelled/finished; awaiting recycle */

/* SynthJob.format - sample codec */
#define SYNTH_JOB_FORMAT_PCM 0   /* uncompressed (hw compType 2) */
#define SYNTH_JOB_FORMAT_ADPCM 1 /* ADPCM (hw compType 4) */

#endif /* MAIN_AUDIO_SYNTH_JOB_H_ */
