#ifndef MAIN_AUDIO_SYNTH_JOB_QUEUE_H_
#define MAIN_AUDIO_SYNTH_JOB_QUEUE_H_

struct SynthDelayedNode;

typedef struct SynthJobTab
{
    struct SynthDelayedNode* lowPrecision;
    struct SynthDelayedNode* event;
    struct SynthDelayedNode* zeroOffset;
} SynthJobTab;

#endif
