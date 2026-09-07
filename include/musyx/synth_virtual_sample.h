#ifndef MUSYX_SYNTH_VIRTUAL_SAMPLE_H_
#define MUSYX_SYNTH_VIRTUAL_SAMPLE_H_

#include "types.h"

#define SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE 0x24
#define SYNTH_VIRTUAL_SAMPLE_MAX_VOICES 64
#define SYNTH_VIRTUAL_SAMPLE_FREE_SLOT 0xff
#define SYNTH_VIRTUAL_SAMPLE_INVALID_ID 0xffffffffU

#define SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE 0
#define SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE 1
#define SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT 2
#define SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE 5
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES 14
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES 8


#define SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND 2
#define SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND 1
#define SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND 0

typedef struct SND_VIRTUALSAMPLE_INFO {
    u16 smpID;
    u16 instID;
    union vsData {
        struct vsUpdate {
            u32 off1;
            u32 len1;
            u32 off2;
            u32 len2;
        } update;
    } data;
} SND_VIRTUALSAMPLE_INFO;

typedef u32 (*SynthVirtualSampleCallback)(int kind, SND_VIRTUALSAMPLE_INFO* data);

typedef struct VS_BUFFER {
    u8 state;
    u8 hwId;
    u8 smpType;
    u8 voice;
    u32 last;
    u32 finalGoodSamples;
    u32 finalLast;
    SND_VIRTUALSAMPLE_INFO info;
} VS_BUFFER;

typedef struct VS {
    u8 numBuffers;
    u8 unk01[3];
    u32 bufferLength;
    VS_BUFFER streamBuffer[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u8 voices[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u16 nextInstID;
    u16 unk94A;
    SynthVirtualSampleCallback callback;
} VS;

extern VS vs;

void vsInit(void);
u32 vsSampleStartNotify(u8 voice);
void vsSampleEndNotify(u32 packed);
void vsSampleUpdates(void);

#endif /* MUSYX_SYNTH_VIRTUAL_SAMPLE_H_ */
