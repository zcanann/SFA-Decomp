#ifndef MAIN_AUDIO_SYNTH_VIRTUAL_SAMPLE_H_
#define MAIN_AUDIO_SYNTH_VIRTUAL_SAMPLE_H_

#include "ghidra_import.h"

#define SYNTH_VIRTUAL_SAMPLE_ENTRY_COUNT_OFFSET 0
#define SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET 4
#define SYNTH_VIRTUAL_SAMPLE_ENTRIES_OFFSET 8
#define SYNTH_VIRTUAL_SAMPLE_ENTRY_SIZE 0x24
#define SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET 0x908
#define SYNTH_VIRTUAL_SAMPLE_NEXT_ID_OFFSET 0x948
#define SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET 0x94c
#define SYNTH_VIRTUAL_SAMPLE_MAX_VOICES 64
#define SYNTH_VIRTUAL_SAMPLE_FREE_SLOT 0xff
#define SYNTH_VIRTUAL_SAMPLE_INVALID_ID 0xffffffffU

#define SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE 0
#define SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE 1
#define SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT 2
#define SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE 5
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES 14
#define SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_BYTES 8

#define VIRTUAL_SAMPLE_MODE_OFFSET 0
#define VIRTUAL_SAMPLE_TYPE_OFFSET 2
#define VIRTUAL_SAMPLE_VOICE_OFFSET 3
#define VIRTUAL_SAMPLE_POSITION_OFFSET 4
#define VIRTUAL_SAMPLE_REMAINING_OFFSET 8
#define VIRTUAL_SAMPLE_LAST_TICK_OFFSET 0xc
#define VIRTUAL_SAMPLE_CALLBACK_SAMPLE_ID_OFFSET 0x10
#define VIRTUAL_SAMPLE_CALLBACK_DATA_OFFSET 0x10
#define VIRTUAL_SAMPLE_GENERATION_OFFSET 0x12
#define VIRTUAL_SAMPLE_CALLBACK_START_OFFSET 0x14
#define VIRTUAL_SAMPLE_CALLBACK_SIZE_OFFSET 0x18
#define VIRTUAL_SAMPLE_CALLBACK_WRAP_A_OFFSET 0x1c
#define VIRTUAL_SAMPLE_CALLBACK_WRAP_B_OFFSET 0x20

#define SYNTH_VIRTUAL_SAMPLE_DONE_CALLBACK_KIND 2
#define SYNTH_VIRTUAL_SAMPLE_STREAM_CALLBACK_KIND 1
#define SYNTH_VIRTUAL_SAMPLE_CLAIM_CALLBACK_KIND 0

typedef void (*SynthVirtualSampleCallback)(int kind, void *data);

typedef struct SynthVirtualSampleCallbackData {
    u16 sampleId;
    u16 generation;
    u32 start;
    u32 size;
    u32 wrapA;
    u32 wrapB;
} SynthVirtualSampleCallbackData;

typedef struct SynthVirtualSampleEntry {
    u8 mode;
    u8 unk01;
    u8 type;
    u8 voice;
    u32 position;
    u32 remaining;
    u32 lastTick;
    SynthVirtualSampleCallbackData callbackData;
} SynthVirtualSampleEntry;

typedef struct SynthVirtualSampleState {
    u8 entryCount;
    u8 unk01[3];
    u32 loopSize;
    SynthVirtualSampleEntry entries[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u8 voiceMap[SYNTH_VIRTUAL_SAMPLE_MAX_VOICES];
    u16 nextId;
    u16 unk94A;
    SynthVirtualSampleCallback callback;
} SynthVirtualSampleState;

void synthInitVirtualSampleTable(void);
u32 synthClaimVirtualSampleSlot(u8 voice);
void synthHandleVirtualSampleDone(u32 packed);
void synthAdvanceVirtualSampleEntry(void *entry, u32 elapsed);
void synthUpdateVirtualSamples(void);
void synthResetLoadedGroupCount(void);

#endif /* MAIN_AUDIO_SYNTH_VIRTUAL_SAMPLE_H_ */
