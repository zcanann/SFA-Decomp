#include "main/audio/vsample_update.h"
#include "main/audio/hw_stream.h"
#include "main/sfa_shared_decls.h"


extern u32 hwGetVirtualSampleState(int slot);

extern u32 hwVoiceInStartup(int slot);

extern u8 synthVirtualSampleState[];

typedef struct
{
    u8 head[8];

    struct
    {
        u8 b[36];
    } ent[64];
} VSStateLayout;

extern u8* synthVoice;
extern u16 synthLoadedGroupCount;

#define SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE 0x404
#define SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET 0x206
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE 0xa0
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND 0xfff
#define SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT 0x1000

/*
 * Periodic virtual-sample tick processor: walks 64 active voices, computes
 * elapsed tick for each, and either advances the envelope (mode 1)
 * or runs sample-completion logic (mode 2 - checks current sample
 * id matches expected and triggers a stop+vacate when threshold
 * elapsed).
 *
 * EN v1.0 Address: 0x8027B25C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027B41C
 * EN v1.1 Size: 452b
 */
void synthUpdateVirtualSamples(void)
{
    u8* state;
    u8* slotMap;
    u32 i;
    u32 currentTick;
    u32 elapsed;
    u8* entry;
    u8 vid;

    if (*(u32*)(synthVirtualSampleState + SYNTH_VIRTUAL_SAMPLE_CALLBACK_OFFSET) != 0)
    {
        state = synthVirtualSampleState;
        slotMap = state;
        for (i = 0; i < SYNTH_VIRTUAL_SAMPLE_MAX_VOICES; i++, slotMap++)
        {
            vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
            if (vid == SYNTH_VIRTUAL_SAMPLE_FREE_SLOT)
            {
                continue;
            }
            if (hwGetVirtualSampleState(i) == 0)
            {
                continue;
            }
            vid = slotMap[SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET];
            entry = ((VSStateLayout*)state)->ent[vid].b;

            currentTick = hwChangeStudio(i);
            if (entry[VIRTUAL_SAMPLE_TYPE_OFFSET] == SYNTH_VIRTUAL_SAMPLE_STREAM_TYPE)
            {
                elapsed = (currentTick / SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES) *
                    SYNTH_VIRTUAL_SAMPLE_ADPCM_FRAME_SAMPLES;
            }
            else
            {
                elapsed = currentTick;
            }

            switch (entry[VIRTUAL_SAMPLE_MODE_OFFSET])
            {
            case SYNTH_VIRTUAL_SAMPLE_MODE_ACTIVE:
                synthAdvanceVirtualSampleEntry(entry, elapsed);
                break;
            case SYNTH_VIRTUAL_SAMPLE_MODE_DONE_WAIT:
                {
                    u32 sampleId = hwGetVirtualSampleID(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
                    u32 expected = ((u32) * (u16*)(entry + VIRTUAL_SAMPLE_GENERATION_OFFSET) << 8) |
                        entry[VIRTUAL_SAMPLE_VOICE_OFFSET];

                    if (expected == sampleId)
                    {
                        u32 prev;

                        synthAdvanceVirtualSampleEntry(entry, elapsed);
                        prev = *(u32*)(entry + VIRTUAL_SAMPLE_LAST_TICK_OFFSET);
                        if (currentTick >= prev)
                        {
                            *(u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET) -= (currentTick - prev);
                        }
                        else
                        {
                            *(u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET) -=
                                *(u32*)(state + SYNTH_VIRTUAL_SAMPLE_LOOP_SIZE_OFFSET) - (prev - currentTick);
                        }
                        *(u32*)(entry + VIRTUAL_SAMPLE_LAST_TICK_OFFSET) = currentTick;

                        if ((s32)(u32)((s32)(*(u16*)(synthVoice +
                                    entry[VIRTUAL_SAMPLE_VOICE_OFFSET] * SYNTH_VIRTUAL_SAMPLE_VOICE_STRIDE +
                                    SYNTH_VIRTUAL_SAMPLE_VOICE_RELEASE_OFFSET) * SYNTH_VIRTUAL_SAMPLE_RELEASE_SCALE +
                                SYNTH_VIRTUAL_SAMPLE_RELEASE_ROUND) /
                            SYNTH_VIRTUAL_SAMPLE_RELEASE_SHIFT) > (s32) * (u32*)(entry + VIRTUAL_SAMPLE_REMAINING_OFFSET))
                        {
                            if (hwVoiceInStartup(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) == 0)
                            {
                                hwBreak(entry[VIRTUAL_SAMPLE_VOICE_OFFSET]);
                            }
                            entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                            *(u8*)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET +
                                entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                        }
                    }
                    else
                    {
                        entry[VIRTUAL_SAMPLE_MODE_OFFSET] = SYNTH_VIRTUAL_SAMPLE_MODE_INACTIVE;
                        *(u8*)(state + SYNTH_VIRTUAL_SAMPLE_VOICE_MAP_OFFSET +
                            entry[VIRTUAL_SAMPLE_VOICE_OFFSET]) = SYNTH_VIRTUAL_SAMPLE_FREE_SLOT;
                    }
                }
                break;
            }
        }
    }
}

/*
 * Reset the loaded sound-group table count.
 *
 * EN v1.1 Address: 0x8027B420
 * EN v1.1 Size: 12b
 */
void synthResetLoadedGroupCount(void)
{
    synthLoadedGroupCount = 0;
}
