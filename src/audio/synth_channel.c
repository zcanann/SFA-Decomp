#include "src/audio/synth_internal.h"

extern void fn_8026FCA0(s32 value, u8 studioIndex, u32 channelIndex);
extern u32 lbl_803DEEA0;

typedef struct SynthPitchPoint {
    u32 threshold;
    u32 value;
} SynthPitchPoint;

typedef struct SynthChannelState {
    s32 eventActive;
    SynthPitchPoint* eventCursor;
    u32 currentValue;
    u8 unk0C[0x24 - 0x0C];
    u32 threshold0;
    u32 unk28;
    u32 threshold1;
    u8 thresholdIndex;
    u8 unk31[0x38 - 0x31];
} SynthChannelState;

#define SYNTH_CHANNEL_STATE(voice, channel) \
    ((SynthChannelState*)&(voice)->unkEE0[0x608 + (((channel) & 0xFF) * sizeof(SynthChannelState))])
#define SYNTH_CHANNEL_THRESHOLD(state, index) (*(u32*)((u8*)(state) + 0x24 + ((index) * 8)))
#define SYNTH_VOICE_PROGRAM_DATA(voice) (*(u8**)((voice)->unk10 + 0x108))
#define SYNTH_PROGRAM_FLAGS(program) (*(u32*)((program) + 0x10))

void fn_8026D6DC(u32 channelIndex) {
    SynthChannelState* channelState;
    SynthPitchPoint* point;
    u32 value;

    channelState = SYNTH_CHANNEL_STATE(gSynthCurrentVoice, channelIndex);
    if (channelState->eventActive != 0) {
        do {
            point = channelState->eventCursor;
            if (point->threshold == 0xFFFFFFFF ||
                point->threshold > SYNTH_CHANNEL_THRESHOLD(channelState, channelState->thresholdIndex)) {
                break;
            }

            if ((SYNTH_PROGRAM_FLAGS(SYNTH_VOICE_PROGRAM_DATA(gSynthCurrentVoice)) & 0x40000000) !=
                0) {
                value = point->value;
                channelState->currentValue = value;
                fn_8026FCA0((s32)(value >> 10), (u8)lbl_803DEEA0, channelIndex);
            } else {
                fn_8026FCA0((s32)point->value, (u8)lbl_803DEEA0, channelIndex);
                point = channelState->eventCursor;
                channelState->currentValue = point->value << 10;
            }

            point = channelState->eventCursor;
            channelState->eventCursor = point + 1;
        } while (1);
    }
}
