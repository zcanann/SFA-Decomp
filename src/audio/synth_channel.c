#include "src/audio/synth_internal.h"
#include "src/audio/synth_voice_overlays.h"

extern u32 gSynthCurrentVoiceSlotIndex;

#define SYNTH_PROGRAM_FLAGS(program) (*(u32*)((program) + 0x10))

void synthUpdateChannelScaleEvents(u32 channelIndex) {
    SynthChannelState* channelState;
    SynthVoiceProgramState* programState;
    SynthPitchPoint* point;
    u32 value;

    channelState = SYNTH_CHANNEL_STATE(gSynthCurrentVoice, channelIndex);
    programState = SYNTH_VOICE_PROGRAM_STATE(gSynthCurrentVoice);
    if (channelState->eventActive != 0) {
        do {
            point = channelState->eventCursor;
            if (point->threshold == 0xFFFFFFFF ||
                point->threshold > SYNTH_CHANNEL_THRESHOLD(channelState, channelState->thresholdIndex)) {
                break;
            }

            if ((SYNTH_PROGRAM_FLAGS(programState->programData) & 0x40000000) != 0) {
                value = point->value;
                channelState->currentValue = value;
                synthSetStudioChannelScale((s32)(value >> 10), (u8)gSynthCurrentVoiceSlotIndex,
                                           channelIndex);
            } else {
                synthSetStudioChannelScale((s32)point->value, (u8)gSynthCurrentVoiceSlotIndex,
                                           channelIndex);
                point = channelState->eventCursor;
                channelState->currentValue = point->value << 10;
            }

            point = channelState->eventCursor;
            channelState->eventCursor = point + 1;
        } while (1);
    }
}
