#include "src/audio/synth_internal.h"

#define SYNTH_DEFAULT_STUDIO_INDEX 8

void synthSetStudioChannelScale(s32 value, u8 studioIndex, u32 channelIndex) {
    u32* channelScale;
    u32 scaledValue;
    u8* studioScales;

    if (studioIndex == 0xFF) {
        studioIndex = SYNTH_DEFAULT_STUDIO_INDEX;
    }

    scaledValue = ((((u32)value) << 3) * 0x600) / 0xF0;
    studioScales = (u8*)&gSynthDelayStorage + ((studioIndex & 0xFF) << 6);
    channelScale = (u32*)(studioScales + ((channelIndex & 0xFF) << 2));
    *channelScale = scaledValue;
}

u32 synthGetVoiceSlotChannelScale(SynthVoiceSlot* slot) {
    u32* channelScale;
    u8 studioIndex;
    u8* studioScales;

    studioIndex = slot->studioIndex;
    if (studioIndex == 0xFF) {
        studioIndex = SYNTH_DEFAULT_STUDIO_INDEX;
    }

    studioScales = (u8*)&gSynthDelayStorage + (studioIndex << 6);
    channelScale = (u32*)(studioScales + (slot->channelIndex << 2));
    return *channelScale;
}
