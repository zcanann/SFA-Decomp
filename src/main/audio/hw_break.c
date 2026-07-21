#include "ghidra_import.h"
#include "main/audio/hw_break.h"
#include "main/audio/dsp_voice_state.h"

extern u8 salTimeOffset;

void hwBreak(int voiceIndex)
{
    u8* entry;
    u32 offset;
    u32 timeOffset;

    offset = voiceIndex * sizeof(DSPvoice);
    entry = (u8*)dspVoice + offset;
    if ((((DSPvoice*)entry)->state == DSP_VOICE_STATE_STARTUP) && (salTimeOffset == 0))
    {
        ((DSPvoice*)entry)->startupBreak = 1;
    }
    entry = (u8*)dspVoice;
    timeOffset = salTimeOffset;
    timeOffset <<= 2;
    entry += offset;
    entry += timeOffset;
    *(u32*)(entry + offsetof(DSPvoice, changed)) |= DSP_VOICE_CHANGE_BREAK;
}
