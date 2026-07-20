#include "ghidra_import.h"
#include "main/audio/hw_break.h"
#include "main/audio/dsp_voice_state.h"

extern u8 salTimeOffset;

void hwBreak(int voiceIndex)
{
    u8* entry;
    u32 offset;
    u32 channel;

    offset = voiceIndex * sizeof(DSPvoice);
    entry = (u8*)dspVoice + offset;
    if ((((DSPvoice*)entry)->state == 1) && (salTimeOffset == 0))
    {
        ((DSPvoice*)entry)->startupBreak = 1;
    }
    entry = (u8*)dspVoice;
    channel = salTimeOffset;
    channel <<= 2;
    entry += offset;
    entry += channel;
    *(u32*)(entry + offsetof(DSPvoice, changed)) |= 0x20;
}
