#include "main/audio/hw_sample.h"
#include "main/audio/dsp_voice_state.h"

void hwSetVirtualSampleLoopBuffer(int slot, u32 valueA, u32 valueB)
{
    dspVoice[slot].vSampleInfo.loopBufferAddr = (void*)valueA;
    dspVoice[slot].vSampleInfo.loopBufferLength = valueB;
}

u8 hwGetVirtualSampleState(int slot)
{
    return dspVoice[slot].vSampleInfo.inLoopBuffer;
}

u8 hwGetSampleType(int slot)
{
    return dspVoice[slot].smp_info.compType;
}

u16 hwGetSampleID(int slot)
{
    return dspVoice[slot].smp_id;
}

void hwSetStreamLoopPS(int slot, u8 value)
{
    dspVoice[slot].streamLoopPS = value;
}
