#include "main/audio/hw_sample.h"

extern u8* dspVoice;

void hwSetVirtualSampleLoopBuffer(int slot, u32 valueA, u32 valueB)
{
    u8* entry;
    u32 offset;

    offset = slot * 0xf4;
    entry = dspVoice + 0x94;
    *(u32*)(entry + offset) = valueA;
    entry = dspVoice + 0x98;
    *(u32*)(entry + offset) = valueB;
}

u8 hwGetVirtualSampleState(int slot)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    return entry[0x9c];
}

u8 hwGetSampleType(int slot)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    return entry[0x90];
}

u16 hwGetSampleID(int slot)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    return *(u16*)(entry + 0x70);
}

void hwSetStreamLoopPS(int slot, u8 value)
{
    u8* entry;

    slot *= 0xf4;
    entry = dspVoice;
    entry += slot;
    entry[0xa0] = value;
}
