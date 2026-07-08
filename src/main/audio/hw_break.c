#include "ghidra_import.h"
#include "main/audio/hw_break.h"

extern u8* dspVoice;
extern u8 salTimeOffset;

void hwBreak(int slot)
{
    u8* entry;
    u32 offset;
    u32 channel;

    offset = slot * 0xf4;
    entry = dspVoice + offset;
    if ((entry[0xec] == 1) && (salTimeOffset == 0))
    {
        entry[0xee] = 1;
    }
    entry = dspVoice;
    channel = salTimeOffset;
    channel <<= 2;
    entry += offset;
    entry += channel;
    *(u32*)(entry + 0x24) |= 0x20;
}
