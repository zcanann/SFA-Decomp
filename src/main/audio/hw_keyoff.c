#include "ghidra_import.h"
#include "main/audio/hw_keyoff.h"

extern u8* dspVoice;
extern u8 salTimeOffset;

void hwKeyOff(int slot)
{
    u8* entry;
    u32 offset;

    slot *= 0xf4;
    entry = dspVoice + slot;
    offset = salTimeOffset << 2;
    entry += offset;
    *(u32*)(entry + 0x24) |= 0x40;
}
