#include "main/audio/hw_voice_start.h"

#pragma exceptions on

extern u8* dspVoice;
extern u8 salTimeOffset;
extern void salActivateVoice(void* entry, u8 studioIndex);

void hwStart(int slot, u8 studioIndex)
{
    int offset;
    u8 startTime;

    offset = slot * 0xf4;
    startTime = salTimeOffset;
    dspVoice[offset + 0xd4] = startTime;
    salActivateVoice(dspVoice + offset, studioIndex);
}
