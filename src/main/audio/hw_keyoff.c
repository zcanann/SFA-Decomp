#include "ghidra_import.h"
#include "main/audio/hw_keyoff.h"
#include "main/audio/dsp_voice_state.h"

extern u8 salTimeOffset;

void hwKeyOff(int slot)
{
    dspVoice[slot].changed[salTimeOffset] |= 0x40;
}
