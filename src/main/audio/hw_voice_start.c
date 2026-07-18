#include "main/audio/hw_voice_start.h"
#include "main/audio/dsp_voice_state.h"
#include "main/audio/hw_dspctrl.h"

extern u8 salTimeOffset;

void hwStart(u32 voice, u8 studio)
{
    dspVoice[voice].singleOffset = salTimeOffset;
    salActivateVoice(&dspVoice[voice], studio);
}
