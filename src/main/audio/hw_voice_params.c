#include "main/audio/dsp_voice.h"
#include "main/audio/dsp_voice_state.h"
#include "main/audio/hw_voice_params.h"

#define DSP_VOICE_ITD_DISABLED_MASK     0x7fffffff
#define DSP_VOICE_ITD_CENTER            0x10

extern u8 salTimeOffset;

void hwSetPitch(u32 slot, u16 pitch)
{
    DSPvoice* entry;
    u32 val;
    u32 channel;

    entry = &dspVoice[slot];
    if (pitch >= 0x4000)
    {
        pitch = 0x3fff;
    }
    channel = entry->lastUpdate.pitch;
    if (channel != 0xff)
    {
        val = entry->pitch[channel];
        if (val == (pitch << 4))
        {
            return;
        }
    }
    channel = salTimeOffset;
    entry->pitch[channel] = pitch << 4;
    channel = salTimeOffset;
    val = entry->changed[channel];
    entry->changed[channel] = val | DSP_VOICE_CHANGE_PITCH;
    entry->lastUpdate.pitch = salTimeOffset;
}

void hwSetSRCType(u32 slot, u8 value)
{
    static u16 dspSRCType[3] = {0, 1, 2};
    DSPvoice* entry = &dspVoice[slot];
    entry->srcTypeSelect = dspSRCType[(u8)value];
    entry->changed[0] |= DSP_VOICE_CHANGE_SRC_TYPE;
}

void hwSetPolyPhaseFilter(u32 slot, u8 value)
{
    static u16 dspCoefSel[3] = {0, 1, 2};
    DSPvoice* entry = &dspVoice[slot];
    entry->srcCoefSelect = dspCoefSel[(u8)value];
    entry->changed[0] |= DSP_VOICE_CHANGE_POLYPHASE;
}

void hwSetITDMode(u32 slot, u8 value)
{
    if (value == 0)
    {
        dspVoice[slot].flags |= DSP_VOICE_ITD_ENABLED_FLAG;
        dspVoice[slot].itdShiftL = DSP_VOICE_ITD_CENTER;
        dspVoice[slot].itdShiftR = DSP_VOICE_ITD_CENTER;
        return;
    }
    dspVoice[slot].flags &= DSP_VOICE_ITD_DISABLED_MASK;
}
