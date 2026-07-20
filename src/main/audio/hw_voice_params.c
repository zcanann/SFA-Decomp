#include "main/audio/dsp_voice.h"
#include "main/audio/dsp_voice_state.h"
#include "main/audio/hw_voice_params.h"

#define DSP_VOICE_STRIDE                0xf4
#define DSP_VOICE_PITCH_CHANGE_FLAG     0x8
#define DSP_VOICE_SRC_TYPE_CHANGE_FLAG  0x100
#define DSP_VOICE_POLYPHASE_CHANGE_FLAG 0x80
#define DSP_VOICE_ITD_ENABLED_FLAG      0x80000000
#define DSP_VOICE_ITD_DISABLED_MASK     0x7fffffff
#define DSP_VOICE_ITD_CENTER            0x10

extern u8 salTimeOffset;

void hwSetPitch(u32 slot, u16 pitch)
{
    DSPvoice* entry;
    u8* channelEntry;
    u32 val;
    u32 channel;

    entry = (DSPvoice*)((u8*)dspVoice + slot * DSP_VOICE_STRIDE);
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
    channel = channel << 2;
    channelEntry = (u8*)entry + channel;
    val = *(u32*)(channelEntry + 0x24);
    *(u32*)(channelEntry + 0x24) = val | DSP_VOICE_PITCH_CHANGE_FLAG;
    entry->lastUpdate.pitch = salTimeOffset;
}

void hwSetSRCType(u32 slot, u8 value)
{
    static u16 dspSRCType[3] = {0, 1, 2};
    DSPvoice* entry = &dspVoice[slot];
    entry->srcTypeSelect = dspSRCType[(u8)value];
    entry->changed[0] |= DSP_VOICE_SRC_TYPE_CHANGE_FLAG;
}

void hwSetPolyPhaseFilter(u32 slot, u8 value)
{
    static u16 dspCoefSel[3] = {0, 1, 2};
    DSPvoice* entry = &dspVoice[slot];
    entry->srcCoefSelect = dspCoefSel[(u8)value];
    entry->changed[0] |= DSP_VOICE_POLYPHASE_CHANGE_FLAG;
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
