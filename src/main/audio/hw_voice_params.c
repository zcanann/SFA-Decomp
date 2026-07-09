#include "main/audio/dsp_voice.h"

#define DSP_VOICE_STRIDE                0xf4
#define DSP_VOICE_PITCH_CHANGE_FLAG     0x8
#define DSP_VOICE_SRC_TYPE_CHANGE_FLAG  0x100
#define DSP_VOICE_POLYPHASE_CHANGE_FLAG 0x80
#define DSP_VOICE_ITD_ENABLED_FLAG      0x80000000
#define DSP_VOICE_ITD_DISABLED_MASK     0x7fffffff
#define DSP_VOICE_ITD_CENTER            0x10

extern DSPvoice* volatile dspVoice;
extern u8 salTimeOffset;
extern u16 lbl_803DC618[4];
extern u16 lbl_803DC620[4];

void hwSetPitch(int slot, u32 pitch)
{
    DSPvoice* entry;
    u8* channelEntry;
    u32 val;
    u32 channel;

    entry = (DSPvoice*)((u8*)dspVoice + slot * DSP_VOICE_STRIDE);
    if ((u16)pitch >= 0x4000)
    {
        pitch = 0x3fff;
    }
    channel = entry->lastUpdate.pitch;
    if (channel != 0xff)
    {
        val = entry->pitch[channel];
        if (val == ((u16)pitch << 4))
        {
            return;
        }
    }
    channel = salTimeOffset;
    pitch = (u16)pitch << 4;
    entry->pitch[channel] = pitch;
    channel = salTimeOffset;
    channel = channel << 2;
    channelEntry = (u8*)entry + channel;
    val = *(u32*)(channelEntry + 0x24);
    *(u32*)(channelEntry + 0x24) = val | DSP_VOICE_PITCH_CHANGE_FLAG;
    entry->lastUpdate.pitch = salTimeOffset;
}

void hwSetSRCType(u32 slot, u8 value)
{
    DSPvoice* entry = &dspVoice[slot];
    entry->srcTypeSelect = lbl_803DC618[(u8)value];
    entry->changed[0] |= DSP_VOICE_SRC_TYPE_CHANGE_FLAG;
}

void hwSetPolyPhaseFilter(u32 slot, u8 value)
{
    DSPvoice* entry = &dspVoice[slot];
    entry->srcCoefSelect = lbl_803DC620[(u8)value];
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
