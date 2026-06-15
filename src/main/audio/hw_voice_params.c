#include "main/audio/dsp_voice.h"

extern u8* volatile dspVoice;
extern u8 salTimeOffset;
extern u16 lbl_803DC618[4];
extern u16 lbl_803DC620[4];

#define DSP_VOICE_STRIDE 0xf4
#define DSP_VOICE_PITCH_CHANGE_FLAG 0x8
#define DSP_VOICE_SRC_TYPE_CHANGE_FLAG 0x100
#define DSP_VOICE_POLYPHASE_CHANGE_FLAG 0x80
#define DSP_VOICE_ITD_ENABLED_FLAG 0x80000000
#define DSP_VOICE_ITD_DISABLED_MASK 0x7fffffff
#define DSP_VOICE_ITD_CENTER 0x10

void hwSetPitch(int slot, u32 pitch)
{
    DSPvoice* entry;
    u8* channelEntry;
    u32 val;
    u32 channel;

    entry = (DSPvoice*)(dspVoice + slot * DSP_VOICE_STRIDE);
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

void hwSetSRCType(int slot, u32 value)
{
    DSPvoice* entry = (DSPvoice*)(dspVoice + slot * DSP_VOICE_STRIDE);
    entry->srcTypeSelect = lbl_803DC618[(u8)value];
    entry->changed[0] |= DSP_VOICE_SRC_TYPE_CHANGE_FLAG;
}

void hwSetPolyPhaseFilter(int slot, u32 value)
{
    DSPvoice* entry = (DSPvoice*)(dspVoice + slot * DSP_VOICE_STRIDE);
    entry->srcCoefSelect = lbl_803DC620[(u8)value];
    entry->changed[0] |= DSP_VOICE_POLYPHASE_CHANGE_FLAG;
}

void hwSetITDMode(int slot, u32 value)
{
    if ((u8)value == 0)
    {
        int offset = slot * DSP_VOICE_STRIDE;
        u8* entry = dspVoice + offset;
        ((DSPvoice*)entry)->flags |= DSP_VOICE_ITD_ENABLED_FLAG;
        value = DSP_VOICE_ITD_CENTER;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->itdShiftL = value;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->itdShiftR = value;
    }
    else
    {
        u8* entry = dspVoice + slot * DSP_VOICE_STRIDE;
        ((DSPvoice*)entry)->flags &= DSP_VOICE_ITD_DISABLED_MASK;
    }
}
