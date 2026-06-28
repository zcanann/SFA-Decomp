#include "main/audio/dsp_voice.h"
#include "main/audio/voice_conv.h"
extern u8 voiceAdsrDecayTable[];
extern u8* volatile dspVoice;

typedef struct HwAdsrEnvelope
{
    u16 attack;
    u16 decay;
    u16 sustain;
    u16 release;
    u16 decayTime;
    u16 releaseTime;
} HwAdsrEnvelope;

void hwSetADSR(int slot, u32* adsr, u8 mode)
{
    u8* entry;
    HwAdsrEnvelope* envelope;
    u32 offset;
    u32 value;

    envelope = (HwAdsrEnvelope*)adsr;
    switch (mode)
    {
    case 0:
        offset = slot * 0xf4;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.mode = 0;
        value = envelope->attack;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.aTime = value;
        value = envelope->decay;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.dTime = value;

        value = envelope->sustain << 3;
        if (value > 0x7fff)
        {
            value = 0x7fff;
        }

        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.sLevel = value;
        value = envelope->release;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.rTime = value;
        break;
    case 1:
    case 2:
        offset = slot * 0xf4;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.mode = 1;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.aMode = 0;

        if (mode == 1)
        {
            value = voiceConvertDbToLinear(adsr[0]) & 0xffff;
            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.aTime = value;

            value = voiceConvertDbToLinear(adsr[1]) & 0xffff;
            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.dTime = value;

            value = envelope->decayTime >> 2;
            if (value > 0x3ff)
            {
                value = 0x3ff;
            }

            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.sLevel = 0xc1 - voiceAdsrDecayTable[value];
        }
        else
        {
            value = adsr[0] & 0xffff;
            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.aTime = value;
            value = adsr[1] & 0xffff;
            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.dTime = value;
            value = envelope->decayTime;
            entry = dspVoice + offset;
            ((DSPvoice*)entry)->adsr.sLevel = value;
        }

        value = envelope->releaseTime;
        entry = dspVoice + offset;
        ((DSPvoice*)entry)->adsr.rTime = value;
        break;
    }

    offset = slot * 0xf4;
    entry = dspVoice + offset;
    ((DSPvoice*)entry)->changed[0] |= 0x10;
}
