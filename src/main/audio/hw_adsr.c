#include "main/audio/dsp_voice.h"

extern u8 voiceAdsrDecayTable[];
extern u8* dspVoice;

extern u32 voiceConvertDbToLinear(u32 dbCents);

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
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.mode = 0;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.aTime = envelope->attack;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.dTime = envelope->decay;

        value = envelope->sustain << 3;
        if (value > 0x7fff)
        {
            value = 0x7fff;
        }

        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.sLevel = value;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.rTime = envelope->release;
        break;
    case 1:
    case 2:
        offset = slot * 0xf4;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.mode = 1;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.aMode = 0;

        if (mode == 1)
        {
            value = voiceConvertDbToLinear(adsr[0]);
            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.aTime = value & 0xffff;

            value = voiceConvertDbToLinear(adsr[1]);
            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.dTime = value & 0xffff;

            value = envelope->decayTime >> 2;
            if (value > 0x3ff)
            {
                value = 0x3ff;
            }

            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.sLevel = 0xc1 - voiceAdsrDecayTable[value];
        }
        else
        {
            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.aTime = adsr[0] & 0xffff;
            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.dTime = adsr[1] & 0xffff;
            entry = dspVoice;
            entry += offset;
            ((DSPvoice*)entry)->adsr.sLevel = envelope->decayTime;
        }

        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.rTime = envelope->releaseTime;
        break;
    }

    offset = slot * 0xf4;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->changed[0] |= 0x10;
}
