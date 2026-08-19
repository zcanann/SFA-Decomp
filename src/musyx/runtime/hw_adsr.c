#include "musyx/dsp_voice_state.h"

#include "musyx/voice_conv.h"
#include "musyx/hw_adsr.h"
#include "musyx/adsr.h"

typedef struct HwAdsrEnvelope
{
    u16 attack;
    u16 decay;
    u16 sustain;
    u16 release;
    u16 decayTime;
    u16 releaseTime;
} HwAdsrEnvelope;

void hwSetADSR(int slot, u32* adsr, u8 mode) {
    u32 value;
    HwAdsrEnvelope* envelope = (HwAdsrEnvelope*)adsr;
    switch (mode) {
    case 0:
        dspVoice[slot].adsr.mode = ADSR_MODE_LINEAR;
        dspVoice[slot].adsr.aTime = envelope->attack;
        dspVoice[slot].adsr.dTime = envelope->decay;

        if ((value = envelope->sustain << 3) > 0x7fff) {
            value = 0x7fff;
        }

        dspVoice[slot].adsr.sLevel = value;
        dspVoice[slot].adsr.rTime = envelope->release;
        break;
    case 1:
    case 2:
        dspVoice[slot].adsr.mode = ADSR_MODE_DLS;
        dspVoice[slot].adsr.aMode = ADSR_ATTACK_MODE_LINEAR;

        if (mode == 1)
        {
            dspVoice[slot].adsr.aTime = voiceConvertTimeCentsToMs(adsr[0]) & 0xffff;
            dspVoice[slot].adsr.dTime = voiceConvertTimeCentsToMs(adsr[1]) & 0xffff;

            value = envelope->decayTime >> 2;
            if (value > 0x3ff)
            {
                value = 0x3ff;
            }

            dspVoice[slot].adsr.sLevel = 0xc1 - voiceAdsrDecayTable[value];
        }
        else
        {
            dspVoice[slot].adsr.aTime = adsr[0] & 0xffff;
            dspVoice[slot].adsr.dTime = adsr[1] & 0xffff;
            dspVoice[slot].adsr.sLevel = envelope->decayTime;
        }

        dspVoice[slot].adsr.rTime = envelope->releaseTime;
        break;
    }

    dspVoice[slot].changed[0] |= DSP_VOICE_CHANGE_ADSR;
}
