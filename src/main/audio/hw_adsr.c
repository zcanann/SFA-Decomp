#include "ghidra_import.h"
#include "main/audio/hw_adsr.h"

extern u8 voiceAdsrDecayTable[];
extern u8 *dspVoice;

extern u32 voiceConvertDbToLinear(u32 value);

typedef struct HwAdsrEnvelope {
    u16 attack;
    u16 decay;
    u16 sustain;
    u16 release;
    u16 decayTime;
    u16 releaseTime;
} HwAdsrEnvelope;

/*
 * --INFO--
 *
 * Function: hwSetADSR
 * EN v1.0 Address: 0x8028348C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802835C0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwSetADSR(int slot, u32 *adsr, u8 mode)
{
    u8 *entry;
    HwAdsrEnvelope *envelope;
    u32 offset;
    u32 value;

    envelope = (HwAdsrEnvelope *)adsr;
    switch (mode) {
    case 0:
        offset = slot * 0xf4;
        entry = dspVoice;
        entry += offset;
        *(u8 *)(entry + 0xa4) = 0;
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xb8) = envelope->attack;
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xbc) = envelope->decay;

        value = envelope->sustain << 3;
        if (value > 0x7fff) {
            value = 0x7fff;
        }

        entry = dspVoice;
        entry += offset;
        *(u16 *)(entry + 0xc0) = value;
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xc4) = envelope->release;
        break;
    case 1:
    case 2:
        offset = slot * 0xf4;
        entry = dspVoice;
        entry += offset;
        *(u8 *)(entry + 0xa4) = 1;
        entry = dspVoice;
        entry += offset;
        *(u8 *)(entry + 0xca) = 0;

        if (mode == 1) {
            value = voiceConvertDbToLinear(adsr[0]);
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xb8) = value & 0xffff;

            value = voiceConvertDbToLinear(adsr[1]);
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xbc) = value & 0xffff;

            value = envelope->decayTime >> 2;
            if (value > 0x3ff) {
                value = 0x3ff;
            }

            entry = dspVoice;
            entry += offset;
            *(u16 *)(entry + 0xc0) = 0xc1 - voiceAdsrDecayTable[value];
        } else {
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xb8) = adsr[0] & 0xffff;
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xbc) = adsr[1] & 0xffff;
            entry = dspVoice;
            entry += offset;
            *(u16 *)(entry + 0xc0) = envelope->decayTime;
        }

        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xc4) = envelope->releaseTime;
        break;
    }

    offset = slot * 0xf4;
    entry = dspVoice;
    entry += offset;
    *(u32 *)(entry + 0x24) |= 0x10;
}

/*
 * --INFO--
 *
 * Function: FUN_80283494
 * EN v1.0 Address: 0x80283494
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802835E0
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80283494(uint param_1)
{
    return 0;
}
