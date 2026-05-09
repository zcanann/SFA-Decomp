#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802835C0.h"

extern u8 lbl_8032F79C[];
extern u8 *dspVoice;

extern u32 voiceConvertDbToLinear(u32 value);

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
    u32 offset;
    u32 value;

    switch (mode) {
    case 0:
        offset = slot * 0xf4;
        entry = dspVoice;
        entry += offset;
        *(u8 *)(entry + 0xa4) = 0;
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xb8) = *(u16 *)((u8 *)adsr + 0);
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xbc) = *(u16 *)((u8 *)adsr + 2);

        value = *(u16 *)((u8 *)adsr + 4) << 3;
        if (value > 0x7fff) {
            value = 0x7fff;
        }

        entry = dspVoice;
        entry += offset;
        *(u16 *)(entry + 0xc0) = value;
        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xc4) = *(u16 *)((u8 *)adsr + 6);
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

            value = *(u16 *)((u8 *)adsr + 8) >> 2;
            if (value > 0x3ff) {
                value = 0x3ff;
            }

            entry = dspVoice;
            entry += offset;
            *(u16 *)(entry + 0xc0) = 0xc1 - lbl_8032F79C[value];
        } else {
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xb8) = adsr[0] & 0xffff;
            entry = dspVoice;
            entry += offset;
            *(u32 *)(entry + 0xbc) = adsr[1] & 0xffff;
            entry = dspVoice;
            entry += offset;
            *(u16 *)(entry + 0xc0) = *(u16 *)((u8 *)adsr + 8);
        }

        entry = dspVoice;
        entry += offset;
        *(u32 *)(entry + 0xc4) = *(u16 *)((u8 *)adsr + 10);
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
