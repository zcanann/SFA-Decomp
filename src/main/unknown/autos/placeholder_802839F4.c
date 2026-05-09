#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802839F4.h"

extern void salDeactivateVoice(void *entry);
extern void fn_8027BEBC(void);
extern void fn_8027BFC4(void);
extern void fn_8027F2AC();
extern u8 *dspVoice;
extern u8 lbl_803CC1E0[];
extern u8 lbl_802C2820[];

extern f32 lbl_803E78E0;
extern f32 lbl_803E78E4;

/*
 * hwSetVolume - large mix-volume setter; computes 4-channel pan from
 * 3-axis float input via fn_8027F2AC, clamps each to s16, and writes
 * back to the voice's pan/volume table.
 *
 * EN v1.0 Address: 0x8028383C
 * EN v1.0 Size: 720b (0x2D0)
 */
void hwSetVolume(int slot, undefined4 p2, f32 a, f32 b, f32 c, u32 aux, undefined4 p7)
{
    u8 *voice;
    u8 *aux_entry;
    f32 out[9];
    int v0, v1, v2;

    voice = dspVoice + slot * 0xf4;

    if (a >= 1.0f) a = 1.0f;
    if (b >= 1.0f) b = 1.0f;
    if (c >= 1.0f) c = 1.0f;

    aux_entry = lbl_803CC1E0 + *(u8 *)(voice + 0xef) * 0xbc;

    fn_8027F2AC(p2, out, aux, p7,
                (*(u32 *)(voice + 0xf0) & 0x80000000u) != 0,
                *(u32 *)(aux_entry + 0x54) == 1,
                a, b, c);

    v0 = (s32)(lbl_803E78E4 * out[0]);
    v1 = (s32)(lbl_803E78E4 * out[1]);
    v2 = (s32)(lbl_803E78E4 * out[2]);
    if (*(u8 *)(voice + 0xe5) == 0xff
        || *(u16 *)(voice + 0x4c) != (u16)v0
        || *(u16 *)(voice + 0x4e) != (u16)v1
        || *(u16 *)(voice + 0x50) != (u16)v2) {
        *(u16 *)(voice + 0x4c) = v0;
        *(u16 *)(voice + 0x4e) = v1;
        *(u16 *)(voice + 0x50) = v2;
        *(u32 *)(voice + 0x24) |= 0x1;
        *(u8 *)(voice + 0xe5) = 0;
    }

    v0 = (s32)(lbl_803E78E4 * out[3]);
    v1 = (s32)(lbl_803E78E4 * out[4]);
    v2 = (s32)(lbl_803E78E4 * out[5]);
    if (*(u8 *)(voice + 0xe6) == 0xff
        || *(u16 *)(voice + 0x52) != (u16)v0
        || *(u16 *)(voice + 0x54) != (u16)v1
        || *(u16 *)(voice + 0x56) != (u16)v2) {
        *(u16 *)(voice + 0x52) = v0;
        *(u16 *)(voice + 0x54) = v1;
        *(u16 *)(voice + 0x56) = v2;
        *(u32 *)(voice + 0x24) |= 0x2;
        *(u8 *)(voice + 0xe6) = 0;
    }

    v0 = (s32)(lbl_803E78E4 * out[6]);
    v1 = (s32)(lbl_803E78E4 * out[7]);
    v2 = (s32)(lbl_803E78E4 * out[8]);
    if (*(u8 *)(voice + 0xe7) == 0xff
        || *(u16 *)(voice + 0x58) != (u16)v0
        || *(u16 *)(voice + 0x5a) != (u16)v1
        || *(u16 *)(voice + 0x5c) != (u16)v2) {
        *(u16 *)(voice + 0x58) = v0;
        *(u16 *)(voice + 0x5a) = v1;
        *(u16 *)(voice + 0x5c) = v2;
        *(u32 *)(voice + 0x24) |= 0x4;
        *(u8 *)(voice + 0xe7) = 0;
    }

    if (*(u32 *)(voice + 0xf0) & 0x80000000) {
        u8 *p = lbl_802C2820 + (((aux >> 16) & 0xff) << 1);
        *(u16 *)(voice + 0xd0) = *(u16 *)p;
        *(u16 *)(voice + 0xd2) = 0x20 - *(u16 *)p;
        *(u32 *)(voice + 0x24) |= 0x200;
    }
}

/*
 * Disable a voice slot.
 *
 * EN v1.0 Address: 0x80283AB0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B0C
 * EN v1.1 Size: 44b
 */
void hwOff(int slot)
{
    salDeactivateVoice(dspVoice + slot * 0xf4);
}

/*
 * Set the four AUX-mix DSP processing callbacks for a voice slot.
 *
 * EN v1.0 Address: 0x80283AB4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B38
 * EN v1.1 Size: 40b
 */
void hwSetAUXProcessingCallbacks(u8 idx, void *cb0, void *cb1, void *cb2, void *cb3)
{
    u8 *entry = lbl_803CC1E0 + idx * 0xbc;
    *(void **)(entry + 0xac) = cb0;
    *(void **)(entry + 0xb4) = cb1;
    *(void **)(entry + 0xb0) = cb2;
    *(void **)(entry + 0xb8) = cb3;
}

/*
 * Activate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B60
 * EN v1.1 Size: 32b
 */
void hwActivateStudio(void)
{
    fn_8027BEBC();
}

/*
 * Deactivate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B80
 * EN v1.1 Size: 32b
 */
void hwDeactivateStudio(void)
{
    fn_8027BFC4();
}
