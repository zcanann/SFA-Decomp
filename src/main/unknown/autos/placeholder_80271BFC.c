#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80271BFC.h"

extern u32 fn_8027ADD8(u8 voiceIdx);
extern void fn_8027A02C(u8 voiceIdx);
extern void fn_80278560(void);
extern void fn_8027AFC0(u32 packed);
extern u16 hwGetVirtualSampleID(int slot);

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD364[];
extern u8 gSynthInitialized;
extern u32 lbl_803DE260;
extern u8 *lbl_803DE268;

/*
 * fn_80271B4C — large MIDI sequencer step (~1000 bytes); stubbed
 * here so callers compile. Full implementation requires more analysis.
 */
#pragma dont_inline on
void fn_80271B4C(void)
{
}
#pragma dont_inline reset

/*
 * Voice "is loud" predicate: returns 1 if voice is active (state != 4),
 * the global active mask has its bit set, AND its current volume
 * (offset 0x5dc) > target volume (offset 0x5d8). Otherwise 0.
 *
 * EN v1.0 Address: 0x80271970
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80271F5C
 * EN v1.1 Size: 84b
 */
int fn_80271F5C(u8 voiceIdx)
{
    u8 *v = lbl_803BCD90 + voiceIdx * 0x30;
    if (v[0x601] == 4) {
        return 0;
    }
    if ((lbl_803DE260 & (1U << voiceIdx)) == 0) {
        return 0;
    }
    if (*(f32 *)(v + 0x5dc) <= *(f32 *)(v + 0x5d8)) {
        return 0;
    }
    return 1;
}

/*
 * Set a single byte field on a voice slot.
 *
 * EN v1.1 Address: 0x80271FB0
 * EN v1.1 Size: 40b
 */
void fn_80271FB0(u8 voiceIdx, u8 value)
{
    if (gSynthInitialized == 0) {
        return;
    }
    *(u8 *)(lbl_803BD364 + voiceIdx * 0x30 + 0x2d) = value;
}

/*
 * Voice command dispatcher: runs different actions per command code.
 *   0 → claim slot via fn_8027ADD8
 *   1 → fn_8027A02C
 *   2 → vacate-or-skip via hwGetVirtualSampleID + fn_8027AFC0 + check
 *   3 → simple vacate via hwGetVirtualSampleID + fn_8027AFC0
 *
 * EN v1.0 Address: 0x802719B0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80271FD8
 * EN v1.1 Size: 204b
 */
int fn_80271FD8(int mode, u8 arg)
{
    u32 result = 0;

    switch (mode) {
    case 0: {
        u8 *entry;
        u32 packed;
        u32 offset;
        offset = (u32)arg * 0x404;
        entry = lbl_803DE268 + offset;
        if (entry[0x11c] != 0) {
            break;
        }
        packed = hwGetVirtualSampleID(arg);
        fn_8027AFC0(packed);
        entry = lbl_803DE268 + offset;
        if (arg != *(u32 *)(entry + 0xf4)) {
            break;
        }
        fn_80278560();
        break;
    }
    case 1:
        fn_8027A02C(arg);
        break;
    case 2:
        result = fn_8027ADD8(arg);
        break;
    case 3: {
        u32 packed = hwGetVirtualSampleID(arg);
        fn_8027AFC0(packed);
        break;
    }
    }
    return result;
}
