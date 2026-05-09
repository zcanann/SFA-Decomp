#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80271BFC.h"

extern u32 fn_8027ADD8(u8 voiceIdx);
extern void voiceKill(u8 voiceIdx);
extern void fn_80278560(void);
extern void fn_8027AFC0(u32 packed);
extern u32 hwGetVirtualSampleID(int slot);
extern void sndConvertMs(u32 *p);
extern void fn_8027142C(u8 *fade);

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD364[];
extern u8 gSynthInitialized;
extern u32 lbl_803DE260;
extern u8 *lbl_803DE268;
extern f32 lbl_803E7798;
extern f32 lbl_803E77A8;
extern f32 lbl_803E77D4;

typedef struct SynthFadeSlotLocal {
    f32 current;
    f32 target;
    f32 start;
    f32 pos;
    f32 step;
    f32 pad14[5];
    u32 handle;
    u8 action;
    u8 state;
    u8 pad2e[2];
} SynthFadeSlotLocal;

/*
 * Route synth fade commands to one slot or to the broadcast pseudo-slots
 * 0xfa through 0xff.
 */
void fn_80271B4C(u32 volume, u32 timeMs, u32 target, u8 action, u32 handle)
{
    u32 convertedTime;
    u32 targetIndex;
    u32 i;
    u32 matchState;
    f32 targetVolume;
    SynthFadeSlotLocal *fade;

    convertedTime = timeMs & 0xffff;
    if (convertedTime != 0) {
        sndConvertMs(&convertedTime);
    }

    targetIndex = target & 0xff;
    if (targetIndex == 0xff) {
        targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
        fade = (SynthFadeSlotLocal *)(lbl_803BCD90 + 0x5d4);
        for (i = 0; i < 0x20; i++, fade++) {
            if ((fade->state == 0) || (fade->state == 1)) {
                fade->action = action;
                fade->handle = 0xffffffff;
                if (convertedTime == 0) {
                    fade->target = targetVolume;
                    fade->current = targetVolume;
                    if (fade->handle != 0xffffffff) {
                        fn_8027142C((u8 *)fade);
                    }
                } else {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->pos = lbl_803E77A8;
                    fade->step = lbl_803E77D4 / (f32)convertedTime;
                }
                lbl_803DE260 |= 1U << i;
            }
        }
        return;
    }

    if (targetIndex == 0xfc) {
        targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
        fade = (SynthFadeSlotLocal *)(lbl_803BCD90 + 0x5d4);
        for (i = 0; i < 0x20; i++, fade++) {
            if ((fade->state == 2) || (fade->state == 3)) {
                fade->action = action;
                fade->handle = 0xffffffff;
                if (convertedTime == 0) {
                    fade->target = targetVolume;
                    fade->current = targetVolume;
                    if (fade->handle != 0xffffffff) {
                        fn_8027142C((u8 *)fade);
                    }
                } else {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->pos = lbl_803E77A8;
                    fade->step = lbl_803E77D4 / (f32)convertedTime;
                }
                lbl_803DE260 |= 1U << i;
            }
        }
        return;
    }

    if (targetIndex >= 0xfa) {
        switch (targetIndex) {
        case 0xfa:
            matchState = 2;
            break;
        case 0xfb:
            matchState = 3;
            break;
        case 0xfd:
            matchState = 0;
            break;
        case 0xfe:
        default:
            matchState = 1;
            break;
        }
        targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
        fade = (SynthFadeSlotLocal *)(lbl_803BCD90 + 0x5d4);
        for (i = 0; i < 0x20; i++, fade++) {
            if (fade->state == matchState) {
                fade->action = action;
                fade->handle = 0xffffffff;
                if (convertedTime == 0) {
                    fade->target = targetVolume;
                    fade->current = targetVolume;
                    if (fade->handle != 0xffffffff) {
                        fn_8027142C((u8 *)fade);
                    }
                } else {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->pos = lbl_803E77A8;
                    fade->step = lbl_803E77D4 / (f32)convertedTime;
                }
                lbl_803DE260 |= 1U << i;
            }
        }
        return;
    }

    fade = (SynthFadeSlotLocal *)(lbl_803BCD90 + 0x5d4 + targetIndex * 0x30);
    fade->action = action;
    fade->handle = handle;
    if (convertedTime == 0) {
        targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
        fade->target = targetVolume;
        fade->current = targetVolume;
        if (fade->handle != 0xffffffff) {
            fn_8027142C((u8 *)fade);
        }
    } else {
        fade->start = fade->current;
        fade->target = lbl_803E7798 * (f32)(volume & 0xff);
        fade->pos = lbl_803E77A8;
        fade->step = lbl_803E77D4 / (f32)convertedTime;
    }
    lbl_803DE260 |= 1U << targetIndex;
}

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
    if (((v[0x601] != 4) && ((lbl_803DE260 & (1U << voiceIdx)) != 0)) &&
        (*(f32 *)(v + 0x5dc) > *(f32 *)(v + 0x5d8))) {
        return 1;
    }
    return 0;
}

/*
 * Set a single byte field on a voice slot.
 *
 * EN v1.1 Address: 0x80271FB0
 * EN v1.1 Size: 40b
 */
void fn_80271FB0(u32 voiceIdx, u8 value)
{
    if (gSynthInitialized == 0) {
        return;
    }
    *(u8 *)(lbl_803BD364 + (voiceIdx & 0xff) * 0x30 + 0x2d) = value;
}

/*
 * Voice command dispatcher: runs different actions per command code.
 *   0 -> claim slot via fn_8027ADD8
 *   1 -> voiceKill
 *   2 -> vacate-or-skip via hwGetVirtualSampleID + fn_8027AFC0 + check
 *   3 -> simple vacate via hwGetVirtualSampleID + fn_8027AFC0
 *
 * EN v1.0 Address: 0x802719B0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80271FD8
 * EN v1.1 Size: 204b
 */
int fn_80271FD8(int mode, u32 arg)
{
    u32 result = 0;

    switch (mode) {
    case 0: {
        u8 *entry;
        u32 offset;
        offset = (arg & 0xff) * 0x404;
        entry = lbl_803DE268 + offset;
        if (entry[0x11c] != 0) {
            break;
        }
        fn_8027AFC0(hwGetVirtualSampleID(arg & 0xff));
        entry = lbl_803DE268 + offset;
        if (arg != *(u32 *)(entry + 0xf4)) {
            break;
        }
        fn_80278560();
        break;
    }
    case 1:
        voiceKill(arg & 0xff);
        break;
    case 2:
        result = fn_8027ADD8(arg & 0xff);
        break;
    case 3: {
        fn_8027AFC0(hwGetVirtualSampleID(arg & 0xff));
        break;
    }
    }
    return result;
}
