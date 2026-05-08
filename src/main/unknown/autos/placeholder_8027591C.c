#include "ghidra_import.h"

extern u8 *lbl_803DE268;
extern int fn_80278B94(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8,
                       int p9, int p10, int p11, int p12, int p13, int p14, int p15, int p16);
extern void fn_80271A3C(int voice, int state);
void fn_80275CB8(int state);
extern void sndConvertMs(u32 *p);
extern void sndConvertTicks(u32 *p, int state);
extern int fn_80274F20(u32 key, u32 *out);
extern void hwInitSamplePlayback(u32 voice, u32 sampleId, u32 *sampleInfo, u32 noKeySync,
                                 u32 priority, u32 handle, u32 noStartOffset, u8 restart);
extern u32 countLeadingZeros(u32 value);
extern void fn_80271370(int state);
extern u32 lbl_803CA2B0[];

/*
 * fn_802757C4 - voice param/key/velocity processor.
 *
 * EN v1.0 Address: 0x802757C4
 * EN v1.0 Size: 408b
 */
void fn_802757C4(int state, int args)
{
    int sum;
    u8 key;
    int result;

    sum = (s32)*(u8 *)(state + 0x12f) + (s32)(s8)((*(u32 *)args >> 8) & 0xff);
    if (sum < 0) {
        key = 0;
    } else if (sum > 0x7f) {
        key = 0x7f;
    } else {
        key = (u8)sum;
    }
    if (*(u8 *)(state + 0x11d) != 0) {
        key |= 0x80;
    }
    *(u8 *)(state + 0x11c) = 1;

    result = fn_80278B94(*(u32 *)args >> 16,
                        (*(u32 *)(args + 4) >> 8) & 0xff,
                        *(u32 *)(args + 4) >> 24,
                        *(u16 *)(state + 0x100), key,
                        (*(u32 *)(state + 0x154) >> 8) & 0xff,
                        (*(u32 *)(state + 0x170) >> 8) & 0xff,
                        *(u8 *)(state + 0x121),
                        *(u8 *)(state + 0x122),
                        *(u8 *)(state + 0x123),
                        *(u32 *)(args + 4) & 0xffff,
                        *(u8 *)(state + 0x120),
                        0,
                        *(u8 *)(state + 0x11e),
                        *(u8 *)(state + 0x11f),
                        *(u8 *)(state + 0x193) == 0);

    *(u8 *)(state + 0x11c) = 0;

    if (result == -1) {
        *(int *)(state + 0x108) = -1;
        return;
    }

    {
        u8 voice = (u8)result;
        u8 *vp = lbl_803DE268 + voice * 0x404;
        *(int *)(state + 0x108) = *(int *)(vp + 0xf8);
        *(int *)(lbl_803DE268 + voice * 0x404 + 0xf0) = *(int *)(state + 0xf4);

        if (*(int *)(state + 0xec) != -1) {
            int prev = *(int *)(state + 0xec);
            *(int *)(lbl_803DE268 + voice * 0x404 + 0xec) = prev;
            *(int *)(lbl_803DE268 + (prev & 0xff) * 0x404 + 0xf0) = result;
        }
        *(int *)(state + 0xec) = result;

        if (*(u8 *)(state + 0x11d) != 0) {
            fn_80271A3C((int)(lbl_803DE268 + voice * 0x404), state);
        }
    }
}

/*
 * Resolve a sample descriptor and start hardware playback for a voice.
 */
void fn_8027595C(int state, u32 *args)
{
    int found;
    u32 mode;
    u32 noStartOffset;
    u32 noKeySync;
    u32 sampleId;

    sampleId = (*args >> 8) & 0xffff;
    found = fn_80274F20(sampleId, lbl_803CA2B0);
    if (found == 0) {
        mode = *args >> 0x18;
        if (mode == 1) {
            lbl_803CA2B0[3] =
                (args[1] * (0x7f - ((*(u32 *)(state + 0x154) >> 0x10) & 0xff))) / 0x7f;
        } else if (mode == 0) {
            lbl_803CA2B0[3] = args[1];
        } else if (mode < 3) {
            lbl_803CA2B0[3] =
                (args[1] * ((*(u32 *)(state + 0x154) >> 0x10) & 0xff)) / 0x7f;
        } else {
            lbl_803CA2B0[3] = 0;
        }
        if (lbl_803CA2B0[4] <= lbl_803CA2B0[3]) {
            lbl_803CA2B0[3] = lbl_803CA2B0[4] - 1;
        }
        noStartOffset = countLeadingZeros(*(u32 *)(state + 0x114) & 0x800);
        noKeySync = countLeadingZeros(*(u32 *)(state + 0x118) & 0x100);
        hwInitSamplePlayback(*(u32 *)(state + 0xf4) & 0xff, sampleId, lbl_803CA2B0,
                             noKeySync >> 5,
                             ((u32)*(u8 *)(state + 0x10c) << 0x18) |
                                 (*(u32 *)(state + 0x110) >> 0xf),
                             *(u32 *)(state + 0xf4), noStartOffset >> 5,
                             *(u8 *)(state + 0x193));
        *(u32 *)(state + 0x124) = lbl_803CA2B0[0];
        if (*(int *)(state + 0x128) != -1) {
            fn_80275CB8(state);
        }
        *(u32 *)(state + 0x118) |= 0x20;
        fn_80271370(state);
    }
}

/*
 * Configure the voice pitch bend ramp and curve flags.
 */
void fn_80275B38(int state, u32 *args)
{
    s8 start;
    s8 target;
    u32 duration[2];

    if (((*args >> 0x18) & 3) == 0) {
        *(u32 *)(state + 0x118) &= ~0x4000;
        *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
    } else {
        *(u32 *)(state + 0x118) |= 0x4000;
    }

    duration[0] = args[1] >> 0x10;
    if (((args[1] >> 8) & 1) == 0) {
        sndConvertTicks(duration, state);
    } else {
        sndConvertMs(duration);
    }
    if (duration[0] == 0) {
        *(u32 *)(state + 0x118) &= ~0x2000;
        *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
    } else {
        *(u32 *)(state + 0x118) |= 0x2000;
        *(u32 *)(state + 0x144) = duration[0];
        start = (s8)(*args >> 8);
        target = (s8)(*args >> 0x10);
        if (start < 0) {
            if (target < 0) {
                *(s8 *)(state + 0x141) = -target;
            } else {
                *(s8 *)(state + 0x141) = target;
            }
            *(s8 *)(state + 0x140) = -start;
            *(u32 *)(state + 0x148) = *(u32 *)(state + 0x144) >> 1;
        } else {
            if (target < 0) {
                if (start == 0) {
                    *(s8 *)(state + 0x141) = -target;
                    *(u32 *)(state + 0x148) = *(u32 *)(state + 0x144) >> 1;
                } else {
                    *(s8 *)(state + 0x141) = 100 - target;
                    start--;
                    *(u32 *)(state + 0x148) = 0;
                }
            } else {
                *(s8 *)(state + 0x141) = target;
                *(u32 *)(state + 0x148) = 0;
            }
            *(s8 *)(state + 0x140) = start;
        }
    }
}

/*
 * fn_80275CB8 - voice processor (~400 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80275CB8(int state)
{
    (void)state;
}
#pragma dont_inline reset

/*
 * fn_80275E48 - voice processor (~600 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80275E48(void) {}
#pragma dont_inline reset

/*
 * fn_802760A0 - voice processor (~640 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_802760A0(void) {}
#pragma dont_inline reset

/*
 * fn_80276320 - voice param store with magic-divide (~160 instructions).
 * Stubbed.
 */
void fn_80276320(int state, u32 *args, u32 idx)
{
    u32 *duration;
    int offset;
    u32 packed;
    u32 initial;
    int stepBase;
    int base;

    offset = (idx & 0xff) * 4;
    packed = *args;
    duration = (u32 *)(state + offset + 0x188);
    *duration = packed >> 0x10;
    sndConvertMs(duration);
    initial = args[1];
    *(u32 *)(state + offset + 0x170) = (*args & 0xff00) << 8;
    stepBase = (s8)initial * 0x10000;
    base = state + offset;
    *(int *)(base + 0x180) = *(int *)(state + offset + 0x170) + stepBase;
    if (*duration == 0) {
        *(int *)(base + 0x178) = stepBase;
    } else {
        *(int *)(base + 0x178) = stepBase / (int)(packed >> 0x10);
    }
    *(u32 *)(state + 0x114) |= 0x2000;
}
