#include "ghidra_import.h"

extern u8 *synthVoice;
extern int audioFn_80278b94(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8,
                       int p9, int p10, int p11, int p12, int p13, int p14, int p15, int p16);
extern void synthCopyHandleFXState(int voice, int state);
void fn_80275CB8(int state);
extern void sndConvertMs(u32 *p);
extern void sndConvertTicks(u32 *p, int state);
extern int dataGetSample(u32 key, u32 *out);
extern void hwInitSamplePlayback(u32 voice, u32 sampleId, u32 *sampleInfo, u32 noKeySync,
                                 u32 priority, u32 handle, u32 noStartOffset, u8 restart);
extern u32 countLeadingZeros(u32 value);
extern void fn_80271370(int state);
extern u32 lbl_803CA2B0[];
extern void *dataGetCurve(u16 key);
extern u32 fn_8027A60C(u32 value);
extern int fn_8027A8D4(int state);
extern void hwSetADSR(int slot, u32 *adsr, u8 mode);
extern u8 lbl_8032F79C[];
extern f32 lbl_8032FB9C[];
extern f32 lbl_803E77F0;
extern f32 lbl_803E77F4;
extern f32 lbl_803E77F8;
extern f64 lbl_803E7800;
extern f64 lbl_803E7808;

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

    result = audioFn_80278b94(*(u32 *)args >> 16,
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
        u8 *vp = synthVoice + voice * 0x404;
        *(int *)(state + 0x108) = *(int *)(vp + 0xf8);
        *(int *)(synthVoice + voice * 0x404 + 0xf0) = *(int *)(state + 0xf4);

        if (*(int *)(state + 0xec) != -1) {
            int prev = *(int *)(state + 0xec);
            *(int *)(synthVoice + voice * 0x404 + 0xec) = prev;
            *(int *)(synthVoice + (prev & 0xff) * 0x404 + 0xf0) = result;
        }
        *(int *)(state + 0xec) = result;

        if (*(u8 *)(state + 0x11d) != 0) {
            synthCopyHandleFXState((int)(synthVoice + voice * 0x404), state);
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
    found = dataGetSample(sampleId, lbl_803CA2B0);
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
 * Resolve ADSR parameters and send them to the hardware voice.
 */
void fn_80275E48(int state, u32 *args)
{
    u8 *table;
    u16 *words;
    u16 sustainIndex;
    u32 velCurve;
    u32 keyCurve;
    int bend;
    u32 adsr[3];
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } conv;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } curve;

    table = dataGetCurve((*args >> 8) & 0xffff);
    if (table != 0) {
        words = (u16 *)table;
        if ((*args >> 0x18) == 0) {
            adsr[0] = (((u16)((words[0] << 8) | ((u32)words[0] >> 8))) << 16) |
                      (u16)((words[1] << 8) | ((u32)words[1] >> 8));
            adsr[1] = (((u16)((words[2] << 8) | ((u32)words[2] >> 8))) << 16) |
                      (u16)((words[3] << 8) | ((u32)words[3] >> 8));
            hwSetADSR(*(u32 *)(state + 0xf4) & 0xff, adsr, 0);
        } else {
            adsr[0] = ((u32)table[3] << 24) | ((u32)table[2] << 16) |
                      ((u32)table[1] << 8) | table[0];
            adsr[1] = ((u32)table[7] << 24) | ((u32)table[6] << 16) |
                      ((u32)table[5] << 8) | table[4];
            sustainIndex = (u16)((words[4] << 8) | ((u32)words[4] >> 8));
            *(u16 *)((u8 *)adsr + 8) =
                (u16)(int)(lbl_803E77F0 *
                           *(f32 *)((u8 *)lbl_8032FB9C + ((sustainIndex >> 3) & 0x1ffc)));
            *(u16 *)((u8 *)adsr + 10) =
                (u16)((words[5] << 8) | ((u32)words[5] >> 8));
            velCurve = ((u32)table[15] << 24) | ((u32)table[14] << 16) |
                       ((u32)table[13] << 8) | table[12];
            keyCurve = ((u32)table[19] << 24) | ((u32)table[18] << 16) |
                       ((u32)table[17] << 8) | table[16];
            if (velCurve != 0x80000000) {
                conv.word.hi = 0x43300000;
                conv.word.lo = *(u32 *)(state + 0x158);
                curve.word.hi = 0x43300000;
                curve.word.lo = velCurve ^ 0x80000000;
                bend = (int)(lbl_803E77F4 * (f32)(conv.d - lbl_803E7800) *
                             (f32)(curve.d - lbl_803E7808));
                adsr[0] += bend;
            }
            if (keyCurve != 0x80000000) {
                conv.word.hi = 0x43300000;
                conv.word.lo = *(u8 *)(state + 0x12f);
                curve.word.hi = 0x43300000;
                curve.word.lo = keyCurve ^ 0x80000000;
                bend = (int)(lbl_803E77F8 * (f32)(conv.d - lbl_803E7800) *
                             (f32)(curve.d - lbl_803E7808));
                adsr[1] += bend;
            }
            hwSetADSR(*(u32 *)(state + 0xf4) & 0xff, adsr, 1);
        }
        *(u32 *)(state + 0x118) |= 0x100;
    }
}

/*
 * Configure the per-voice envelope state from an ADSR/keygroup table.
 */
void fn_802760A0(int state, u32 *args)
{
    s16 basePan;
    u16 decayRaw;
    u16 releaseRaw;
    u32 velCurve;
    u32 keyCurve;
    u32 decayIndex;
    u32 panDelta;
    u32 panScaled;
    int attack;
    int decay;
    int delta;
    u8 *table;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } conv;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } curve;

    table = dataGetCurve((*args >> 8) & 0xffff);
    if (table != 0) {
        *(s16 *)(state + 0x204) = (s16)((s8)args[1] << 8);
        basePan = *(s16 *)(state + 0x204);
        panDelta = (u32)(s16)(s8)(args[1] >> 8);
        panScaled = panDelta << 8;
        delta = (int)panScaled / 100 + ((int)(panScaled | (panDelta >> 24)) >> 31);
        delta = (s16)delta - (s16)(delta >> 31);
        if (basePan < 0) {
            *(s16 *)(state + 0x204) = basePan - (s16)delta;
        } else {
            *(s16 *)(state + 0x204) = basePan + (s16)delta;
        }

        decayRaw = *(u16 *)(table + 8);
        releaseRaw = *(u16 *)(table + 10);
        attack = ((u32)table[3] << 24) | ((u32)table[2] << 16) | ((u32)table[1] << 8) |
                 table[0];
        decay = ((u32)table[7] << 24) | ((u32)table[6] << 16) | ((u32)table[5] << 8) |
                table[4];
        velCurve = ((u32)table[15] << 24) | ((u32)table[14] << 16) |
                   ((u32)table[13] << 8) | table[12];
        keyCurve = ((u32)table[19] << 24) | ((u32)table[18] << 16) |
                   ((u32)table[17] << 8) | table[16];

        if (velCurve != 0x80000000) {
            conv.word.hi = 0x43300000;
            conv.word.lo = *(u32 *)(state + 0x158);
            curve.word.hi = 0x43300000;
            curve.word.lo = velCurve ^ 0x80000000;
            attack += (int)(lbl_803E77F4 * (f32)(conv.d - lbl_803E7800) *
                            (f32)(curve.d - lbl_803E7808));
        }
        if (keyCurve != 0x80000000) {
            conv.word.hi = 0x43300000;
            conv.word.lo = *(u8 *)(state + 0x12f);
            curve.word.hi = 0x43300000;
            curve.word.lo = keyCurve ^ 0x80000000;
            decay += (int)(lbl_803E77F8 * (f32)(conv.d - lbl_803E7800) *
                           (f32)(curve.d - lbl_803E7808));
        }

        *(u8 *)(state + 0x1dc) = 1;
        *(u8 *)(state + 0x202) = 0;
        *(u32 *)(state + 0x1f0) = fn_8027A60C(attack);
        *(u32 *)(state + 0x1f4) = fn_8027A60C(decay);
        decayIndex = ((decayRaw & 0xff) << 8 | ((u32)decayRaw >> 8)) >> 2;
        if (decayIndex > 0x3ff) {
            decayIndex = 0x3ff;
        }
        *(u16 *)(state + 0x1f8) = 0xc1 - lbl_8032F79C[decayIndex];
        *(u32 *)(state + 0x1fc) = ((releaseRaw & 0xff) << 8) | ((u32)releaseRaw >> 8);
        fn_8027A8D4(state + 0x1dc);
        *(u32 *)(state + 0x114) |= 0x200;
    }
}

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
