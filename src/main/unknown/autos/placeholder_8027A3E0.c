#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027A3E0.h"

extern u32 __cvt_fp2unsigned(double x);
extern double __ieee754_pow(double x, double y);

extern u8 voiceMidiKeySlots[];
extern u8 voiceDirectSlots[];
extern u8 lbl_803BD150[];
extern f32 lbl_8032F218[];
extern f32 lbl_8032F418[];
extern f32 lbl_803E7818;
extern f32 lbl_803E7828;
extern f32 lbl_803E7830;
extern f32 lbl_803E7834;
extern f32 lbl_803E7838;
extern f64 lbl_803E7820;
extern f64 lbl_803E7840;

/*
 * Mark all entries of the MIDI voice-id table and direct voice-id table as
 * as 0xFF (free). The asm has the inner stb's unrolled
 * to 16 per loop iter for the 128-byte table (4 outer x 32 bytes),
 * and the 64-byte table is fully unrolled.
 *
 * EN v1.0 Address: 0x8027A270
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A330
 * EN v1.1 Size: 432b
 */
void voiceInitRegistrationTables(void)
{
    u8 *p = voiceMidiKeySlots;
    int i;
    int j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 32; j++) {
            p[j] = 0xff;
        }
        p += 32;
    }
    {
        u8 *q = voiceDirectSlots;
        for (j = 0; j < 64; j++) {
            q[j] = 0xff;
        }
    }
}

/*
 * Convert a u16 sample-rate-style value to a scaled int via the magic
 * f64 conversion trick.
 *
 * EN v1.0 Address: 0x8027A294
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A4E0
 * EN v1.1 Size: 60b
 */
int fn_8027A4E0(u16 x)
{
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;
    conv.w.hi = 0x43300000;
    conv.w.lo = (u32)x;
    return (int)((conv.d - lbl_803E7820) * lbl_803E7818);
}

/*
 * Pitch-table lookup with semitone interpolation: from cents-encoded
 * input (high byte = base note, low byte = fractional semitone),
 * pick a base frequency from one of two tables (above/below center
 * note), scale by fraction, then convert to a u32 sample-rate ratio.
 *
 * EN v1.0 Address: 0x8027A298
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A51C
 * EN v1.1 Size: 240b
 */
u32 fn_8027A51C(u8 noteIn, u32 packed)
{
    u8 baseNote;
    u8 inputNote;
    f32 freq;
    f64 fracD;
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;

    if (packed == 0xffffffffU) {
        packed = 0x40005622;
    }
    baseNote = (u8)(packed >> 24);
    inputNote = noteIn;
    if (inputNote == baseNote) {
        conv.w.hi = 0x43300000;
        conv.w.lo = packed & 0xffffff;
        freq = (f32)(conv.d - lbl_803E7820);
    } else if (baseNote >= inputNote) {
        u32 d = baseNote - inputNote;
        f32 mul = lbl_8032F418[d];
        conv.w.hi = 0x43300000;
        conv.w.lo = packed & 0xffffff;
        freq = (f32)((conv.d - lbl_803E7820) * mul);
    } else {
        u32 d = inputNote - baseNote;
        f32 mul = lbl_8032F218[d];
        conv.w.hi = 0x43300000;
        conv.w.lo = packed & 0xffffff;
        freq = (f32)((conv.d - lbl_803E7820) * mul);
    }
    {
        union {
            struct { u32 hi, lo; } w;
            f64 d;
        } conv2;
        u32 sampleRate = *(u32 *)lbl_803BD150;
        conv2.w.hi = 0x43300000;
        conv2.w.lo = sampleRate;
        return __cvt_fp2unsigned((f64)(freq * lbl_803E7828) /
                                 (conv2.d - lbl_803E7820));
    }
}

/*
 * dB-to-linear-level conversion via pow + magic conversion.
 *
 * EN v1.0 Address: 0x8027A29C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A60C
 * EN v1.1 Size: 84b
 */
u32 fn_8027A60C(u32 dbCents)
{
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;
    f64 base;
    f64 result;

    conv.w.hi = 0x43300000;
    conv.w.lo = dbCents ^ 0x80000000U;
    base = __ieee754_pow(lbl_803E7834,
                         lbl_803E7838 * (conv.d - lbl_803E7840));
    result = lbl_803E7830 * base;
    return __cvt_fp2unsigned(result);
}
