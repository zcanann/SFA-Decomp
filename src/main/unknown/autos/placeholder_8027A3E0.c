#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027A3E0.h"

extern u32 __cvt_fp2unsigned(double x);
extern f32 powf(f32 x, f32 y);

extern u8 voiceMidiKeySlots[][16];
extern u8 voiceDirectSlots[];
extern u8 lbl_803BD150[];
extern f32 voicePitchUpTable[];
extern f32 voicePitchDownTable[];
extern f32 lbl_803E7818;
extern f32 lbl_803E7828;
extern f32 lbl_803E7830;
extern f32 lbl_803E7834;
extern f32 lbl_803E7838;
extern f64 lbl_803E7820;
extern f64 lbl_803E7840;

/*
 * Mark all entries of the MIDI voice-id table and direct voice-id table
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
    u8 *p = &voiceMidiKeySlots[0][0];
    int i;

    for (i = 0; i < 4; i++) {
        p[0] = 0xff;
        p[1] = 0xff;
        p[2] = 0xff;
        p[3] = 0xff;
        p[4] = 0xff;
        p[5] = 0xff;
        p[6] = 0xff;
        p[7] = 0xff;
        p[8] = 0xff;
        p[9] = 0xff;
        p[10] = 0xff;
        p[11] = 0xff;
        p[12] = 0xff;
        p[13] = 0xff;
        p[14] = 0xff;
        p[15] = 0xff;
        p[16] = 0xff;
        p[17] = 0xff;
        p[18] = 0xff;
        p[19] = 0xff;
        p[20] = 0xff;
        p[21] = 0xff;
        p[22] = 0xff;
        p[23] = 0xff;
        p[24] = 0xff;
        p[25] = 0xff;
        p[26] = 0xff;
        p[27] = 0xff;
        p[28] = 0xff;
        p[29] = 0xff;
        p[30] = 0xff;
        p[31] = 0xff;
        p += 32;
    }
    voiceDirectSlots[0] = 0xff;
    voiceDirectSlots[1] = 0xff;
    voiceDirectSlots[2] = 0xff;
    voiceDirectSlots[3] = 0xff;
    voiceDirectSlots[4] = 0xff;
    voiceDirectSlots[5] = 0xff;
    voiceDirectSlots[6] = 0xff;
    voiceDirectSlots[7] = 0xff;
    voiceDirectSlots[8] = 0xff;
    voiceDirectSlots[9] = 0xff;
    voiceDirectSlots[10] = 0xff;
    voiceDirectSlots[11] = 0xff;
    voiceDirectSlots[12] = 0xff;
    voiceDirectSlots[13] = 0xff;
    voiceDirectSlots[14] = 0xff;
    voiceDirectSlots[15] = 0xff;
    voiceDirectSlots[16] = 0xff;
    voiceDirectSlots[17] = 0xff;
    voiceDirectSlots[18] = 0xff;
    voiceDirectSlots[19] = 0xff;
    voiceDirectSlots[20] = 0xff;
    voiceDirectSlots[21] = 0xff;
    voiceDirectSlots[22] = 0xff;
    voiceDirectSlots[23] = 0xff;
    voiceDirectSlots[24] = 0xff;
    voiceDirectSlots[25] = 0xff;
    voiceDirectSlots[26] = 0xff;
    voiceDirectSlots[27] = 0xff;
    voiceDirectSlots[28] = 0xff;
    voiceDirectSlots[29] = 0xff;
    voiceDirectSlots[30] = 0xff;
    voiceDirectSlots[31] = 0xff;
    voiceDirectSlots[32] = 0xff;
    voiceDirectSlots[33] = 0xff;
    voiceDirectSlots[34] = 0xff;
    voiceDirectSlots[35] = 0xff;
    voiceDirectSlots[36] = 0xff;
    voiceDirectSlots[37] = 0xff;
    voiceDirectSlots[38] = 0xff;
    voiceDirectSlots[39] = 0xff;
    voiceDirectSlots[40] = 0xff;
    voiceDirectSlots[41] = 0xff;
    voiceDirectSlots[42] = 0xff;
    voiceDirectSlots[43] = 0xff;
    voiceDirectSlots[44] = 0xff;
    voiceDirectSlots[45] = 0xff;
    voiceDirectSlots[46] = 0xff;
    voiceDirectSlots[47] = 0xff;
    voiceDirectSlots[48] = 0xff;
    voiceDirectSlots[49] = 0xff;
    voiceDirectSlots[50] = 0xff;
    voiceDirectSlots[51] = 0xff;
    voiceDirectSlots[52] = 0xff;
    voiceDirectSlots[53] = 0xff;
    voiceDirectSlots[54] = 0xff;
    voiceDirectSlots[55] = 0xff;
    voiceDirectSlots[56] = 0xff;
    voiceDirectSlots[57] = 0xff;
    voiceDirectSlots[58] = 0xff;
    voiceDirectSlots[59] = 0xff;
    voiceDirectSlots[60] = 0xff;
    voiceDirectSlots[61] = 0xff;
    voiceDirectSlots[62] = 0xff;
    voiceDirectSlots[63] = 0xff;
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
int voiceScaleSampleRate(u16 x)
{
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;

    conv.w.lo = (u32)x;
    conv.w.hi = 0x43300000;
    return (int)(lbl_803E7818 * (conv.d - lbl_803E7820));
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
u32 voiceGetPitchRatio(u8 noteIn, u32 packed)
{
    u8 baseNote;
    u8 inputNote;
    f32 freq;
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;

    if (packed == 0xffffffffU) {
        packed = 0x40005622;
    }
    baseNote = (u8)(packed >> 24);
    inputNote = noteIn;
    if (inputNote != baseNote) {
        if (baseNote < inputNote) {
            u32 d = inputNote - baseNote;
            freq = voicePitchUpTable[d];
        } else {
            u32 d = baseNote - inputNote;
            freq = voicePitchDownTable[d];
        }
        conv.w.lo = packed & 0xffffff;
        conv.w.hi = 0x43300000;
        freq = (conv.d - lbl_803E7820) * freq;
    } else {
        conv.w.lo = packed & 0xffffff;
        conv.w.hi = 0x43300000;
        freq = conv.d - lbl_803E7820;
    }
    conv.w.lo = *(u32 *)lbl_803BD150;
    conv.w.hi = 0x43300000;
    return __cvt_fp2unsigned((freq * lbl_803E7828) /
                             (f32)(conv.d - lbl_803E7820));
}

/*
 * dB-to-linear-level conversion via pow + magic conversion.
 *
 * EN v1.0 Address: 0x8027A29C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A60C
 * EN v1.1 Size: 84b
 */
u32 voiceConvertDbToLinear(u32 dbCents)
{
    union {
        struct { u32 hi, lo; } w;
        f64 d;
    } conv;
    f32 scaledDb;
    f32 base;
    f32 result;

    conv.w.hi = 0x43300000;
    conv.w.lo = dbCents ^ 0x80000000U;
    scaledDb = conv.d - lbl_803E7840;
    base = powf(lbl_803E7834, lbl_803E7838 * scaledDb);
    result = lbl_803E7830 * base;
    return __cvt_fp2unsigned(result);
}
