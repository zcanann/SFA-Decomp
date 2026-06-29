#include "main/audio/voice_manage.h"
extern asm u32 __cvt_fp2unsigned(register f64 d);
extern f32 powf(f32 x, f32 y);
extern u8 voiceMidiKeySlots[][SYNTH_VOICE_MIDI_KEY_COUNT];
extern u8 voiceDirectSlots[];
extern u8 lbl_803BD150[];
extern f32 voicePitchUpTable[];
extern f32 voicePitchDownTable[];
extern f32 lbl_803E7818;
extern f32 lbl_803E7828;
extern f32 lbl_803E7830;
extern f32 lbl_803E7834;
extern f32 lbl_803E7838;

/*
 * Mark all entries of the MIDI voice-id table and direct voice-id table
 * as free. The asm has the inner stb's unrolled to two MIDI rows per
 * loop iter, and the direct-voice table is fully unrolled.
 *
 * EN v1.0 Address: 0x8027A270
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027A330
 * EN v1.1 Size: 432b
 */
void voiceInitRegistrationTables(void)
{
    int channel;
    int key;

    for (channel = 0; channel < SYNTH_VOICE_MIDI_CHANNEL_COUNT; channel++)
    {
        for (key = 0; key < SYNTH_VOICE_MIDI_KEY_COUNT; key++)
        {
            voiceMidiKeySlots[channel][key] = SYNTH_VOICE_REGISTRATION_FREE;
        }
    }
    voiceDirectSlots[0] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[1] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[2] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[3] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[4] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[5] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[6] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[7] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[8] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[9] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[10] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[11] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[12] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[13] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[14] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[15] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[16] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[17] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[18] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[19] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[20] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[21] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[22] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[23] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[24] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[25] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[26] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[27] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[28] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[29] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[30] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[31] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[32] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[33] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[34] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[35] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[36] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[37] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[38] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[39] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[40] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[41] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[42] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[43] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[44] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[45] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[46] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[47] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[48] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[49] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[50] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[51] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[52] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[53] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[54] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[55] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[56] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[57] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[58] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[59] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[60] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[61] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[62] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[63] = SYNTH_VOICE_REGISTRATION_FREE;
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
    return (int)(lbl_803E7818 * (f32)(u32)x);
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
    u32 d;

    if (packed == 0xffffffffU)
    {
        packed = 0x40005622;
    }
    baseNote = (u8)(packed >> 24);
    inputNote = noteIn;
    if (inputNote != baseNote)
    {
        if (baseNote < inputNote)
        {
            d = inputNote - baseNote;
            freq = voicePitchUpTable[d];
        }
        else
        {
            d = baseNote - inputNote;
            freq = voicePitchDownTable[d];
        }
        freq = (f32)(u32)(packed & 0xffffff) * freq;
    }
    else
    {
        freq = (f32)(u32)(packed & 0xffffff);
    }
    return __cvt_fp2unsigned((lbl_803E7828 * freq) /
        (f32)(u32)*(u32*)lbl_803BD150);
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
    f32 scaledDb;
    f32 base;
    f32 result;

    scaledDb = (f32)(s32)dbCents;
    base = powf(lbl_803E7834, scaledDb * lbl_803E7838);
    result = lbl_803E7830 * base;
    return __cvt_fp2unsigned(result);
}
