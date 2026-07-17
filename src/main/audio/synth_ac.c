#include "main/audio/synth_config.h"

extern f32 voicePitchUpTable[];
extern f32 voicePitchDownTable[];
extern asm u32 __cvt_fp2unsigned(register f64 d);

int voiceScaleSampleRate(u16 value)
{
    return (int)(1.0594631f * (f32)(u32)value);
}

u32 voiceGetPitchRatio(u8 key, u32 sampleInfo)
{
    u8 originalKey;
    f32 frequency;

    if (sampleInfo == 0xffffffffU)
    {
        sampleInfo = 0x40005622;
    }
    originalKey = (u8)(sampleInfo >> 24);
    if (key != originalKey)
    {
        if (originalKey < key)
        {
            frequency = voicePitchUpTable[key - originalKey];
        }
        else
        {
            frequency = voicePitchDownTable[originalKey - key];
        }
        frequency = (f32)(u32)(sampleInfo & 0xffffff) * frequency;
    }
    else
    {
        frequency = (f32)(u32)(sampleInfo & 0xffffff);
    }
    return __cvt_fp2unsigned((4096.0f * frequency) /
                             (f32)SYNTH_CONFIGURATION->sampleRate);
}
