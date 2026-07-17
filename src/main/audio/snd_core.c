#include "main/audio/snd_core.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_control.h"
#include "main/audio/synth_config.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

#pragma exceptions on

extern u8 gSynthInitialized;
extern void IFFifoAlloc(void);
extern const float lbl_803E78C8;
extern const double lbl_803E78D0;
extern const double lbl_803E78D8;

void sndQuit(void)
{
    hwExit();
    IFFifoAlloc();
    s3dExit();
    synthExit();
    gSynthInitialized = 0;
}

void sndSetMaxVoices(u8 valueA, u8 valueB)
{
    SYNTH_CONFIGURATION->musicVoiceCount = valueA;
    SYNTH_CONFIGURATION->fxVoiceCount = valueB;
}

u8 sndIsInstalled(void)
{
    return gSynthInitialized;
}

#pragma fp_contract off
void salApplyMatrix(f32* matrix, f32* vec, f32* out)
{
    out[0] = matrix[9] + (matrix[0] * vec[0] + matrix[1] * vec[1] + matrix[2] * vec[2]);
    out[1] = matrix[10] + (matrix[3] * vec[0] + matrix[4] * vec[1] + matrix[5] * vec[2]);
    out[2] = matrix[11] + (matrix[6] * vec[0] + matrix[7] * vec[1] + matrix[8] * vec[2]);
}
#pragma fp_contract reset

#pragma fp_contract off
extern inline f32 sqrtf(f32 x)
{
    volatile f32 y;
    if (x > lbl_803E78C8)
    {
        f64 guess = __frsqrte((f64)x);
        guess = lbl_803E78D0 * guess * (lbl_803E78D8 - guess * guess * x);
        guess = lbl_803E78D0 * guess * (lbl_803E78D8 - guess * guess * x);
        guess = lbl_803E78D0 * guess * (lbl_803E78D8 - guess * guess * x);
        y = (f32)(x * guess);
        return y;
    }
    return x;
}

f32 salNormalizeVector(f32* v)
{
    f32 len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    v[0] /= len;
    v[1] /= len;
    v[2] /= len;
    return len;
}
#pragma fp_contract reset

const float lbl_803E78C8 = 0.0f;
const double lbl_803E78D0 = 0.5;
const double lbl_803E78D8 = 3.0;
