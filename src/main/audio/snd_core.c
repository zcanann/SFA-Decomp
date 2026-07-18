#include "main/audio/snd_core.h"
#include "main/audio/data_tables.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_control.h"
#include "main/audio/synth_config.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/fake_tgmath.h"


extern u8 gSynthInitialized;

void sndQuit(void)
{
    hwExit();
    dataExit();
    s3dExit();
    synthExit();
    gSynthInitialized = 0;
}

void sndSetMaxVoices(u8 valueA, u8 valueB)
{
    SYNTH_CONFIGURATION->musicVoiceCount = valueA;
    SYNTH_CONFIGURATION->fxVoiceCount = valueB;
}

u32 sndIsInstalled(void)
{
    return gSynthInitialized;
}

void salApplyMatrix(f32* matrix, f32* vec, f32* out)
{
    out[0] = matrix[9] + (matrix[0] * vec[0] + matrix[1] * vec[1] + matrix[2] * vec[2]);
    out[1] = matrix[10] + (matrix[3] * vec[0] + matrix[4] * vec[1] + matrix[5] * vec[2]);
    out[2] = matrix[11] + (matrix[6] * vec[0] + matrix[7] * vec[1] + matrix[8] * vec[2]);
}

f32 salNormalizeVector(f32* v)
{
    f32 len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    v[0] /= len;
    v[1] /= len;
    v[2] /= len;
    return len;
}

