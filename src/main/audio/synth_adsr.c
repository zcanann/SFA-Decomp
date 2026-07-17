#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

extern asm u32 __cvt_fp2unsigned(register f64 d);

u32 voiceConvertDbToLinear(u32 timeCents)
{
    return __cvt_fp2unsigned(1000.0f *
                             powf(2.0f, 1.2715658e-08f * (f32)(s32)timeCents));
}
