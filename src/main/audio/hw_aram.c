#include "main/audio/hw_aram.h"

extern u32 lbl_803BD150[];
extern f32 lbl_803E78E8;
extern asm u32 __cvt_fp2unsigned(register f64 d);
u32 hwExitStream(u32 value)
{
    return __cvt_fp2unsigned((double)((lbl_803E78E8 * (f32)value) / (f32)lbl_803BD150[0]));
}

void hwGetStreamPlayBuffer(u32 unused, u32 value)
{
    aramInit(value);
}

void hwTransAddr(void)
{
    aramGetZeroBuffer();
}
