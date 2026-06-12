#include "main/audio/hw_aram.h"

extern u32 lbl_803BD150[];
extern f32 lbl_803E78E8;
extern u32 __cvt_fp2unsigned(double value);
u32 hwExitStream(u32 value)
{
    return __cvt_fp2unsigned((double)((lbl_803E78E8 * (f32)value) / (f32)lbl_803BD150[0]));
}

void hwGetStreamPlayBuffer(undefined4 unused, undefined4 value)
{
    aramInit(value);
}

void hwTransAddr(void)
{
    aramGetZeroBuffer();
}
