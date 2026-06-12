#include "main/dll/boulder.h"

extern u32 randomGetRange(int min, int max);

extern f32 lbl_803E5ED8;

void fn_801F4ECC(int obj, u8* rec)
{
    *(f32*)(rec + 0x04) = *(f32*)(rec + 0x08);
    *(f32*)(rec + 0x14) = *(f32*)(rec + 0x18);
    *(f32*)(rec + 0x24) = *(f32*)(rec + 0x28);
    *(f32*)(rec + 0x08) = *(f32*)(rec + 0x0c);
    *(f32*)(rec + 0x18) = *(f32*)(rec + 0x1c);
    *(f32*)(rec + 0x28) = *(f32*)(rec + 0x2c);
    *(f32*)(rec + 0x0c) = *(f32*)(rec + 0x10);
    *(f32*)(rec + 0x1c) = *(f32*)(rec + 0x20);
    *(f32*)(rec + 0x2c) = *(f32*)(rec + 0x30);
    *(f32*)(rec + 0x44) =
        lbl_803E5ED8 * (f32)(s32)
    randomGetRange(0xa0, 0xb4);
    *(f32*)(rec + 0x10) = *(f32*)(rec + 0x34);
    *(f32*)(rec + 0x20) = *(f32*)(rec + 0x38);
    *(f32*)(rec + 0x30) = *(f32*)(rec + 0x3c);
}
