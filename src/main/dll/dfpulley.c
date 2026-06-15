#include "main/game_object.h"
#include "dolphin/mtx.h"

extern f32 lbl_803E4DFC;

void DFPulley_integrateLinks(u8* self)
{
    u8* linkPtr;
    u8* part;
    int j;
    int i;
    Vec accel;
    Vec velscaled;
    Vec scaled;
    f32 mag;
    f32 zero;

    part = (u8*)*(int*)(self + 0);
    i = 0;
    zero = lbl_803E4DFC;
    for (; i < (int)self[0x8]; i++, part += 0x34)
    {
        *(f32*)((u8*)&accel + 8) = zero;
        *(f32*)((u8*)&accel + 4) = zero;
        *(f32*)((u8*)&accel + 0) = zero;

        if (part[0x30] == 0)
        {
            for (j = 0, linkPtr = part; j < (int)part[0x24]; j++)
            {
                u8* link = (u8*)*(u32*)(linkPtr + 0x28);
                if ((u32)part == *(u32*)(link + 4))
                {
                    PSVECAdd(&accel, (Vec*)(link + 0x18), &accel);
                }
                else
                {
                    PSVECSubtract(&accel, (Vec*)(link + 0x18), &accel);
                }
                linkPtr += 4;
            }
            mag = PSVECMag(&accel);
            if (mag > ((GameObject *)self)->anim.velocityZ)
            {
                PSVECScale(&accel, &accel, ((GameObject *)self)->anim.velocityZ / mag);
            }
            PSVECScale(&accel, &accel, *(f32*)(self + 0x40));
            PSVECAdd(&accel, (Vec*)(part + 0x18), &accel);
            PSVECAdd((Vec*)(part + 0xC), &accel, (Vec*)(part + 0xC));
            PSVECScale((Vec*)(part + 0xC), &velscaled, *(f32*)(self + 0x38));
            PSVECSubtract((Vec*)(part + 0xC), &velscaled, (Vec*)(part + 0xC));
            *(f32*)(part + 0x10) = *(f32 *)&((GameObject *)self)->anim.parent * *(f32*)(self + 0x3C)
                + *(f32*)(part + 0x10);
            PSVECScale((Vec*)(part + 0xC), &scaled, *(f32 *)&((GameObject *)self)->anim.parent);
            PSVECAdd((Vec*)part, &scaled, (Vec*)part);
        }
    }
}
