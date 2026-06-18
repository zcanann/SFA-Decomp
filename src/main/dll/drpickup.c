#include "main/dll/DR/DRpickup.h"
#include "main/camera_interface.h"

extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Matrix_TransformPoint(void* mtx, float x, float y, float z, float* ox, float* oy, float* oz);
extern void PSVECAdd(const void* a, const void* b, void* ab);
extern float powfBitEstimate(float x, float y);

extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5C28;
extern f32 lbl_803E5C2C;
extern f32 lbl_803E5C30;

void fn_801EC1AC(int obj, int state)
{
    PickupFlags* flags;
    int origBit4;
    f32 rate;
    f32 target;
    f32 clampedRate;
    f32 out[3];
    f32 vec_args[4];

    flags = (PickupFlags*)(state + 0x428);
    origBit4 = flags->b4;

    if ((((DRPickupState*)state)->flags458 & 0x100) != 0)
    {
        flags->b6 = 1;
    }
    else
    {
        flags->b6 = 0;
    }

    if ((((DRPickupState*)state)->flags458 & 0x200) != 0)
    {
        flags->b4 = 1;
    }
    else
    {
        flags->b4 = 0;
    }

    if ((origBit4 == 0) && (flags->b4 != 0))
    {
        Sfx_PlayFromObject(obj, 0x45f);
    }

    target = lbl_803E5AE8;
    if (flags->b6 != 0)
    {
        target = ((DRPickupState*)state)->unk538;
    }
    rate = (target - ((DRPickupState*)state)->unk430) * lbl_803E5C28;
    clampedRate = (rate < lbl_803E5C2C)
                      ? lbl_803E5C2C
                      : ((rate > lbl_803E5B8C) ? lbl_803E5B8C : rate);
    *(f32*)(state + 0x430) = clampedRate * timeDelta + *(f32*)((int)state + 0x430);

    target = lbl_803E5AE8;
    if (flags->b4 != 0)
    {
        f32 vy53c = ((DRPickupState*)state)->unk53C;
        f32 v49c = ((DRPickupState*)state)->unk49C;
        if (v49c >= target)
        {
            f32 nv = -vy53c;
            target = (nv < -v49c * oneOverTimeDelta)
                         ? -v49c * oneOverTimeDelta
                         : ((nv > target) ? target : nv);
        }
        else
        {
            target = (vy53c < target)
                         ? target
                         : ((vy53c > -v49c * oneOverTimeDelta) ? -v49c * oneOverTimeDelta : vy53c);
        }
    }
    {
        f32 fz = *(f32*)&lbl_803E5AE8;
        ((DRPickupState*)state)->unk4A0 = fz;
        ((DRPickupState*)state)->unk4A4 = fz;
    }
    ((DRPickupState*)state)->unk4A8 = (*(f32*)(state + 0x430) + target) * timeDelta;

    Matrix_TransformPoint((void*)(state + 0x6c),
                          ((DRPickupState*)state)->unk4A0,
                          ((DRPickupState*)state)->unk4A4,
                          ((DRPickupState*)state)->unk4A8,
                          &out[0], &out[1], &out[2]);
    Matrix_TransformPoint((void*)(state + 0x12c),
                          out[0], out[1], out[2],
                          &out[0], &out[1], &out[2]);
    PSVECAdd(out, (void*)(state + 0x494), (void*)(state + 0x494));

    ((DRPickupState*)state)->angVel414 =
        (-((DRPickupState*)state)->unk45C * ((DRPickupState*)state)->unk52C) * timeDelta +
        ((DRPickupState*)state)->angVel414;
    ((DRPickupState*)state)->angVel414 =
        powfBitEstimate(((DRPickupState*)state)->unk530, timeDelta) *
        ((DRPickupState*)state)->angVel414;

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->angVel414;
        lim = ((DRPickupState*)state)->unk534;
        ((DRPickupState*)state)->angVel414 = (v < -lim) ? -lim : ((v > lim) ? lim : v);
    }

    {
        f32 newF = (f32)(s32) * (s16*)(state + 0x40e) +
            ((DRPickupState*)state)->angVel414 * timeDelta;
        s32 delta;
        *(s16*)(state + 0x40e) = newF;
        delta = (s32)(((DRPickupState*)state)->angVel414 * ((DRPickupState*)state)->unk550);
        delta -= (s32)(u16) * (u32*)(state + 0x410);
        if (delta > 0x8000)
        {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xFFFF;
        }
        *(u32*)(state + 0x410) =
            (u32)(s32)((f32)delta * ((DRPickupState*)state)->unk554 +
                (f32)(s32) * (u32*)((int)state + 0x410));
    }
    {
        s32 delta = (s32) * (s16*)(state + 0x40e) - (s32)(u16) * (s16*)(state + 0x40c);
        if (delta > 0x8000)
        {
            delta = delta - 0xFFFF;
        }
        if (delta < -0x8000)
        {
            delta = delta + 0xFFFF;
        }
        *(s16*)(state + 0x40c) = (s16)((f32)delta * ((DRPickupState*)state)->unk558 +
            (f32)(s32) * (s16*)((int)state + 0x40c));
    }

    if (flags->b7 != 0)
    {
        ((DRPickupState*)state)->unk584 =
            (-((DRPickupState*)state)->unk570) * timeDelta + ((DRPickupState*)state)->unk584;
        {
            f32 v = ((DRPickupState*)state)->unk584;
            ((DRPickupState*)state)->unk584 = (v < lbl_803E5C30)
                                         ? lbl_803E5C30
                                         : ((v > lbl_803E5B48) ? lbl_803E5B48 : v);
        }
        *(s16*)(obj + 0x2) = (f32)(s32) * (s16*)(obj + 0x2) +
            ((DRPickupState*)state)->unk584 * timeDelta;
    }

    if (flags->b1 == 0)
    {
        vec_args[0] = ((DRPickupState*)state)->angVel414;
        vec_args[1] = ((DRPickupState*)state)->unk49C;
        vec_args[2] = (f32)(s32) * (s16*)(obj + 0x4);
        vec_args[3] = (f32)(s32) * (s16*)(obj + 0x2);
        (*gCameraInterface)->releaseAction(vec_args, 0x10);
    }

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->unk494;
        lim = ((DRPickupState*)state)->unk47C;
        ((DRPickupState*)state)->unk494 = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = ((DRPickupState*)state)->unk494;
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                ((DRPickupState*)state)->unk494 = lbl_803E5AE8;
            }
        }
    }

    {
        f32 v = ((DRPickupState*)state)->unk498;
        f32 lim = -((DRPickupState*)state)->unk480;
        ((DRPickupState*)state)->unk498 = (v < lim)
                                     ? lim
                                     : ((v > lbl_803E5AEC) ? lbl_803E5AEC : v);
        v = ((DRPickupState*)state)->unk498;
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                ((DRPickupState*)state)->unk498 = lbl_803E5AE8;
            }
        }
    }

    {
        f32 lim;
        f32 v;
        v = ((DRPickupState*)state)->unk49C;
        lim = ((DRPickupState*)state)->unk484;
        ((DRPickupState*)state)->unk49C = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = ((DRPickupState*)state)->unk49C;
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                ((DRPickupState*)state)->unk49C = lbl_803E5AE8;
            }
        }
    }
}
