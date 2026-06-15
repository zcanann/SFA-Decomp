#include "main/dll/DR/DRpickup.h"
#include "main/game_object.h"
#include "main/camera_interface.h"

extern void Sfx_PlayFromObject(int obj, int sfxId);
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

    if ((*(u32*)(state + 0x458) & 0x100) != 0)
    {
        flags->b6 = 1;
    }
    else
    {
        flags->b6 = 0;
    }

    if ((*(u32*)(state + 0x458) & 0x200) != 0)
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
        target = *(f32*)(state + 0x538);
    }
    rate = (target - *(f32*)(state + 0x430)) * lbl_803E5C28;
    clampedRate = (rate < lbl_803E5C2C)
                      ? lbl_803E5C2C
                      : ((rate > lbl_803E5B8C) ? lbl_803E5B8C : rate);
    *(f32*)(state + 0x430) = clampedRate * timeDelta + *(f32*)((int)state + 0x430);

    target = lbl_803E5AE8;
    if (flags->b4 != 0)
    {
        f32 vy53c = *(f32*)(state + 0x53c);
        f32 v49c = *(f32*)(state + 0x49c);
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
        *(f32*)(state + 0x4a0) = fz;
        *(f32*)(state + 0x4a4) = fz;
    }
    *(f32*)(state + 0x4a8) = (*(f32*)(state + 0x430) + target) * timeDelta;

    Matrix_TransformPoint((void*)(state + 0x6c),
                          *(f32*)(state + 0x4a0),
                          *(f32*)(state + 0x4a4),
                          *(f32*)(state + 0x4a8),
                          &out[0], &out[1], &out[2]);
    Matrix_TransformPoint((void*)(state + 0x12c),
                          out[0], out[1], out[2],
                          &out[0], &out[1], &out[2]);
    PSVECAdd(out, (void*)(state + 0x494), (void*)(state + 0x494));

    *(f32*)(state + 0x414) =
        (-*(f32*)(state + 0x45c) * *(f32*)(state + 0x52c)) * timeDelta +
        *(f32*)(state + 0x414);
    *(f32*)(state + 0x414) =
        powfBitEstimate(*(f32*)(state + 0x530), timeDelta) *
        *(f32*)(state + 0x414);

    {
        f32 lim;
        f32 v;
        v = *(f32*)(state + 0x414);
        lim = *(f32*)(state + 0x534);
        *(f32*)(state + 0x414) = (v < -lim) ? -lim : ((v > lim) ? lim : v);
    }

    /* Apply 0x414 * timeDelta to short at 0x40e, then chase the scaled
       angular velocity through 0x410 with overflow normalization. */
    {
        f32 newF = (f32)(s32) * (s16*)(state + 0x40e) +
            *(f32*)(state + 0x414) * timeDelta;
        s32 delta;
        *(s16*)(state + 0x40e) = newF;
        delta = (s32)(*(f32*)(state + 0x414) * *(f32*)(state + 0x550));
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
            (u32)(s32)((f32)delta * *(f32*)(state + 0x554) +
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
        *(s16*)(state + 0x40c) = (s16)((f32)delta * *(f32*)(state + 0x558) +
            (f32)(s32) * (s16*)((int)state + 0x40c));
    }

    if (flags->b7 != 0)
    {
        *(f32*)(state + 0x584) =
            (-*(f32*)(state + 0x570)) * timeDelta + *(f32*)(state + 0x584);
        {
            f32 v = *(f32*)(state + 0x584);
            *(f32*)(state + 0x584) = (v < lbl_803E5C30)
                                         ? lbl_803E5C30
                                         : ((v > lbl_803E5B48) ? lbl_803E5B48 : v);
        }
        ((GameObject *)obj)->anim.rotY = (f32)(s32) * (s16*)(obj + 0x2) +
            *(f32*)(state + 0x584) * timeDelta;
    }

    if (flags->b1 == 0)
    {
        vec_args[0] = *(f32*)(state + 0x414);
        vec_args[1] = *(f32*)(state + 0x49c);
        vec_args[2] = (f32)(s32) * (s16*)(obj + 0x4);
        vec_args[3] = (f32)(s32) * (s16*)(obj + 0x2);
        (*gCameraInterface)->releaseAction(vec_args, 0x10);
    }

    {
        f32 lim;
        f32 v;
        v = *(f32*)(state + 0x494);
        lim = *(f32*)(state + 0x47c);
        *(f32*)(state + 0x494) = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = *(f32*)(state + 0x494);
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                *(f32*)(state + 0x494) = lbl_803E5AE8;
            }
        }
    }

    {
        f32 v = *(f32*)(state + 0x498);
        f32 lim = -*(f32*)(state + 0x480);
        *(f32*)(state + 0x498) = (v < lim)
                                     ? lim
                                     : ((v > lbl_803E5AEC) ? lbl_803E5AEC : v);
        v = *(f32*)(state + 0x498);
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                *(f32*)(state + 0x498) = lbl_803E5AE8;
            }
        }
    }

    {
        f32 lim;
        f32 v;
        v = *(f32*)(state + 0x49c);
        lim = *(f32*)(state + 0x484);
        *(f32*)(state + 0x49c) = (v < -lim) ? -lim : ((v > lim) ? lim : v);
        v = *(f32*)(state + 0x49c);
        if (v < lbl_803E5B8C)
        {
            if (v > lbl_803E5BA4)
            {
                *(f32*)(state + 0x49c) = lbl_803E5AE8;
            }
        }
    }
}
