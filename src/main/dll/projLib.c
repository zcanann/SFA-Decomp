#include "main/dll/projLib.h"

extern f32 Vec_distance(f32 * a, f32 * b);
extern u32 randomGetRange(int min, int max);
extern undefined4 Obj_GetPlayerObject();
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 fn_80038F1C(int a, int b);
extern void* seqFn_800394a0();
extern undefined4 objMathFn_8003a380(ushort* obj, uint target, float* pos, int pathState,
                                     short* turnState, float targetYaw, int mode, short yawLimit);
extern int fn_8003A8B4();
extern undefined4 fn_8003A9C0();
extern undefined4 fn_8003AC14();
extern undefined4 objFn_8003acfc();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern f32 sqrtf(f32 value);

extern u8 framesThisStep;
extern f32 lbl_803E1C8C;
extern f32 lbl_803E1C90;
extern f64 lbl_803E1C98;
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CD4;
extern f32 lbl_803E1CD8;
extern f32 lbl_803E1CDC;

/*
 * --INFO--
 *
 * Function: dll_2E_func03
 * EN v1.0 Address: 0x80115094
 * EN v1.0 Size: 1468b
 * EN v1.1 Address: 0x80115318
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct ProjNearSearch
{
    f32 range;
    f32 dx;
    f32 dy;
    f32 dz;
} ProjNearSearch;

static uint projGetLockTarget(int state, ushort* obj, ProjNearSearch* sv)
{
    uint t = *(uint*)(state + 0x608);
    if (t != 0) return t;
    return ObjGroup_FindNearestObject(8, obj, sv);
}

void dll_2E_func03(ushort* obj, int state, undefined4 unused)
{
    register int yawDelta;
    register int seqHandle;
    register uint target;
    int bit1;
    int ival;
    uint hitReact;
    float dist;
    float blendA;
    float blendB;
    float blendMax;
    float targetYaw;
    ProjNearSearch sv;

    (void)unused;
    sv.range = lbl_803E1C8C;
    targetYaw = lbl_803E1CD0;
    yawDelta = 0;
    seqHandle = (int)seqFn_800394a0();
    Obj_GetPlayerObject();
    if (*(u8*)(state + 0x601) == 0)
    {
        bit1 = *(u8*)(state + 0x611) & 1;
        if (bit1 != 0 && *(u8*)(state + 0x600) != 8)
        {
            *(u8*)(state + 0x600) = 8;
            if ((*(byte*)(state + 0x611) & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                *(undefined4*)(state + 0x5f8) = 0x50;
                fn_8003A9C0(state + 0x1c, (uint) * (byte*)(state + 0x610), 0, 0);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (uint) * (byte*)(state + 0x610));
            }
        }
        else if (bit1 == 0 && *(u8*)(state + 0x600) == 8)
        {
            *(u8*)(state + 0x600) = 0;
            if ((*(byte*)(state + 0x611) & 8) == 0)
            {
                objFn_8003acfc((int)obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                *(undefined4*)(state + 0x5f8) = 0x50;
            }
        }
        if (*(u8*)(state + 0x600) > 1)
        {
            if (*(int*)(state + 0x5f8) != 0 && (*(byte*)(state + 0x611) & 8) == 0)
            {
                *(uint*)(state + 0x5f8) =
                    !fn_8003A8B4(obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
            }
            else
            {
                fn_8003AC14((int)obj, seqFn_800394a0(), (uint) * (byte*)(state + 0x610));
            }
        }
        else
        {
            if ((target = projGetLockTarget(state, obj, &sv)) != 0)
            {
                if ((*(byte*)(state + 0x611) & 0x20) != 0)
                {
                    sv.dx = *(float*)(state + 0x10) - *(float*)(target + 0xc);
                    sv.dy = *(float*)(state + 0x14) - *(float*)(target + 0x10);
                    sv.dz = *(float*)(state + 0x18) - *(float*)(target + 0x14);
                    blendA = sv.dx * sv.dx;
                    blendB = sv.dz * sv.dz;
                    dist = sqrtf(blendA + blendB);
                    if (dist <= lbl_803E1CD4)
                    {
                        blendA = (dist - lbl_803E1CD8) / lbl_803E1CD0;
                        blendMax = lbl_803E1CA4;
                        blendB = lbl_803E1C90;
                        if (blendA < blendB)
                        {
                        }
                        else if (blendA > blendMax)
                        {
                            blendB = blendMax;
                        }
                        else
                        {
                            blendB = blendA;
                        }
                        blendB = lbl_803E1CA4 - blendB;
                        blendA = lbl_803E1CA4 - blendB;
                        *(float*)(state + 0x10) =
                            *(float*)(state + 0x10) * blendA + *(float*)(obj + 6) * blendB;
                        *(float*)(state + 0x18) =
                            *(float*)(state + 0x18) * blendA + *(float*)(obj + 10) * blendB;
                    }
                }
                if ((*(int*)(state + 0x618) != -1) && (target == *(uint*)(state + 0x604)))
                {
                    ival = -(uint)framesThisStep + *(int*)(state + 0x620);
                    *(int*)(state + 0x620) = ival;
                    if ((ival <= 0) && (0 < (int)(*(int*)(state + 0x620) + (uint)framesThisStep)))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                        *(undefined4*)(state + 0x5f8) = 0x50;
                        fn_8003A9C0(state + 0x1c, (uint) * (byte*)(state + 0x610), 0, 0);
                        *(undefined*)(state + 0x600) = 0;
                        goto LAB_801158cc;
                    }
                    if (*(int*)(state + 0x5f8) != 0)
                    {
                        *(uint*)(state + 0x5f8) =
                            !fn_8003A8B4(obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                    }
                    if (*(int*)(state + 0x620) < -*(int*)(state + 0x61c))
                    {
                        *(uint*)(state + 0x620) =
                            randomGetRange(*(int*)(state + 0x61c), *(int*)(state + 0x618));
                    }
                    if (*(int*)(state + 0x620) < 0) goto LAB_801158cc;
                }
                else
                {
                    *(int*)(state + 0x620) = *(int*)(state + 0x618);
                }
                if ((target != *(uint*)(state + 0x604)) && (target != 0))
                {
                    hitReact = *(uint*)(target + 0x54);
                    if (hitReact != 0)
                    {
                        if ((*(byte*)(hitReact + 0x62) & 2) != 0)
                        {
                            targetYaw = lbl_803E1CDC * (float)(int)*(short*)(hitReact + 0x5e);
                        }
                        else if ((*(byte*)(hitReact + 0x62) & 1) != 0)
                        {
                            targetYaw = (float)(int)*(short*)(hitReact + 0x5a);
                        }
                        else
                        {
                            targetYaw = lbl_803E1CD0;
                        }
                    }
                    else
                    {
                        targetYaw = lbl_803E1CD0;
                    }
                }
                if (target != 0)
                {
                    yawDelta = Obj_GetYawDeltaToObject(obj, target, (float*)0x0);
                }
                if ((*(byte*)(state + 0x611) & 0x10) != 0)
                {
                    fn_80038F1C(0, 1);
                    yawDelta = yawDelta + -0x8000;
                }
                ival = (short)yawDelta;
                ival = (ival >= 0) ? ival : -ival;
                if (((0x5555 < ival) || (target == 0)) ||
                    (Vec_distance((float*)(obj + 0xc), (float*)(target + 0x18)) > *(float*)(state + 0x614)))
                {
                    if ((*(u8*)(state + 0x600) != 0) ||
                        ((target == 0 && (*(uint*)(state + 0x604) != 0))))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                        *(undefined4*)(state + 0x5f8) = 10;
                        fn_8003A9C0(state + 0x1c, (uint) * (byte*)(state + 0x610), 0, 0);
                        *(undefined*)(state + 0x600) = 0;
                    }
                }
                else
                {
                    if ((target != *(uint*)(state + 0x604)) || (*(u8*)(state + 0x600) == 0))
                    {
                        objFn_8003acfc((int)obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                        *(undefined4*)(state + 0x5f8) = 1;
                    }
                    if ((*(byte*)(state + 0x611) & 8) != 0)
                    {
                        *(undefined4*)(state + 0x5f8) = 0;
                    }
                    objMathFn_8003a380(obj, target, (float*)(state + 0x10),
                                       (*(int*)(state + 0x5f8) != 0) ? state + 0x1c : 0,
                                       (short*)(state + 0x5bc), targetYaw, 8,
                                       *(short*)(state + 0x60c));
                    *(undefined*)(state + 0x600) = 1;
                }
                *(uint*)(state + 0x604) = target;
                if (*(int*)(state + 0x5f8) == 0)
                {
                    *(undefined4*)(state + 0x608) = 0;
                }
                if (((*(byte*)(state + 0x611) & 8) == 0) && (*(int*)(state + 0x5f8) != 0))
                {
                    *(uint*)(state + 0x5f8) =
                        !fn_8003A8B4(obj, seqHandle, (uint) * (byte*)(state + 0x610), state + 0x1c);
                }
            }
        }
    }
LAB_801158cc:
    return;
}


void FUN_801150ac(void)
{
    undefined8 ctx;

    ctx = FUN_80286840();
    dll_2E_func03((ushort*)((ulonglong)ctx >> 0x20), (int)ctx, 0);
    FUN_8028688c();
    return;
}
