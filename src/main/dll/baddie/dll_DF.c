#include "ghidra_import.h"
#include "main/dll/baddie/dll_DF.h"

#pragma peephole off
#pragma scheduling off

extern double FUN_80017708();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_8002f6ac();
extern undefined4 ObjHits_SyncObjectPosition();
extern char fn_8004B394();
extern undefined4 FUN_80046cd0();
extern undefined4 FUN_80061a80();
extern undefined4 FUN_800d9a98();
extern undefined4 FUN_800d9b7c();
extern undefined4 FUN_800d9de0();
extern undefined4 FUN_800da594();
extern undefined4 FUN_800da5e8();
extern undefined4 FUN_800da850();
extern undefined4 FUN_800da860();
extern short FUN_800daa04();
extern uint FUN_800daf38();
extern ushort FUN_800db110();
extern int FUN_800db2f0();
extern undefined4 FUN_800db47c();
extern ushort FUN_800db690();
extern undefined4 FUN_80139800();
extern undefined4 FUN_80139910();
extern undefined4 FUN_80139a48();
extern undefined4 FUN_80139a4c();
extern int FUN_80139e1c();
extern void fn_8013AD50();
extern undefined4 FUN_8013a144();
extern undefined4 FUN_8013d8f0();
extern undefined4 FUN_80146f9c();
extern undefined4 FUN_80146fa0();
extern undefined8 FUN_80286828();
extern undefined4 FUN_80286874();
extern double FUN_80293900();
extern undefined4 SUB41();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd728;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e30ac;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d8;
extern f32 FLOAT_803e30f8;
extern f32 FLOAT_803e30fc;
extern f32 FLOAT_803e3114;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e311c;
extern f32 FLOAT_803e3120;
extern f32 FLOAT_803e3124;
extern f32 FLOAT_803e3128;
extern f32 FLOAT_803e312c;
extern f32 FLOAT_803e3130;
extern f32 FLOAT_803e3134;
extern f32 FLOAT_803e3138;
extern f32 FLOAT_803e313c;
extern f32 FLOAT_803e3140;
extern f32 FLOAT_803e3144;
extern f32 FLOAT_803e3148;
extern f32 FLOAT_803e314c;
extern f32 FLOAT_803e3150;

extern f32 timeDelta;
extern f32 oneOverTimeDelta;

extern f32 lbl_803E23DC;  /*  0.0f  */
extern f32 lbl_803E23F4;  /* -0.01f */
extern f32 lbl_803E241C;  /* -0.15f */
extern f32 lbl_803E2420;  /*  0.05f */
extern f32 lbl_803E243C;  /*  0.02f */
extern f32 lbl_803E2488;  /*  5.0f  */
extern f32 lbl_803E248C;  /*  3.0f  */

extern f32 getXZDistance(f32 *a, f32 *b);
extern void mathFn_80021ac8(void *params, void *outVec);
extern f32 sqrtf(f32 x);

/*
 * --INFO--
 *
 * Function: FUN_8013b368
 * EN v1.0 Address: 0x8013B368
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8013B6F0
 * EN v1.1 Size: 8764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013b368(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
}

void fn_8013D5A4(u8 *obj, u8 *state, f32 *targetPos, u8 flag, f32 baseRadius)
{
    struct {
        s16 a;
        s16 angle;
        s16 c;
    } params;
    f32 delta[3];
    f32 sum;
    f32 v;
    f32 dec;
    f32 thresh;
    f32 distSq;
    f32 dist;
    f32 dx;
    f32 dz;
    f32 vel;
    f32 candidate;
    f32 *otherTarget;
    u8 *ctx;

    sum = lbl_803E2420;
    v = *(f32 *)(state + 0x14);
    dec = lbl_803E241C * timeDelta;
    while (v > lbl_803E23DC) {
        sum = sum + v * timeDelta;
        v = v + dec;
    }
    thresh = baseRadius + sum;
    distSq = thresh * thresh;
    dist = getXZDistance(targetPos, (f32 *)(obj + 0x18));
    if (dist < distSq) {
        candidate = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
        if (candidate < lbl_803E23DC) {
            candidate = lbl_803E23DC;
        }
        *(f32 *)(state + 0x14) = candidate;
        return;
    }
    if (flag != 0) {
        delta[0] = *(f32 *)(targetPos + 0) - *(f32 *)(obj + 0x18);
        delta[1] = *(f32 *)(targetPos + 1) - *(f32 *)(obj + 0x1c);
        delta[2] = *(f32 *)(targetPos + 2) - *(f32 *)(obj + 0x20);
        params.a = -*(s16 *)(obj + 0x0);
        params.angle = 0;
        params.c = 0;
        mathFn_80021ac8(&params, delta);
        if (delta[2] > lbl_803E23DC) {
            candidate = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
            if (candidate < lbl_803E23DC) {
                candidate = lbl_803E23DC;
            }
            *(f32 *)(state + 0x14) = candidate;
            return;
        }
    }
    if ((*(u32 *)(state + 0x54) & 0x10000000) != 0) {
        *(f32 *)(state + 0x14) =
            lbl_803E23F4 * timeDelta + *(f32 *)(state + 0x14);
        if (*(f32 *)(state + 0x14) < lbl_803E23DC) {
            *(f32 *)(state + 0x14) = lbl_803E23DC;
        }
        return;
    }
    {
        f32 deltaSpeed = lbl_803E2488 + thresh;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        ctx = *(u8 **)(obj + 0xb8);
        otherTarget = *(f32 **)(ctx + 0x28);
        if (otherTarget == *(f32 **)(ctx + 0x6f0)) {
            dx = *(f32 *)(ctx + 0x6f4) - *(f32 *)(obj + 0x18);
            dz = *(f32 *)(ctx + 0x6fc) - *(f32 *)(obj + 0x20);
            vel = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = *(f32 *)((u8 *)otherTarget + 0) - *(f32 *)(obj + 0x18);
            dz = *(f32 *)((u8 *)otherTarget + 8) - *(f32 *)(obj + 0x20);
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidate = distOther - vel;
            }
        } else {
            candidate = lbl_803E23DC;
        }
        if (dist < deltaSpeedSq) {
            if (candidate > lbl_803E23DC) {
                if (candidate < *(f32 *)(state + 0x14)) {
                    f32 step = lbl_803E241C * timeDelta + *(f32 *)(state + 0x14);
                    if (step < candidate) {
                        step = candidate;
                    }
                    *(f32 *)(state + 0x14) = step;
                    return;
                } else {
                    f32 step;
                    if (candidate > lbl_803E248C) {
                        step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
                        if (step > lbl_803E248C) {
                            step = lbl_803E248C;
                        }
                        *(f32 *)(state + 0x14) = step;
                        return;
                    }
                    step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
                    if (step > candidate) {
                        step = candidate;
                    }
                    *(f32 *)(state + 0x14) = step;
                    return;
                }
            }
        }
    }
    if ((*(u32 *)(state + 0x54) & 0x00100000) != 0) {
        *(f32 *)(state + 0x14) =
            lbl_803E243C * timeDelta + *(f32 *)(state + 0x14);
        if (*(f32 *)(state + 0x14) > lbl_803E248C) {
            *(f32 *)(state + 0x14) = lbl_803E248C;
        }
        return;
    }
    {
        f32 step = lbl_803E2420 * timeDelta + *(f32 *)(state + 0x14);
        if (step > lbl_803E248C) {
            step = lbl_803E248C;
        }
        *(f32 *)(state + 0x14) = step;
    }
}
