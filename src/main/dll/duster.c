#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/duster.h"

#pragma dont_inline on

extern int Sfx_PlayFromObject(u32 obj, int sfxId);
extern int getAngle(f32 dx, f32 dz);
extern uint randomGetRange();
extern undefined4 fn_80017A88();
extern void* Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern uint Obj_IsLoadingLocked();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern void ObjHits_DisableObject(int);
extern void ObjHits_EnableObject(int);
extern void fn_80292E20(uint, float*, float*);
extern u8 objBboxFn_800640cc();
extern f32 sidekickToy_accelerateTowardTargetXZ(int obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                                f32 drag);
extern void fn_8014CD1C(int obj, int state, int moveId, f32 a, f32 b, int c);
extern int Curve_AdvanceAlongPath(int curve, f32 dt);
extern char lbl_803DBCD8;
extern void fn_8014D08C(int, int, int, float, int, int);
extern void fn_80154D0C(int, int, ushort*, float*);
extern uint fn_80154FB4(double, short*, int, uint);
extern int fn_80169EF4(f32 speed, f32 arc, float* src, float* dst, char flag);
extern undefined4 PSVECSubtract();
extern undefined4 PSVECNormalize();
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern undefined4 PSVECCrossProduct();
extern void fn_80293018(int angle, float* outSin, float* outCos);
extern double fn_80293900();
extern uint fn_80295CBC();

extern undefined4 lbl_8031F2F8;
extern u8 lbl_8031F318[];
extern undefined4* gSHthorntailAnimationInterface;
extern f64 DOUBLE_803e36a8;
extern f64 DOUBLE_803e36b0;
extern f64 DOUBLE_803e3700;
extern f64 DOUBLE_803e3738;
extern f32 timeDelta;
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern f32 lbl_803E2A08;
extern f32 lbl_803E2A20;
extern f32 lbl_803E2A24;
extern f32 lbl_803E2A28;
extern f32 lbl_803E2A2C;
extern f32 lbl_803E2A30;
extern f32 lbl_803E2A34;
extern f32 lbl_803E2A38;
extern f32 lbl_803E2A3C;
extern f32 lbl_803E2A40;
extern f32 lbl_803E2A48;
extern f32 lbl_803E2A4C;
extern f32 lbl_803E2A50;
extern f32 lbl_803E2A54;
extern f32 lbl_803E2A58;
extern f32 lbl_803E2A60;
extern f32 lbl_803E2A70;
extern f32 lbl_803E2A74;
extern f32 lbl_803E2A78;
extern f32 lbl_803E2A7C;
extern f32 lbl_803E2A80;
extern f32 lbl_803E2B18;
extern f32 lbl_803E2A5C;
extern f32 lbl_803E2A84;
extern f32 lbl_803E2A88;
extern f32 lbl_803E2A8C;
extern f32 lbl_803E2A90;
extern f32 lbl_803E2A98;
extern f32 lbl_803E2AA8;
extern f32 lbl_803E2AAC;
extern f32 lbl_803E2AB0;
extern f32 lbl_803E2AB4;
extern f32 lbl_803E2AB8;
extern f32 lbl_803E2ABC;
extern f32 lbl_803E2AC0;
extern f32 lbl_803E2AC4;
extern f32 lbl_803E2AC8;
extern f32 lbl_803E2ACC;
extern f32 lbl_803E2AD0;
extern f32 lbl_803E2AD4;
extern f32 lbl_803E2AD8;
extern f32 lbl_803E2ADC;
extern f32 lbl_803E2AE0;
extern f32 lbl_803E2AE4;
extern f32 lbl_803E2AE8;
extern f32 lbl_803E2AEC;
extern f32 lbl_803E2AF0;
extern f32 lbl_803E2AF4;
extern f32 lbl_803E2AF8;
extern f32 lbl_803E2AFC;
extern f32 lbl_803E2B00;
extern f32 lbl_803E2B04;
extern f32 lbl_803DBCEC;


/*
 * --INFO--
 *
 * Function: fn_8015536C
 * EN v1.0 Address: 0x801556D4
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80155818
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015536C(float lateral, float height, float* outPos, float* anchor)
{
    float hi;
    float lo;
    float sideAxis[3];
    float up[3];

    hi = anchor[6] - lbl_803E2A20;
    if (height > hi)
    {
        height = hi;
    }
    else
    {
        lo = lbl_803E2A24 + anchor[5];
        if (height < lo)
        {
            height = lo;
        }
    }
    if (anchor[4] > lbl_803E2A00)
    {
        hi = anchor[4] - lbl_803E2A20;
        lo = lbl_803E2A20;
    }
    else
    {
        hi = lbl_803E2A28;
        lo = lbl_803E2A20 + anchor[4];
    }
    if (lateral > hi)
    {
        lateral = hi;
    }
    else
    {
        if (lateral < lo)
        {
            lateral = lo;
        }
    }
    outPos[1] = height;
    up[0] = lbl_803E2A00;
    up[1] = lbl_803E2A04;
    up[2] = lbl_803E2A00;
    PSVECCrossProduct(up, anchor, sideAxis);
    PSVECNormalize(sideAxis, sideAxis);
    *outPos = lateral * sideAxis[0] + anchor[7];
    outPos[2] = lateral * sideAxis[2] + anchor[8];
    *outPos = lbl_803E2A2C * *anchor + *outPos;
    outPos[1] = lbl_803E2A2C * anchor[1] + outPos[1];
    outPos[2] = lbl_803E2A2C * anchor[2] + outPos[2];
}

/*
 * --INFO--
 *
 * Function: fn_801554B4
 * EN v1.0 Address: 0x80155830
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80155960
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801554B4(int* obj, int state)
{
    u8 didHit;
    float* probeOffsets;
    int i;
    f32 dot;
    float dv[3];
    float sideAxis[3];
    float bv[3];
    float toAnchor[3];
    float av[3];
    float cv[3];
    float sideAxis0[3];
    float minv[3];
    float maxv[3];
    float hit[18];

    didHit = 0;
    probeOffsets = (float*)&lbl_8031F2F8;
    for (i = 0; didHit == 0 && i < 4; i = i + 1)
    {
        maxv[0] = *(float*)(obj + 3) + *probeOffsets;
        maxv[1] = *(float*)(obj + 4);
        maxv[2] = *(float*)(obj + 5) + probeOffsets[1];
        minv[0] = *(float*)(obj + 3) - *probeOffsets;
        minv[1] = *(float*)(obj + 4);
        minv[2] = *(float*)(obj + 5) - probeOffsets[1];
        didHit = objBboxFn_800640cc(maxv, minv, lbl_803E2A00, 3, hit, obj, 5, 3, 0xff, 0);
        probeOffsets = probeOffsets + 2;
    }
    if (didHit != 0)
    {
        *(float*)(obj + 3) = (hit[17] - lbl_803E2A20) * ((minv[0] - maxv[0]) / lbl_803E2A24) + maxv[0];
        *(float*)(obj + 5) = (hit[17] - lbl_803E2A20) * ((minv[2] - maxv[2]) / lbl_803E2A24) + maxv[2];
        *(float*)(state + 0x344) = hit[7];
        *(float*)(state + 0x348) = hit[8];
        *(float*)(state + 0x34c) = hit[9];
        *(float*)(state + 0x350) = hit[10];
        *(float*)(state + 0x358) = (hit[3] > hit[4]) ? hit[3] : hit[4];
        *(float*)(state + 0x35c) = (hit[15] < hit[16]) ? hit[15] : hit[16];
        av[0] = lbl_803E2A00;
        av[1] = lbl_803E2A04;
        av[2] = lbl_803E2A00;
        PSVECCrossProduct(av, (float*)(state + 0x344), sideAxis0);
        PSVECNormalize(sideAxis0, sideAxis0);
        *(float*)(state + 0x360) = hit[1];
        *(float*)(state + 0x364) = hit[5];
        cv[0] = hit[2];
        cv[2] = hit[6];
        bv[0] = *(float*)(state + 0x360);
        bv[1] = *(float*)(state + 0x358);
        bv[2] = *(float*)(state + 0x364);
        PSVECSubtract(bv, cv, toAnchor);
        dot = PSVECDotProduct(toAnchor, (float*)(state + 0x344));
        bv[0] = *(float*)(state + 0x344) * dot + cv[0];
        bv[1] = *(float*)(state + 0x348) * dot + cv[1];
        bv[2] = *(float*)(state + 0x34c) * dot + cv[2];
        dv[0] = lbl_803E2A00;
        dv[1] = lbl_803E2A04;
        dv[2] = lbl_803E2A00;
        PSVECCrossProduct(dv, (float*)(state + 0x344), sideAxis);
        PSVECNormalize(sideAxis, sideAxis);
        if (lbl_803E2A00 != sideAxis[0])
        {
            *(float*)(state + 0x354) = (cv[0] - *(float*)(state + 0x360)) / sideAxis[0];
        }
        else
        {
            *(float*)(state + 0x354) = (cv[2] - *(float*)(state + 0x364)) / sideAxis[2];
        }
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
}

/*
 * --INFO--
 *
 * Function: rachnopUpdateWhileFrozen
 * EN v1.0 Address: 0x80155B08
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155C1C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void rachnopUpdateWhileFrozen(uint obj, int state, undefined4 param_3, int eventKind)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind != 0x11)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXfox_runbreath2);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_801557D4
 * EN v1.0 Address: 0x80155B6C
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80155C80
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801557D4(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else
    {
        if ((*(short*)(*(int*)&((BaddieState*)state)->trackedObj + 0x44) == 1) &&
            (cond = (int)fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
        {
            *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 & ~0x10000;
        }
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            Sfx_PlayFromObject((uint)obj, SFXfox_runbreath1);
            fn_8014D08C((int)obj, state, 2, lbl_803E2A04, 0, 0);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80155884
 * EN v1.0 Address: 0x80155CAC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80155D30
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155884(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else if ((*(short*)(*(int*)&((BaddieState*)state)->trackedObj + 0x44) == 1) &&
        (cond = (int)fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
    {
        fn_80154FB4((double)lbl_803E2A30, (short*)obj, state, 0x19);
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            fn_8014D08C((int)obj, state, 0, lbl_803E2A30, 0, 0);
            Sfx_PlayFromObject((uint)obj, SFXfox_roll4);
        }
    }
    else
    {
        *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80155948
 * EN v1.0 Address: 0x80155E00
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x80155DF4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155948(int* obj, int state)
{
    short move;
    int cond;
    ushort outIds[2];
    float outVec[3];

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else if ((*(short*)(*(int*)&((BaddieState*)state)->trackedObj + 0x44) == 1) &&
        (cond = (int)fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
    {
        ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
        move = *(short*)(obj + 0x28);
        if (move == 3)
        {
            fn_80154FB4((double)lbl_803E2A00, (short*)obj, state, 0x19);
        }
        else if ((move == 0) || (move == 1))
        {
            fn_80154FB4((double)lbl_803E2A30, (short*)obj, state, 0x19);
        }
        fn_80154D0C((int)obj, state, outIds, outVec);
        if (((((BaddieState*)state)->controlFlags & 0x40000000) != 0) ||
            ((outIds[0] < 0x5dc && (*(short*)(obj + 0x28) != 1))))
        {
            if (outIds[0] < 0x5dc)
            {
                Sfx_PlayFromObject((uint)obj, SFXfox_roll3);
                fn_8014D08C((int)obj, state, 1, lbl_803E2A30, 0, 0);
            }
            else
            {
                fn_8014D08C((int)obj, state, 3, lbl_803E2A30, 0, 0);
            }
        }
    }
    else
    {
        *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: rachnopInit
 * EN v1.0 Address: 0x8015603C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155F58
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void rachnopInit(undefined4 param_1, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = lbl_803E2A34;
    *(undefined4*)&((BaddieState*)state)->unk2E4 = 1;
    fa = lbl_803E2A38;
    ((BaddieState*)state)->unk308 = lbl_803E2A38;
    ((BaddieState*)state)->unk300 = fa;
    ((BaddieState*)state)->unk304 = lbl_803E2A3C;
    ((BaddieState*)state)->unk320 = 0;
    fb = lbl_803E2A40;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A40;
    ((BaddieState*)state)->unk321 = 4;
    fa = lbl_803E2A04;
    ((BaddieState*)state)->unk318 = lbl_803E2A04;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    *(float*)(state + 0x324) = lbl_803E2A00;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    ((BaddieState*)state)->pathStep = fa;
    return;
}

/*
 * --INFO--
 *
 * Function: pollenFn_80155b10
 * EN v1.0 Address: 0x801560A0
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80155FBC
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pollenFn_80155b10(uint obj, int state)
{
    uint loadLocked;
    int ref;
    undefined2* setup;
    f32 spd;
    f32 t;
    f32 dx;
    f32 dz;
    f32 a[3];
    f32 b[3];
    float velXZ;
    float cosVal;
    float velY;
    float cosPitch;

    loadLocked = Obj_IsLoadingLocked();
    if ((loadLocked & 0xff) != 0)
    {
        a[0] = ((GameObject*)obj)->anim.localPosX;
        a[1] = lbl_803E2A48 + ((GameObject*)obj)->anim.localPosY;
        a[2] = ((GameObject*)obj)->anim.localPosZ;
        ref = *(int*)&((BaddieState*)state)->trackedObj;
        b[0] = *(float*)(ref + 0xc);
        b[1] = lbl_803E2A4C + *(float*)(ref + 0x10);
        b[2] = *(float*)(ref + 0x14);
        spd = lbl_803E2A50 *
            (lbl_803E2A58 * (f32)(int)
        randomGetRange(-10, 10) + lbl_803E2A54
        )
        ;
        ref = fn_80169EF4(spd, lbl_803E2A5C, a, b, 1);
        fn_80293018(ref, &cosVal, &velXZ);
        velXZ = velXZ * spd;
        cosVal = cosVal * spd;
        dx = b[0] - ((GameObject*)obj)->anim.localPosX;
        dz = b[2] - ((GameObject*)obj)->anim.localPosZ;
        if (lbl_803E2A60 != dz)
        {
            ref = getAngle(dx, dz);
            fn_80293018(ref, &cosPitch, &velY);
            t = velXZ;
            velY = velY * t;
            velXZ = t * cosPitch;
        }
        else
        {
            velY = lbl_803E2A60;
        }
        setup = Obj_AllocObjectSetup(0x24, 0x47b);
        *(float*)(setup + 4) = a[0];
        *(float*)(setup + 6) = a[1];
        *(undefined4*)(setup + 8) = a[2];
        *(undefined*)(setup + 2) = 1;
        *(undefined*)((int)setup + 5) = 1;
        *(undefined*)(setup + 3) = 0xff;
        *(undefined*)((int)setup + 7) = 0xff;
        ref = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (ref != 0)
        {
            *(float*)(ref + 0x24) = velXZ;
            *(float*)(ref + 0x28) = cosVal;
            *(float*)(ref + 0x2c) = velY;
            *(uint*)(ref + 0xc4) = obj;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt2);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: timeOfDayFn_80155cf8
 * EN v1.0 Address: 0x80156314
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801561A4
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void timeOfDayFn_80155cf8(int obj, int state)
{
    byte isDaytime;
    float timeInfo[4];

    (*(code*)(*(int*)gSHthorntailAnimationInterface + 0x14))(timeInfo);
    if ((timeInfo[0] >= lbl_803E2A70) && (timeInfo[0] <= lbl_803E2A74))
    {
        isDaytime = 1;
    }
    else
    {
        isDaytime = 0;
    }
    if ((isDaytime != 0) && (((BaddieState*)state)->seqEntryIndex == 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
        fn_8014D08C(obj, state, 1, lbl_803E2A78, 0, 0);
    }
    else if ((isDaytime == 0) && (((BaddieState*)state)->seqEntryIndex == 2))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
        fn_8014D08C(obj, state, 3, lbl_803E2A78, 0, 0);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: baddieUpdateWhileFrozen_80155e10
 * EN v1.0 Address: 0x801564EC
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801562BC
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void baddieUpdateWhileFrozen_80155e10(uint obj, int state, undefined4 param_11, int eventKind, undefined4 param_13,
                                      int damage)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind == 0x11)
    {
        if ((((BaddieState*)state)->seqEntryIndex == 2) && (((GameObject*)obj)->anim.currentMove != 5))
        {
            fn_8014D08C(obj, state, 5, lbl_803E2A7C, 0, 0);
        }
    }
    else if ((((GameObject*)obj)->anim.currentMove == 5) || (((GameObject*)obj)->anim.currentMove == 4))
    {
        if (damage > (int)(uint)((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt1);
            Sfx_PlayFromObject(obj, SFXen_blkscrp6);
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - damage;
            Sfx_PlayFromObject(obj, SFXfox_roll1);
            Sfx_PlayFromObject(obj, SFXen_blkscrp6);
        }
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
        Sfx_PlayFromObject(obj, SFXfox_roll2);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80155F20
 * EN v1.0 Address: 0x8015666C
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x801563CC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155F20(int obj, int state)
{
    *(float*)(state + 0x324) = lbl_803E2A60;
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        if (((BaddieState*)state)->seqEntryIndex == 1)
        {
            if (((GameObject*)obj)->anim.currentMove == 1)
            {
                ((BaddieState*)state)->seqEntryIndex = 2;
                *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 & ~0x10000;
            }
            else if (((GameObject*)obj)->anim.currentMove == 3)
            {
                ((BaddieState*)state)->seqEntryIndex = 0;
                *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
                fn_8014D08C(obj, state, 0, lbl_803E2A54, 0, 0);
            }
        }
        else if ((((BaddieState*)state)->seqEntryIndex == 2) && (((GameObject*)obj)->anim.currentMove != 2))
        {
            fn_8014D08C(obj, state, 2, lbl_803E2A54, 0, 0);
        }
    }
    timeOfDayFn_80155cf8(obj, state);
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80156010
 * EN v1.0 Address: 0x80156978
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: 0x801564BC
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156010(uint obj, int state)
{
    bool timerExpired;
    short move;
    double dVar3;

    timerExpired = false;
    *(float*)(state + 0x324) = *(float*)(state + 0x324) - timeDelta;
    if (*(float*)(state + 0x324) <= lbl_803E2A60)
    {
        timerExpired = true;
        *(float*)(state + 0x324) = *(f32 *)&lbl_803E2A60;
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        move = ((GameObject*)obj)->anim.currentMove;
        if (move == 4)
        {
            pollenFn_80155b10(obj, state);
            *(float*)(state + 0x324) = lbl_803E2A80;
            fn_8014D08C(obj, state, 5, lbl_803E2A54, 0, 0);
        }
        else if ((move == 5) && (timerExpired))
        {
            fn_8014D08C(obj, state, 6, lbl_803E2A54, 0, 0);
            Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
        }
        else if (move == 6)
        {
            fn_8014D08C(obj, state, 2, lbl_803E2A54, 0, 0);
            *(float*)(state + 0x324) = lbl_803E2A80;
        }
        else if (((move == 2) && (timerExpired)) && ((((BaddieState*)state)->controlFlags & 0x4000000) != 0))
        {
            fn_8014D08C(obj, state, 4, lbl_803E2A54, 0, 0);
            dVar3 = (double)Sfx_PlayFromObject(obj, SFXfox_fightbreath1);
        }
    }
    timeOfDayFn_80155cf8(obj, state);
    return;
}

/*
 * --INFO--
 *
 * Function: baddieInit_80156188
 * EN v1.0 Address: 0x80156DE4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80156634
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void baddieInit_80156188(undefined4 param_1, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = lbl_803E2A84;
    *(undefined4*)&((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = lbl_803E2A58;
    ((BaddieState*)state)->unk300 = lbl_803E2A88;
    ((BaddieState*)state)->unk304 = lbl_803E2A8C;
    ((BaddieState*)state)->unk320 = 0;
    fb = lbl_803E2A90;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A90;
    ((BaddieState*)state)->unk321 = 7;
    fa = lbl_803E2A54;
    ((BaddieState*)state)->unk318 = lbl_803E2A54;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    ((BaddieState*)state)->seqEntryIndex = 0;
    *(float*)(state + 0x324) = lbl_803E2A60;
    ((BaddieState*)state)->pathStep = fa;
    return;
}

/*
 * --INFO--
 *
 * Function: wbUpdateWhileFrozen
 * EN v1.0 Address: 0x80156E48
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80156698
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wbUpdateWhileFrozen(uint obj, int state, undefined4 param_3, int eventKind)
{
    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXfox_cough3);
            ((BaddieState*)state)->hitCounter = 0;
            *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x20;
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_8015625C
 * EN v1.0 Address: 0x80156EB8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80156708
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015625C(uint obj, int state)
{
    f32 zero;
    uint randVal;
    int tracked;
    f32 moveSpeed;

    if (*(float*)(state + 0x328) > lbl_803E2AA8)
    {
        *(float*)(state + 0x328) = lbl_803E2AAC;
    }
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXfox_cough4);
    }
    *(float*)(state + 0x328) = *(float*)(state + 0x328) - timeDelta;
    if (*(float*)(state + 0x328) <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            *(float*)(state + 0x328) = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            *(float*)(state + 0x328) = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_decoy);
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    zero = lbl_803E2A98;
    if (*(float*)(state + 0x324) > zero)
    {
        *(float*)(state + 0x324) = *(float*)(state + 0x324) - timeDelta;
        if (*(float*)(state + 0x324) <= zero)
        {
            *(float*)(state + 0x324) = lbl_803E2AB0;
            *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 | 0x10000;
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x400) != 0)
    {
        *(float*)(state + 0x324) = lbl_803E2AB0;
    }
    if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2AB4;
    }
    else
    {
        tracked = *(int*)&((BaddieState*)state)->trackedObj;
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, *(float*)(tracked + 0x18),
                                                         lbl_803E2AB8 + *(float*)(tracked + 0x1c),
                                                         *(float*)(tracked + 0x20),
                                                         lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                         ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

/*
 * --INFO--
 *
 * Function: fn_8015652C
 * EN v1.0 Address: 0x80157220
 * EN v1.0 Size: 1284b
 * EN v1.1 Address: 0x801569D8
 * EN v1.1 Size: 892b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015652C(uint obj, int state)
{
    f32 zero;
    uint randVal;
    float* curveState;
    int placement;
    f32 moveSpeed;

    curveState = *(float**)state;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXfox_cough4);
    }
    *(float*)(state + 0x328) = *(float*)(state + 0x328) - timeDelta;
    if (*(float*)(state + 0x328) <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            *(float*)(state + 0x328) = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            *(float*)(state + 0x328) = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_decoy);
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    zero = lbl_803E2A98;
    if (*(float*)(state + 0x324) > zero)
    {
        *(float*)(state + 0x324) = *(float*)(state + 0x324) - timeDelta;
        if (*(float*)(state + 0x324) <= zero)
        {
            *(float*)(state + 0x324) = zero;
        }
    }
    else
    {
        *(uint*)&((BaddieState*)state)->unk2E4 = *(uint*)&((BaddieState*)state)->unk2E4 & ~0x10000;
    }
    if ((((BaddieState*)state)->controlFlags & 0x2000) != 0)
    {
        if (((Curve_AdvanceAlongPath((int)curveState, ((BaddieState*)state)->pathStep) != 0 ||
                    *(int*)(curveState + 4) != 0) &&
                (*gRomCurveInterface)->goNextPoint(curveState) != 0) &&
            (*gRomCurveInterface)->initCurve(*(void**)state, (void*)obj, lbl_803E2AE4,
                                             (int*)&lbl_803DBCD8, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~0x2000;
        }
        if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
        {
            moveSpeed = lbl_803E2ABC;
        }
        else
        {
            moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, curveState[0x1a], curveState[0x1b], curveState[0x1c],
                                                             lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                             ((BaddieState*)state)->unk304);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2ABC;
    }
    else
    {
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, *(float*)(placement + 8), *(float*)(placement + 0xc),
                                                         *(float*)(placement + 0x10), lbl_803E2ABC, lbl_803E2AC0,
                                                         lbl_803E2AC4,
                                                         ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

/*
 * --INFO--
 *
 * Function: wbInit
 * EN v1.0 Address: 0x80157724
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80156D54
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wbInit(undefined4 param_1, int state)
{
    float fa;
    uint ua;

    ((BaddieState*)state)->speedScale = lbl_803E2AE8;
    *(undefined4*)&((BaddieState*)state)->unk2E4 = 0x2002b029;
    ((BaddieState*)state)->unk308 = lbl_803E2ACC;
    ((BaddieState*)state)->unk300 = lbl_803E2AEC;
    ((BaddieState*)state)->unk304 = lbl_803E2AF0;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2AF4;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2AF4;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 2;
    ((BaddieState*)state)->unk31C = fa;
    ua = randomGetRange(0x78, 0x1e0);
    *(float*)(state + 0x328) =
        (float)(int)ua;
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80156950
 * EN v1.0 Address: 0x801577C8
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x80156DFC
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156950(uint obj, int state)
{
    switch (*(short*)(obj + 0xa0))
    {
    case 5:
        if (*(ushort*)(state + 0x2f8) != 0)
        {
            Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
        }
        break;
    case 6:
        if (*(ushort*)(state + 0x2f8) != 0)
        {
            Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
        }
        break;
    case 7:
        if (*(ushort*)(state + 0x2f8) != 0)
        {
            if (*(float*)(obj + 0x98) < lbl_803E2AF8)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
            }
        }
        break;
    case 8:
        if (*(ushort*)(state + 0x2f8) != 0)
        {
            if (*(float*)(obj + 0x98) < lbl_803E2AFC)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath1);
            }
            else if (*(float*)(obj + 0x98) < lbl_803E2B00)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath4);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
            }
        }
        break;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: mutatedEbaUpdateWhileFrozen
 * EN v1.0 Address: 0x801578C4
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x80156EF0
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mutatedEbaUpdateWhileFrozen(uint obj, int state, undefined4 param_11, int eventKind)
{
    short move;

    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            move = ((GameObject*)obj)->anim.currentMove;
            if ((((move == 0) || (move == 1)) || (move == 3)) || (move == 4))
            {
                Sfx_PlayFromObject(obj, SFXfox_roll2);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
            }
            else
            {
                fn_8014D08C(obj, state, 4, lbl_803E2B04, 0, 0);
                ((BaddieState*)state)->seqEntryIndex = 0;
                Sfx_PlayFromObject(obj, SFXfox_roll1);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_80156B0C
 * EN v1.0 Address: 0x801579F4
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x80156FB8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156B0C(uint obj, int state)
{
    int tblOff;

    ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    if (((((BaddieState*)state)->controlFlags & 0x80000000) != 0) && (((BaddieState*)state)->seqEntryIndex <= 1))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | 0x40000000;
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ((BaddieState*)state)->seqEntryIndex += 1;
        if (10 < ((BaddieState*)state)->seqEntryIndex)
        {
            ((BaddieState*)state)->seqEntryIndex = 3;
        }
        if (*(ushort*)(state + 0x2a0) < 4)
        {
            tblOff = (uint)((BaddieState*)state)->seqEntryIndex * 0xc;
            fn_8014D08C(obj, state, (uint)lbl_8031F318[tblOff + 8],
                        *(float*)(lbl_8031F318 + tblOff), 0, 0);
        }
        else
        {
            tblOff = (uint)((BaddieState*)state)->seqEntryIndex * 0xc;
            fn_8014D08C(obj, state, (uint)lbl_8031F318[tblOff + 9],
                        *(float*)(lbl_8031F318 + tblOff), 0, 0);
        }
    }
    fn_80156950(obj, state);
    return;
}

/*
 * --INFO--
 * Function: fn_80156C34
 * EN v1.0 Address: 0x80156C34
 * EN v1.0 Size: 168b
 */
void fn_80156C34(uint obj, int state)
{
    int tblOff;
    uint phase;

    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        phase = ((BaddieState*)state)->seqEntryIndex;
        if (phase == 0)
        {
            ((BaddieState*)state)->seqEntryIndex += 1;
        }
        else if (phase >= 2)
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
        tblOff = (uint)((BaddieState*)state)->seqEntryIndex * 0xc;
        fn_8014D08C(obj, state, (uint)lbl_8031F318[tblOff + 8],
                    *(float*)(lbl_8031F318 + tblOff), 0, 0);
    }
    fn_80156950(obj, state);
    return;
}

/*
 * --INFO--
 * Function: mutatedEbaInit
 * EN v1.0 Address: 0x80156CDC
 * EN v1.0 Size: 104b
 */
void mutatedEbaInit(undefined4 param_1, int state)
{
    float fa;

    ((BaddieState*)state)->speedScale = lbl_803E2A84;
    *(undefined4*)&((BaddieState*)state)->unk2E4 = 0x46001;
    ((BaddieState*)state)->unk308 = lbl_803E2A58;
    ((BaddieState*)state)->unk300 = lbl_803E2A88;
    ((BaddieState*)state)->unk304 = lbl_803E2A8C;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2A54;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A54;
    ((BaddieState*)state)->unk321 = 4;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 3;
    ((BaddieState*)state)->unk31C = fa;
    ((BaddieState*)state)->seqEntryIndex = 1;
    ((BaddieState*)state)->hitCounter = 0xa;
    return;
}

/*
 * --INFO--
 * Function: hoodedZyckUpdateWhileFrozen
 * EN v1.0 Address: 0x80156D44
 * EN v1.0 Size: 92b
 */
void hoodedZyckUpdateWhileFrozen(uint obj, int state, undefined4 param_3, int eventKind)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXwatery_bubble2);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

/*
 * --INFO--
 * Function: fn_80156DA0
 * EN v1.0 Address: 0x80156DA0
 * EN v1.0 Size: 612b
 */
void fn_80156DA0(int obj, int state)
{
    bool resetting;
    int groundHit;
    ushort randBit;
    float fromPos[3];
    float toPos[3];
    float sinYaw;
    float cosYaw;
    undefined4 hitOut;

    *(float*)(state + 0x324) = *(float*)(state + 0x324) - timeDelta;
    if (*(float*)(state + 0x324) <= lbl_803E2A60)
    {
        *(float*)(state + 0x324) = (float)(int)randomGetRange(0x3c, 0x78);
    }
    if (lbl_803E2A60 != *(float*)(state + 0x328))
    {
        ObjHits_DisableObject(obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            fn_8014D08C(obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            ObjHits_EnableObject(obj);
            *(float*)(state + 0x328) = lbl_803E2A60;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        resetting = true;
    }
    else
    {
        resetting = false;
    }
    if (!resetting)
    {
        *(short*)obj = (short)((short)*(short*)obj + (short)*(ushort*)(state + 0x338));
        fromPos[0] = ((GameObject*)obj)->anim.localPosX;
        fromPos[1] = ((GameObject*)obj)->anim.localPosY;
        fromPos[2] = ((GameObject*)obj)->anim.localPosZ;
        fn_80292E20((uint) * (ushort*)obj, &sinYaw, &cosYaw);
        toPos[0] = ((GameObject*)obj)->anim.localPosX - lbl_803E2ABC * sinYaw;
        toPos[1] = lbl_803E2AC0 + ((GameObject*)obj)->anim.localPosY;
        toPos[2] = ((GameObject*)obj)->anim.localPosZ - lbl_803E2ABC * cosYaw;
        hitOut = 0;
        groundHit = objBboxFn_800640cc(fromPos, toPos, (float*)0x3, &hitOut, obj,
                                   (uint) * (byte*)(state + 0x261), 0xff, 0xffffffff, 0);
        if (((groundHit & 0xff) == 0) || ((((BaddieState*)state)->controlFlags & 0x40000000) == 0))
        {
            if ((groundHit & 0xff) != 0)
            {
                if (((GameObject*)obj)->anim.currentMove == 0)
                {
                    *(undefined2*)(state + 0x338) = 0;
                    fn_8014D08C(obj, state, 0, lbl_803E2AC8, 0, 1);
                }
                else
                {
                    float fz;
                    fn_8014D08C(obj, state, 1, lbl_803E2ACC, 0, 0);
                    fz = lbl_803E2B18;
                    ((GameObject*)obj)->anim.velocityX = fz;
                    ((GameObject*)obj)->anim.velocityY = fz;
                    ((GameObject*)obj)->anim.velocityZ = fz;
                    randBit = (ushort)randomGetRange(0, 1);
                    *(undefined2*)(state + 0x338) = (ushort)((randBit - 1) * 0x12c);
                }
            }
        }
        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    }
    return;
}
