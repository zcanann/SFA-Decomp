#include "main/dll/baddie_state.h"
#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/sidekickToy.h"
#include "main/dll/mediumbasket.h"
#include "main/dll/tricky_state.h"

typedef struct BaddieAfterUpdateBonesCbState
{
    u8 pad0[0x2B0 - 0x0];
    s16 unk2B0;
    u16 unk2B2;
    u8 pad2B4[0x2D8 - 0x2B4];
    f32 unk2D8;
    u32 unk2DC;
    u8 pad2E0[0x2F2 - 0x2E0];
    u8 unk2F2;
    u8 unk2F3;
    u8 unk2F4;
    u8 pad2F5[0x36C - 0x2F5];
    s32 unk36C;
} BaddieAfterUpdateBonesCbState;


typedef struct SidekickToyUpdateCurveTargetLatchState
{
    u8 pad0[0x2B0 - 0x0];
    s16 unk2B0;
    u16 unk2B2;
    u8 pad2B4[0x2D8 - 0x2B4];
    f32 unk2D8;
    u8 pad2DC[0x2F2 - 0x2DC];
    u8 unk2F2;
    u8 unk2F3;
    u8 unk2F4;
    u8 pad2F5[0x36C - 0x2F5];
    s32 unk36C;
} SidekickToyUpdateCurveTargetLatchState;


extern undefined4 ABS();
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 ObjHits_DisableObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined4 fn_80154870();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern undefined4 FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern ulonglong FUN_8028682c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80292754();
extern double FUN_80293900();

extern undefined4 DAT_8031e840;
extern undefined4 DAT_8031e860;
extern f64 DOUBLE_803e3218;
extern f64 DOUBLE_803e3278;
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3258;
extern f32 lbl_803E3264;
extern f32 lbl_803E3280;

typedef struct
{
    s16 rx, ry, rz, pad;
    f32 scale;
    f32 x, y, z;
} TrickyPosRot;

typedef struct
{
    f32 dx, dy, dz;
    u8 pad0[2];
    s16 dAngle;
    u8 pad1[3];
    s8 events[8];
    s8 eventCount;
} TrickyMoveResult;

extern void* memcpy(void* dst, void* src, int n);
extern void characterDoEyeAnims(short* obj, void* p);
extern void fn_8003B0D0(short* obj, int b, void* c, int d);
extern void trickyFn_80148d8c(short* obj, int state);
extern void Tricky_resumeAfterCommand(short* obj, int state);
extern void Tricky_applyFloorResponse(short* obj, int state);
extern void setMatrixFromObjectPos(f32* mtx, void* rec);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 sqrtf(f32);
extern f32 powfBitEstimate(f32 x, f32 y);
extern void objMove(short* obj, f32 dx, f32 dy, f32 dz);
extern void fn_8014FF20(short* obj, int state);
extern void fn_8014FF24(short* obj, int state);
extern void fn_80150910(short* obj, int state);
extern void fn_80150EDC(short* obj, int state);
extern void fn_8015165C(short* obj, int state);
extern void fn_80152040(short* obj, int state);
extern void fn_80152514(short* obj, int state);
extern void fn_80152B90(short* obj, int state);
extern void fn_80153040(short* obj, int state);
extern void fn_80153248(short* obj, int state);
extern void fn_8015383C(short* obj, int state);
extern void fn_80153BFC(short* obj, int state);
extern void fn_80153E0C(short* obj, int state);
extern void fn_801540A0(short* obj, int state);
extern void fn_80154584(short* obj, int state);
extern void fn_80155884(short* obj, int state);
extern void fn_80155948(short* obj, int state);
extern void fn_801557D4(short* obj, int state);
extern void fn_80155F20(short* obj, int state);
extern void fn_80156010(short* obj, int state);
extern void fn_8015625C(short* obj, int state);
extern void fn_8015652C(short* obj, int state);
extern void fn_80156B0C(short* obj, int state);
extern void fn_80156C34(short* obj, int state);
extern void fn_80156DA0(short* obj, int state);
extern void fn_80157004(short* obj, int state);
extern void fn_80157558(short* obj, int state);
extern void fn_80158494(short* obj, int state);
extern void fn_80158C2C(short* obj, int state);
extern void fn_80159284(short* obj, int state);
extern void fn_80159958(short* obj, int state);
extern void fn_80159FCC(short* obj, int state);
extern void fn_8015A924(short* obj, int state);
extern void smallbasket_applyReactionState(short* obj, int state);
extern f32 lbl_803E256C;
extern f32 lbl_803E2570;
extern f32 lbl_803E2574;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E25CC;
extern f32 lbl_803E25D0;
extern f32 lbl_803E25D4;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;

/*
 * --INFO--
 *
 * Function: objAnimFn_8014a9f0
 * EN v1.0 Address: 0x8014A9F0
 * EN v1.0 Size: 3720b
 * EN v1.1 Address: 0x8014AE50
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void objAnimFn_8014a9f0(short* obj, int state)
{
    f32 vy;
    f32 dz;
    f32 dx;
    f32 dy;
    uint flags;
    int mode;
    int i;
    f32 v;
    f32 c;
    f32 phase;
    f32 outY;
    TrickyMoveResult res;
    TrickyPosRot rec;
    f32 mtx[16];

    memcpy((void*)(state + 0x2c4), (void*)(state + 0x2b8), 0xc);
    memcpy((void*)(state + 0x2b8), obj + 0x12, 0xc);
    if ((((TrickyState*)state)->controlFlags & 0x400) != 0)
    {
        characterDoEyeAnims(obj, (void*)(state + 0x26c));
    }
    if ((*(void**)&((TrickyState*)state)->actionTargetObj != 0) && ((((TrickyState*)state)->controlFlags & 0x800) != 0))
    {
        fn_8003B0D0(obj, *(int*)&((TrickyState*)state)->actionTargetObj, (void*)(state + 0x26c), 0x19);
    }
    ((TrickyState*)state)->unk2F0 = ((TrickyState*)state)->unk2EF;
    flags = ((TrickyState*)state)->flags2DC;
    if ((flags & 0x800) != 0)
    {
        trickyFn_80148d8c(obj, state);
    }
    else if ((flags & 0x1000) != 0)
    {
        Tricky_resumeAfterCommand(obj, state);
    }
    else if ((flags & 0x20000000) != 0)
    {
        if ((flags & 0x400) != 0)
        {
            ((TrickyState*)state)->unk2EF = 3;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case 0x11:
            case 0x13a:
            case 0x5b7:
            case 0x5b8:
            case 0x5b9:
            case 0x5e1:
            case 0x7a6:
                fn_8015165C(obj, state);
                break;
            case 0xd8:
            case 0x281:
                fn_80152040(obj, state);
                break;
            case 0x613:
                fn_80152514(obj, state);
                break;
            case 0x642:
                fn_80152B90(obj, state);
                break;
            case 0x3fe:
            case 0x7c6:
                fn_80153248(obj, state);
                break;
            case 0x58b:
                fn_80153BFC(obj, state);
                break;
            case 0x369:
                fn_801540A0(obj, state);
                break;
            case 0x251:
                fn_80154870(obj, state);
                break;
            case 0x25d:
                fn_80155948(obj, state);
                break;
            case 0x457:
                fn_80156010(obj, state);
                break;
            case 0x4d7:
                fn_8015625C(obj, state);
                break;
            case 0x458:
                fn_80156B0C(obj, state);
                break;
            case 0x851:
                mediumbasket_enterWhirlpoolGroup((int*)obj, (GroundBaddieState*)state);
                break;
            case 0x842:
            case 0x84b:
                fn_8015A924(obj, state);
                break;
            case 0x4ac:
                fn_80157558(obj, state);
                break;
            case 0x427:
                fn_8014FF24(obj, state);
                break;
            case 0x6a2:
            case 0x6a3:
            case 0x6a4:
            case 0x6a5:
                fn_80159284(obj, state);
                break;
            case 0x7c8:
                fn_80159958(obj, state);
                break;
            case 0x7c7:
            default:
                fn_8014FF24(obj, state);
                break;
            }
        }
        else
        {
            ((TrickyState*)state)->unk2EF = 4;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case 0x11:
            case 0x13a:
            case 0x5b7:
            case 0x5b8:
            case 0x5b9:
            case 0x5e1:
            case 0x7a6:
                fn_80150EDC(obj, state);
                break;
            case 0xd8:
            case 0x281:
                fn_80152040(obj, state);
                break;
            case 0x613:
                fn_80152514(obj, state);
                break;
            case 0x642:
                fn_80152B90(obj, state);
                break;
            case 0x3fe:
            case 0x7c6:
                fn_80153248(obj, state);
                break;
            case 0x58b:
                fn_80153BFC(obj, state);
                break;
            case 0x369:
                fn_801540A0(obj, state);
                break;
            case 0x251:
                fn_80154870(obj, state);
                break;
            case 0x25d:
                fn_80155884(obj, state);
                break;
            case 0x457:
                fn_80156010(obj, state);
                break;
            case 0x4d7:
                fn_8015625C(obj, state);
                break;
            case 0x458:
                fn_80156B0C(obj, state);
                break;
            case 0x851:
                mediumbasket_enterWhirlpoolGroup((int*)obj, (GroundBaddieState*)state);
                break;
            case 0x842:
            case 0x84b:
                fn_8015A924(obj, state);
                break;
            case 0x4ac:
                fn_80157004(obj, state);
                break;
            case 0x427:
                fn_8014FF20(obj, state);
                break;
            case 0x6a2:
            case 0x6a3:
            case 0x6a4:
            case 0x6a5:
                fn_80158C2C(obj, state);
                break;
            case 0x7c8:
                fn_80159FCC(obj, state);
                break;
            case 0x7c7:
            default:
                fn_8014FF20(obj, state);
                break;
            }
        }
    }
    else if ((flags & 0x100) != 0)
    {
        ((TrickyState*)state)->unk2EF = 2;
        if (((((TrickyState*)state)->flags2DC & 0x100) != 0) && ((((TrickyState*)state)->unk2E0 & 0x100) == 0))
        {
            int moveId = ((TrickyState*)state)->unk322;
            ((TrickyState*)state)->animPlaySpeed = lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->unk31C);
            ((TrickyState*)state)->unk323 = 1;
            ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E2574, 0x10);
            if (*(void**)(obj + 0x2a) != 0)
            {
                *(u8*)(*(int*)(obj + 0x2a) + 0x70) = 0;
            }
        }
        if ((((TrickyState*)state)->flags2DC & 0x40000000) != 0)
        {
            ((TrickyState*)state)->animPlaySpeed = lbl_803E2578;
            ((TrickyState*)state)->unk323 = 0;
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2574, 0);
            if (*(void**)(obj + 0x2a) != 0)
            {
                *(u8*)(*(int*)(obj + 0x2a) + 0x70) = 0;
            }
            ((TrickyState*)state)->flags2DC &= ~0x100LL;
            *(u8*)(obj + 0x1b) = 0xff;
        }
        else
        {
            *(u8*)(obj + 0x1b) = (u8)(int)(lbl_803E257C * *(f32*)(obj + 0x4c));
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~0x4000;
        }
    }
    else
    {
        ((TrickyState*)state)->unk2EF = 5;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x11:
        case 0x13a:
        case 0x5b7:
        case 0x5b8:
        case 0x5b9:
        case 0x5e1:
        case 0x7a6:
            fn_80150910(obj, state);
            break;
        case 0xd8:
        case 0x281:
            fn_80152040(obj, state);
            break;
        case 0x613:
            fn_80152514(obj, state);
            break;
        case 0x642:
            fn_80152B90(obj, state);
            break;
        case 0x3fe:
        case 0x7c6:
            fn_80153040(obj, state);
            break;
        case 0x58b:
            fn_8015383C(obj, state);
            break;
        case 0x369:
            fn_80153E0C(obj, state);
            break;
        case 0x251:
            fn_80154584(obj, state);
            break;
        case 0x25d:
            fn_801557D4(obj, state);
            break;
        case 0x457:
            fn_80155F20(obj, state);
            break;
        case 0x4d7:
            fn_8015652C(obj, state);
            break;
        case 0x458:
            fn_80156C34(obj, state);
            break;
        case 0x851:
            mediumbasket_leaveWhirlpoolGroup((int*)obj, (GroundBaddieState*)state);
            break;
        case 0x842:
        case 0x84b:
            smallbasket_applyReactionState(obj, state);
            break;
        case 0x4ac:
            fn_80156DA0(obj, state);
            break;
        case 0x427:
            fn_8014FF20(obj, state);
            break;
        case 0x6a2:
        case 0x6a3:
        case 0x6a4:
        case 0x6a5:
            fn_80158494(obj, state);
            break;
        case 0x7c8:
            fn_80159958(obj, state);
            break;
        case 0x7c7:
        default:
            fn_8014FF20(obj, state);
            break;
        }
    }
    if (((TrickyState*)state)->unk2EF != ((TrickyState*)state)->unk2F0)
    {
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC | 0x80000000;
    }
    else
    {
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & 0x7fffffff;
    }
    res.eventCount = 0;
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, ((TrickyState*)state)->animPlaySpeed,
                                                                    timeDelta,
                                                                    (ObjAnimEventList*)&res) != 0)
    {
        ((TrickyState*)state)->flags2DC |= 0x40000000LL;
    }
    else
    {
        ((TrickyState*)state)->flags2DC &= ~0x40000000LL;
    }
    ((TrickyState*)state)->unk2F8 = 0;
    for (i = 0; i < res.eventCount; i++)
    {
        ((TrickyState*)state)->unk2F8 |= 1 << res.events[i];
    }
    vy = lbl_803E2574;
    if ((((((TrickyState*)state)->controlFlags & 0x20) != 0) && ((((TrickyState*)state)->controlFlags & 0x400000) == 0))
        && (((((TrickyState*)state)->flags2DC & 0x1800) == 0) && ((((TrickyState*)state)->unk323 & 4) == 0)))
    {
        vy = -(((TrickyState*)state)->unk300 * timeDelta - *(f32*)(obj + 0x14));
    }
    v = *(f32*)(obj + 0x12);
    *(f32*)(obj + 0x12) = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
    v = *(f32*)(obj + 0x14);
    *(f32*)(obj + 0x14) = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
    v = *(f32*)(obj + 0x16);
    *(f32*)(obj + 0x16) = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
    mode = 0;
    if (((((TrickyState*)state)->controlFlags & 0x80) != 0) && (((TrickyState*)state)->unk323 != 0))
    {
        mode = 1;
    }
    else if ((((TrickyState*)state)->controlFlags & 0x100) != 0)
    {
        mode = 2;
    }
    else if ((((TrickyState*)state)->controlFlags & 0x10) != 0)
    {
        mode = 3;
    }
    if (((((TrickyState*)state)->controlFlags & 0x200) != 0) && ((((TrickyState*)state)->flags2DC & 0x4010) != 0))
    {
        mode = 3;
    }
    if (mode == 1)
    {
        f32 zero;
        dx = (dz = lbl_803E2574);
        dy = dz;
        if ((((TrickyState*)state)->unk323 & 2) != 0)
        {
            dx = res.dx * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->unk323 & 4) != 0)
        {
            dy = res.dy * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->unk323 & 1) != 0)
        {
            dz = -res.dz * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->unk323 & 8) != 0)
        {
            ((GameObject*)obj)->anim.rotX += res.dAngle;
        }
        rec.rx = ((GameObject*)obj)->anim.rotX;
        rec.ry = ((GameObject*)obj)->anim.rotY;
        rec.rz = ((GameObject*)obj)->anim.rotZ;
        rec.scale = lbl_803E256C;
        zero = lbl_803E2574;
        rec.x = zero;
        rec.y = zero;
        rec.z = zero;
        setMatrixFromObjectPos(mtx, &rec);
        if ((((TrickyState*)state)->unk323 & 4) != 0)
        {
            Matrix_TransformPoint(mtx, dx, dy, -dz, (f32*)(obj + 0x12), (f32*)(obj + 0x14), (f32*)(obj + 0x16));
        }
        else
        {
            Matrix_TransformPoint(mtx, dx, lbl_803E2574, -dz, (f32*)(obj + 0x12), &outY, (f32*)(obj + 0x16));
        }
    }
    else if (mode == 2)
    {
        if (ObjAnim_SampleRootCurvePhase(
            sqrtf(*(f32*)(obj + 0x12) * *(f32*)(obj + 0x12) +
                *(f32*)(obj + 0x16) * *(f32*)(obj + 0x16)),
            (ObjAnimComponent*)obj, &phase) != 0)
        {
            ((TrickyState*)state)->animPlaySpeed = phase;
        }
    }
    else if (mode == 3)
    {
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            *(f32*)(obj + 0x12) = *(f32*)(obj + 0x12) * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            *(f32*)(obj + 0x14) = *(f32*)(obj + 0x14) * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            *(f32*)(obj + 0x16) = *(f32*)(obj + 0x16) * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
        }
    }
    Tricky_applyFloorResponse(obj, state);
    if (((((TrickyState*)state)->controlFlags & 0x400000) != 0) || ((((TrickyState*)state)->flags2DC & 0x8100000) != 0))
    {
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            objMove(obj, *(f32*)(obj + 0x12) * timeDelta, *(f32*)(obj + 0x14) * timeDelta,
                    *(f32*)(obj + 0x16) * timeDelta);
        }
    }
    else if ((((TrickyState*)state)->controlFlags & 0x20) != 0)
    {
        f32 newY = (*(f32*)(obj + 0x14) * timeDelta + *(f32*)(obj + 8))
            - lbl_803E25D4 * (((TrickyState*)state)->unk300 * (timeDelta * timeDelta));
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            objMove(obj, *(f32*)(obj + 0x12) * timeDelta, newY - *(f32*)(obj + 8),
                    *(f32*)(obj + 0x16) * timeDelta);
            *(f32*)(obj + 0x14) = vy;
        }
    }
    else if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
    {
        objMove(obj, *(f32*)(obj + 0x12) * timeDelta, *(f32*)(obj + 0x14) * timeDelta,
                *(f32*)(obj + 0x16) * timeDelta);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_8014ab58
 * EN v1.0 Address: 0x8014AB58
 * EN v1.0 Size: 5468b
 * EN v1.1 Address: 0x8014AE50
 * EN v1.1 Size: 3744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8014c690
 * EN v1.0 Address: 0x8014C690
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014C294
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8014c694
 * EN v1.0 Address: 0x8014C694
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8014C4DC
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8014c78c
 * EN v1.0 Address: 0x8014C78C
 * EN v1.0 Size: 772b
 * EN v1.1 Address: 0x8014C594
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c78c(undefined4 param_1, undefined4 param_2, int param_3, int* param_4)
{
    ushort uVar1;
    ushort* puVar2;
    uint uVar3;
    undefined4* puVar4;
    int iVar5;
    int iVar6;
    int iVar7;
    int iVar8;
    double extraout_f1;
    double dVar9;
    ulonglong uVar10;
    float local_48;
    int local_44;
    float local_40;
    float local_3c;
    float local_38;
    longlong local_30;

    uVar10 = FUN_8028682c();
    puVar2 = (ushort*)(uVar10 >> 0x20);
    local_48 = (float)extraout_f1;
    iVar8 = *(int*)(puVar2 + 0x5c);
    local_44 = 0;
    iVar7 = 0;
    if ((uVar10 & 1) == 0)
    {
        local_48 = (float)extraout_f1 * (float)extraout_f1;
        puVar4 = ObjGroup_GetObjects(3, &local_44);
        if (local_44 != 0)
        {
            for (iVar6 = 0; iVar6 < local_44; iVar6 = iVar6 + 1)
            {
                dVar9 = FUN_80017714((float*)(puVar2 + 0xc), (float*)(puVar4[iVar6] + 0x18));
                if ((dVar9 < (double)local_48) && ((ushort*)puVar4[iVar6] != puVar2))
                {
                    *param_4 = (int)puVar4[iVar6];
                    dVar9 = FUN_80293900(dVar9);
                    local_30 = (longlong)(int)
                    dVar9;
                    *(short*)(param_4 + 1) = (short)(int)dVar9;
                    if ((uVar10 & 2) != 0)
                    {
                        if ((*(uint*)(iVar8 + 0x2e4) & 0x8000) == 0)
                        {
                            iVar5 = *param_4;
                            local_40 = *(float*)(puVar2 + 0xc) - *(float*)(iVar5 + 0x18);
                            local_3c = *(float*)(puVar2 + 0xe) - *(float*)(iVar5 + 0x1c);
                            local_38 = *(float*)(puVar2 + 0x10) - *(float*)(iVar5 + 0x20);
                        }
                        else
                        {
                            local_40 = *(float*)(puVar2 + 0xc) - *(float*)(*param_4 + 0x18);
                            local_3c = lbl_803E31FC;
                            local_38 = *(float*)(puVar2 + 0x10) - *(float*)(*param_4 + 0x20);
                        }
                        uVar3 = FUN_80017730();
                        if (*(short**)(puVar2 + 0x18) == (short*)0x0)
                        {
                            uVar1 = *puVar2;
                        }
                        else
                        {
                            uVar1 = *puVar2 + **(short**)(puVar2 + 0x18);
                        }
                        uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
                        if (0x8000 < (int)uVar3)
                        {
                            uVar3 = uVar3 - 0xffff;
                        }
                        if ((int)uVar3 < -0x8000)
                        {
                            uVar3 = uVar3 + 0xffff;
                        }
                        iVar5 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
                        *(uint*)(iVar8 + 0x2dc) = *(uint*)(iVar8 + 0x2dc) & ~*(uint*)(&DAT_8031e840 + iVar5);
                        if ((uVar10 & 4) != 0)
                        {
                            *(uint*)(*(int*)(*param_4 + 0xb8) + 0x2dc) =
                                *(uint*)(*(int*)(*param_4 + 0xb8) + 0x2dc) & ~*(uint*)(&DAT_8031e860 + iVar5);
                        }
                    }
                    param_4 = param_4 + 2;
                    iVar7 = iVar7 + 1;
                    if (param_3 <= iVar7)
                    {
                        iVar6 = local_44;
                    }
                }
            }
        }
    }
    else
    {
        iVar7 = ObjGroup_FindNearestObject(3, puVar2, &local_48);
        *param_4 = iVar7;
        if (iVar7 != 0)
        {
            local_30 = (longlong)(int)
            local_48;
            *(short*)(param_4 + 1) = (short)(int)local_48;
            if ((uVar10 & 2) != 0)
            {
                if ((*(uint*)(iVar8 + 0x2e4) & 0x8000) == 0)
                {
                    iVar7 = *param_4;
                    local_40 = *(float*)(puVar2 + 0xc) - *(float*)(iVar7 + 0x18);
                    local_3c = *(float*)(puVar2 + 0xe) - *(float*)(iVar7 + 0x1c);
                    local_38 = *(float*)(puVar2 + 0x10) - *(float*)(iVar7 + 0x20);
                }
                else
                {
                    local_40 = *(float*)(puVar2 + 0xc) - *(float*)(*param_4 + 0x18);
                    local_3c = lbl_803E31FC;
                    local_38 = *(float*)(puVar2 + 0x10) - *(float*)(*param_4 + 0x20);
                }
                uVar3 = FUN_80017730();
                if (*(short**)(puVar2 + 0x18) == (short*)0x0)
                {
                    uVar1 = *puVar2;
                }
                else
                {
                    uVar1 = *puVar2 + **(short**)(puVar2 + 0x18);
                }
                uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
                if (0x8000 < (int)uVar3)
                {
                    uVar3 = uVar3 - 0xffff;
                }
                if ((int)uVar3 < -0x8000)
                {
                    uVar3 = uVar3 + 0xffff;
                }
                iVar7 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
                *(uint*)(iVar8 + 0x2dc) = *(uint*)(iVar8 + 0x2dc) & ~*(uint*)(&DAT_8031e840 + iVar7);
                if ((uVar10 & 4) != 0)
                {
                    *(uint*)(*(int*)(*param_4 + 0xb8) + 0x2dc) =
                        *(uint*)(*(int*)(*param_4 + 0xb8) + 0x2dc) & ~*(uint*)(&DAT_8031e860 + iVar7);
                }
            }
        }
    }
    FUN_80286878();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8014cbcc
 * EN v1.0 Address: 0x8014CBCC
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x8014CA48
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_8014cbcc(int param_1)
{
    int iVar1;
    double dVar2;

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    if (iVar1 == 0)
    {
        dVar2 = (double)lbl_803E31FC;
    }
    else if ((*(ushort*)(iVar1 + 0x2b2) == 0) || (*(ushort*)(iVar1 + 0x2b0) == 0))
    {
        dVar2 = (double)lbl_803E31FC;
    }
    else
    {
        dVar2 = (double)((float)((double)CONCAT44(0x43300000, (uint) * (ushort*)(iVar1 + 0x2b0)) -
                DOUBLE_803e3278) /
            (float)((double)CONCAT44(0x43300000, (uint) * (ushort*)(iVar1 + 0x2b2)) -
                DOUBLE_803e3278));
    }
    return dVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_8014ccac
 * EN v1.0 Address: 0x8014CCAC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8014CAE4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_8014ccac(int param_1, undefined4 param_2)
{
    *(undefined4*)(*(int*)&((GameObject*)param_1)->extra + 0x29c) = param_2;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ccb8
 * EN v1.0 Address: 0x8014CCB8
 * EN v1.0 Size: 756b
 * EN v1.1 Address: 0x8014CAF0
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8014ccb8(double param_1, double param_2, double param_3, int param_4, int param_5,
                  float* param_6, char param_7)
{
    float fVar1;
    double dVar2;
    double dVar3;
    double dVar4;
    float afStack_c8[3];
    float local_bc;
    float local_b8;
    float local_b4;
    float local_b0;
    float local_ac;
    float local_a8;
    float afStack_a4[13];
    undefined4 local_70;
    uint uStack_6c;

    dVar2 = SeekTwiceBeforeRead((float*)(param_5 + 0x2b8));
    if (dVar2 <= (double)lbl_803E31FC)
    {
        local_b0 = lbl_803E31FC;
        local_ac = lbl_803E31FC;
        local_a8 = lbl_803E31FC;
    }
    else
    {
        local_a8 = (float)((double)lbl_803E3200 / dVar2);
        local_b0 = *(float*)(param_5 + 0x2b8) * local_a8;
        local_ac = *(float*)(param_5 + 700) * local_a8;
        local_a8 = *(float*)(param_5 + 0x2c0) * local_a8;
        FUN_80247ef8(&local_b0, &local_b0);
    }
    dVar3 = SeekTwiceBeforeRead(param_6);
    if (dVar3 <= (double)lbl_803E31FC)
    {
        local_bc = lbl_803E31FC;
        local_b8 = lbl_803E31FC;
        local_b4 = lbl_803E31FC;
    }
    else
    {
        local_b4 = (float)((double)lbl_803E3200 / dVar3);
        local_bc = *param_6 * local_b4;
        local_b8 = param_6[1] * local_b4;
        local_b4 = param_6[2] * local_b4;
    }
    FUN_80247fb0(&local_b0, &local_bc, afStack_c8);
    dVar4 = SeekTwiceBeforeRead(afStack_c8);
    if ((double)lbl_803E31FC < dVar4)
    {
        FUN_80247f90(&local_b0, &local_bc);
        dVar4 = (double)FUN_80292754();
        uStack_6c = ((uint)(byte)((param_3 < dVar4) << 2) << 0x1c) >> 0x1e ^ 0x80000000;
        local_70 = 0x43300000;
        if (ABS((double)(float)((double)CONCAT44(0x43300000, uStack_6c) - DOUBLE_803e3218)) !=
            (double)lbl_803E31FC)
        {
            fVar1 = lbl_803E3258;
            if ((double)lbl_803E31FC < dVar4)
            {
                fVar1 = lbl_803E3200;
            }
            FUN_80247944((double)(float)(param_3 * (double)fVar1), afStack_a4, afStack_c8);
            FUN_80247cd8(afStack_a4, &local_b0, &local_bc);
        }
    }
    dVar4 = (double)(float)(dVar3 * (double)lbl_803E3280);
    dVar3 = (double)(float)(dVar2 + param_2);
    if ((dVar4 <= dVar3) && (dVar3 = dVar4, dVar4 < (double)(float)(dVar2 - param_2)))
    {
        dVar3 = (double)(float)(dVar2 - param_2);
    }
    if (param_1 < dVar3)
    {
        dVar3 = param_1;
    }
    *(float*)(param_4 + 0x24) = (float)((double)local_bc * dVar3);
    *(float*)(param_4 + 0x28) = (float)((double)local_b8 * dVar3);
    *(float*)(param_4 + 0x2c) = (float)((double)local_b4 * dVar3);
    if ((param_7 != '\0') && (*(float*)(param_4 + 0x28) < lbl_803E31FC))
    {
        fVar1 = lbl_803E3264 + *(float*)(*(int*)(param_5 + 0x29c) + 0x10);
        if (*(float*)(param_4 + 0x10) < fVar1)
        {
            *(float*)(param_4 + 0x28) =
                *(float*)(param_4 + 0x28) *
                (lbl_803E3200 - (fVar1 - *(float*)(param_4 + 0x10)) / lbl_803E3264);
        }
    }
    return;
}


/* 8b "li r3, N; blr" returners. */
int Baddie_EnemygetExtraSize(void) { return 0x370; }
int enemy_getObjectTypeId(void) { return 0x14b; }

/* 12b 3-insn patterns. */
void fn_8014C66C(int* obj, int x) { *(int*)((char*)((int**)obj)[0xb8 / 4] + 0x29c) = x; }

/* Drift-recovery: add new fns with v1.0 names. */
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E2598;


#pragma scheduling off
#pragma peephole off
void fn_8014C5C0(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    *(s16*)((char*)state + 688) = 0;
}

void fn_8014C63C(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    *(void**)((char*)state + 668) = Obj_GetPlayerObject();
}

u8 fn_8014C4D8(int* obj)
{
    int* state;
    f32 val;
    if (obj == NULL) goto null_obj;
    state = ((GameObject*)obj)->extra;
    goto have_state;
null_obj:
    return 0;
have_state:
    if (state == NULL) goto null_state;
    val = *(f32*)((char*)state + 728);
    if (val != lbl_803E2574)
    {
        return (u8)((s32)(val / lbl_803E2598) + 1);
    }
    return 0;
null_state:
    return 0;
}


void fn_8014D08C(int obj, int p2, f32 mult, int a, int b, u8 c)
{
    extern f32 lbl_803E256C;
    extern f32 lbl_803E2570;
    extern f32 lbl_803E2574;
    void* sub;

    *(f32*)(p2 + 0x308) = lbl_803E256C / (lbl_803E2570 * mult);
    *(u8*)(p2 + 0x323) = c;
    ObjAnim_SetCurrentMove(obj, (u8)a, lbl_803E2574, b);
    sub = ((GameObject*)obj)->anim.hitReactState;
    if (sub != NULL)
    {
        ((ObjHitsPriorityState*)sub)->suppressOutgoingHits = 0;
    }
}

extern void playerTailFn_80026b3c(int* p1, int p2, int p3, void* p4);
extern void fn_8015983C(void);

void baddieAfterUpdateBonesCb(int obj, int* p2)
{
    int* state = ((GameObject*)obj)->extra;
    int v = *p2;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x7C8:
        playerTailFn_80026b3c(p2, v, ((BaddieAfterUpdateBonesCbState*)state)->unk36C, (void*)fn_8015983C);
        break;
    default:
        playerTailFn_80026b3c(p2, v, ((BaddieAfterUpdateBonesCbState*)state)->unk36C, NULL);
        break;
    }
}


void fn_8014C540(int* obj, int* p4, f32* p5, f32* p6)
{
    int* state;
    f32 fz;
    if (obj != NULL)
    {
        state = ((GameObject*)obj)->extra;
        if (state != NULL)
        {
            *p5 = (f32)(u32) * (u8*)((char*)state + 755) / lbl_803E257C;
            *p6 = (f32)(u32) * (u8*)((char*)state + 756);
            *p4 = *(u8*)((char*)state + 754);
            return;
        }
    }
    fz = lbl_803E2574;
    *p5 = fz;
    *p6 = fz;
    *p4 = 0;
}

f32 fn_8014C5D0(register int obj)
{
    register u16 a;
    register int* state;
    u16 b;
    state = ((GameObject*)obj)->extra;
    if (state == NULL) return lbl_803E2574;
    a = *(u16*)((char*)state + 690);
    if (a != 0)
    {
        b = *(u16*)((char*)state + 688);
        if (b != 0)
        {
            return (f32)(u32)
            b / (f32)(u32)
            a;
        }
    }
    return lbl_803E2574;
}


/* sidekickToy_accelerateTowardTargetXZ: xz-plane physics step toward a target. Computes the planar
 * distance to (tx,ty,tz), then nudges the obj's xz velocity (offsets 0x24,
 * 0x2c) by timeDelta * speedScale * unitDir, clamped at +/-maxVel, with an
 * optional drag pass. Returns the y-delta. */
f32 sidekickToy_accelerateTowardTargetXZ(int obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag)
{
    f32 dx = tx - ((GameObject*)obj)->anim.worldPosX;
    f32 dy = ty - ((GameObject*)obj)->anim.worldPosY;
    f32 dz = tz - ((GameObject*)obj)->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dz * dz);
    if (dist > accel)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + timeDelta * (speedScale * (dx /
            dist));
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + timeDelta * (speedScale * (dz /
            dist));
    }
    else if (dist > lbl_803E2574)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + timeDelta * (speedScale * (dx /
            accel));
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + timeDelta * (speedScale * (dz /
            accel));
    }
    if (((GameObject*)obj)->anim.velocityX < -maxVel)
    {
        ((GameObject*)obj)->anim.velocityX = -maxVel;
    }
    else if (((GameObject*)obj)->anim.velocityX > maxVel)
    {
        ((GameObject*)obj)->anim.velocityX = maxVel;
    }
    if (((GameObject*)obj)->anim.velocityZ < -maxVel)
    {
        ((GameObject*)obj)->anim.velocityZ = -maxVel;
    }
    else if (((GameObject*)obj)->anim.velocityZ > maxVel)
    {
        ((GameObject*)obj)->anim.velocityZ = maxVel;
    }
    if (lbl_803E2574 != drag)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * powfBitEstimate(drag, timeDelta);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

/* sidekickToy_accelerateTowardTarget3D: 3D physics step toward a target. Variant of sidekickToy_accelerateTowardTargetXZ that
 * uses the full 3D distance (xyz) instead of planar (xz), and also nudges
 * the y-axis velocity at obj+0x28. Returns the y-delta. */
f32 sidekickToy_accelerateTowardTarget3D(int obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale, f32 maxVel,
                                         f32 drag)
{
    f32 dx = tx - ((GameObject*)obj)->anim.worldPosX;
    f32 dy = ty - ((GameObject*)obj)->anim.worldPosY;
    f32 dz = tz - ((GameObject*)obj)->anim.worldPosZ;
    f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
    if (dist > accel)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + timeDelta * (speedScale * (dx /
            dist));
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + timeDelta * (speedScale * (dy /
            dist));
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + timeDelta * (speedScale * (dz /
            dist));
    }
    else if (dist > lbl_803E2574)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + timeDelta * (speedScale * (dx /
            accel));
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + timeDelta * (speedScale * (dy /
            accel));
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + timeDelta * (speedScale * (dz /
            accel));
    }
    if (((GameObject*)obj)->anim.velocityX < -maxVel)
    {
        ((GameObject*)obj)->anim.velocityX = -maxVel;
    }
    else if (((GameObject*)obj)->anim.velocityX > maxVel)
    {
        ((GameObject*)obj)->anim.velocityX = maxVel;
    }
    if (((GameObject*)obj)->anim.velocityY < -maxVel)
    {
        ((GameObject*)obj)->anim.velocityY = -maxVel;
    }
    else if (((GameObject*)obj)->anim.velocityY > maxVel)
    {
        ((GameObject*)obj)->anim.velocityY = maxVel;
    }
    if (((GameObject*)obj)->anim.velocityZ < -maxVel)
    {
        ((GameObject*)obj)->anim.velocityZ = -maxVel;
    }
    else if (((GameObject*)obj)->anim.velocityZ > maxVel)
    {
        ((GameObject*)obj)->anim.velocityZ = maxVel;
    }
    if (lbl_803E2574 != drag)
    {
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * powfBitEstimate(drag, timeDelta);
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * powfBitEstimate(drag, timeDelta);
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(drag, timeDelta);
    }
    return dy;
}

extern u8 baddieTargetFn_8014a150(int obj, u8* state, f32* pos, void* dataOffset);
extern u8 lbl_803DBC58;
extern f32 lbl_803E25DC;

/* sidekickToy_updateCurveTargetLatch: pre-curve probe + state-bit gate. If state's 0x2000 bit is
 * set, ask baddieTargetFn_8014a150 whether the target is locked on; on hit,
 * leave state[0x2dc] alone. Otherwise initialise the rom-curve walker with
 * (data, obj, lbl_803E25DC, &lbl_803DBC58, -1) and toggle
 * the 0x2000 bit based on the u8 result. */
void sidekickToy_updateCurveTargetLatch(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8* data = *(u8**)state;
    if ((*(u32*)(state + 0x2dc) & 0x2000) != 0)
    {
        if ((u8)baddieTargetFn_8014a150(obj, state, &((GameObject*)obj)->anim.worldPosX, data + 0x68) != 0)
        {
            return;
        }
    }
    if ((*gRomCurveInterface)->initCurve(*(u8**)state, (void*)obj, lbl_803E25DC,
                                         (int*)&lbl_803DBC58, -1) != 0)
    {
        *(u32*)(state + 0x2dc) &= ~0x2000LL;
    }
    else
    {
        *(u32*)(state + 0x2dc) = *(u32*)(state + 0x2dc) | 0x2000;
    }
}

typedef struct
{
    f32 x, y, z;
} TrickyVec3;

typedef struct
{
    short* obj;
    s16 dist;
} TrickyTargetRec;

extern f32 vec3f_distanceSquared(void* a, void* b);
extern int getAngle(f32 x, f32 z);
extern uint lbl_8031DBF0[];
extern uint lbl_8031DC10[];

/*
 * --INFO--
 *
 * Function: fn_8014C11C
 * EN v1.0 Address: 0x8014C11C
 * EN v1.0 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_8014C11C(short* obj, f32 radius, u8 flags, int max, TrickyTargetRec* out)
{
    int i;
    int n;
    int state;
    TrickyTargetRec* cur;
    short** arr;
    short ang;
    short* tgt;
    uint diff;
    int b2;
    int b4;
    f32 d2;
    int count;
    TrickyVec3 d;
    void* dp = &d;

    state = *(int*)(obj + 0x5c);
    count = 0;
    n = 0;
    if ((flags & 1) != 0)
    {
        tgt = (short*)ObjGroup_FindNearestObject(3, obj, &radius);
        out->obj = tgt;
        if (tgt != 0)
        {
            out->dist = radius;
            n = 1;
            if ((flags & 2) != 0)
            {
                if ((((TrickyState*)state)->controlFlags & 0x8000) != 0)
                {
                    d.x = *(f32*)(obj + 0xc) - *(f32*)(out->obj + 0xc);
                    d.y = lbl_803E2574;
                    d.z = *(f32*)(obj + 0x10) - *(f32*)(out->obj + 0x10);
                }
                else
                {
                    d.x = *(f32*)(obj + 0xc) - *(f32*)(out->obj + 0xc);
                    d.y = *(f32*)(obj + 0xe) - *(f32*)(out->obj + 0xe);
                    d.z = *(f32*)(obj + 0x10) - *(f32*)(out->obj + 0x10);
                }
                diff = (u16)getAngle(-d.x, -d.z);
                if (*(short**)(obj + 0x18) != 0)
                {
                    ang = (s16)(((GameObject*)obj)->anim.rotX + **(short**)(obj + 0x18));
                }
                else
                {
                    ang = ((GameObject*)obj)->anim.rotX;
                }
                diff = diff - ((int)ang & 0xffffU);
                if (0x8000 < (int)diff)
                {
                    diff = diff - 0xffff;
                }
                if ((int)diff < -0x8000)
                {
                    diff = diff + 0xffff;
                }
                ang = (short)((diff & 0xffff) >> 0xd);
                ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~lbl_8031DBF0[ang];
                if ((flags & 4) != 0)
                {
                    *(uint*)(*(int*)(out->obj + 0x5c) + 0x2dc) =
                        *(uint*)(*(int*)(out->obj + 0x5c) + 0x2dc) & ~lbl_8031DC10[ang];
                }
            }
        }
    }
    else
    {
        radius = (f32)(f64)
        radius * (f32)(f64)
        radius;
        arr = (short**)ObjGroup_GetObjects(3, &count);
        if (count != 0)
        {
            i = 0;
            cur = out;
            b2 = flags & 2;
            b4 = flags & 4;
            for (; i < count; i++)
            {
                d2 = vec3f_distanceSquared(obj + 0xc, arr[i] + 0xc);
                if ((d2 < radius) && (arr[i] != obj))
                {
                    cur->obj = arr[i];
                    cur->dist = sqrtf(d2);
                    if (b2 != 0)
                    {
                        if ((((TrickyState*)state)->controlFlags & 0x8000) != 0)
                        {
                            d.x = *(f32*)(obj + 0xc) - *(f32*)(cur->obj + 0xc);
                            d.y = lbl_803E2574;
                            d.z = *(f32*)(obj + 0x10) - *(f32*)(cur->obj + 0x10);
                        }
                        else
                        {
                            d.x = *(f32*)(obj + 0xc) - *(f32*)(cur->obj + 0xc);
                            d.y = *(f32*)(obj + 0xe) - *(f32*)(cur->obj + 0xe);
                            d.z = *(f32*)(obj + 0x10) - *(f32*)(cur->obj + 0x10);
                        }
                        diff = (u16)getAngle(-d.x, -d.z);
                        if (*(short**)(obj + 0x18) != 0)
                        {
                            ang = (s16)(((GameObject*)obj)->anim.rotX + **(short**)(obj + 0x18));
                        }
                        else
                        {
                            ang = ((GameObject*)obj)->anim.rotX;
                        }
                        diff = diff - ((int)ang & 0xffffU);
                        if (0x8000 < (int)diff)
                        {
                            diff = diff - 0xffff;
                        }
                        if ((int)diff < -0x8000)
                        {
                            diff = diff + 0xffff;
                        }
                        ang = (short)((diff & 0xffff) >> 0xd);
                        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~lbl_8031DBF0[ang];
                        if (b4 != 0)
                        {
                            *(uint*)(*(int*)(cur->obj + 0x5c) + 0x2dc) =
                                *(uint*)(*(int*)(cur->obj + 0x5c) + 0x2dc) & ~lbl_8031DC10[ang];
                        }
                    }
                    cur++;
                    n++;
                    if (n >= max)
                    {
                        i = count;
                    }
                }
            }
        }
    }
    return n;
}

extern int* getTrickyObject(void);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern void fn_80026C30(int* obj, int flag);
extern void baddieInstantiateWeapon(int* node, int* sub);
extern void fn_8014BC98(int* node, int* sub);
extern void fn_8014B878(int* node, int* sub);

int enemy_animEventCallback(int* node, int unused, ObjAnimUpdateState* animUpdate)
{
    char* sub = *(char**)&((GameObject*)node)->extra;
    s8* n29 = *(s8**)&((GameObject*)node)->anim.placementData;
    int i;
    int* obj;

    if (((GameObject*)node)->unkF4 != 0)
        return 0;
    ((TrickyState*)sub)->flags2DC |= 0x8000;
    memcpy(sub + 0x2c4, sub + 0x2b8, 0xc);
    memcpy(sub + 0x2b8, (char*)node + 0x24, 0xc);
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            obj = getTrickyObject();
            if (obj != NULL)
            {
                (*(void (*)(int*, int, int*))(*(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.dll) + 0x34)))(
                    obj, 1, node);
                ((TrickyState*)sub)->flags2DC |= 0x200000;
                *(int**)&((TrickyState*)sub)->actionTargetObj = obj;
            }
            break;
        case 4:
            obj = Obj_GetPlayerObject();
            if (obj != NULL)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x200000;
                *(int**)&((TrickyState*)sub)->actionTargetObj = obj;
            }
            break;
        case 2:
            if (((GameObject*)node)->anim.seqId == 0x7a6)
                *(u16*)(sub + 0x2b6) = 0x7a5;
            else
                *(u16*)(sub + 0x2b6) = 0x33;
            break;
        case 3:
            (*gObjectTriggerInterface)->setCamVars(0x49, 4, (int)node, 0x3c);
            break;
        case 6:
            if (*(int**)&((TrickyState*)sub)->unk36C != NULL)
                fn_80026C30(*(int**)&((TrickyState*)sub)->unk36C, 1);
            break;
        case 7:
            if (*(int**)&((TrickyState*)sub)->unk36C != NULL)
                fn_80026C30(*(int**)&((TrickyState*)sub)->unk36C, 0);
            break;
        }
    }
    baddieInstantiateWeapon(node, (int*)sub);
    if (((GameObject*)node)->seqIndex == -1)
    {
        ((TrickyState*)sub)->unk2E8 &= ~3;
        ObjHits_DisableObject(node);
        return 0;
    }
    if ((((TrickyState*)sub)->flags2DC & 0x1800) == 0)
    {
        fn_8014BC98(node, (int*)sub);
        fn_8014B878(node, (int*)sub);
    }
    if (n29[0x2e] != -1)
    {
        if ((((TrickyState*)sub)->flags2DC & 0x600) != 0)
        {
            if (animUpdate->sequenceSlot == ((GameObject*)node)->seqIndex)
                return 4;
        }
    }
    return 0;
}


extern f32 lbl_803E25B8;
extern f32 lbl_803E25EC;
extern f32 lbl_803E25F0;
extern f32 lbl_803E25F4;

extern int playerIsDisguised(int* p);
extern void baddieFn_8014a304(int* a, int* s, f32 v);
extern f32 lbl_803E25D8;

void fn_8014B878(int* arg1, int* sub)
{
    int* player;
    int* tricky;
    int* target;
    int* camTarget;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    target = *(int**)&((TrickyState*)sub)->actionTargetObj;
    if (target != NULL && (((TrickyState*)sub)->controlFlags & 0x10000) == 0 &&
        (target != player || (((GameObject*)player)->objectFlags & 0x1000) == 0))
    {
        ((TrickyState*)sub)->flags2DC &= 0xff7fffff;
        camTarget = (int*)(*gCameraInterface)->getOverrideTarget();
        if (camTarget == arg1)
        {
            ((TrickyState*)sub)->flags2DC |= 0x800200;
        }
        {
            u16 dist = ((TrickyState*)sub)->unk2A4;
            u16 near = (u16)(int)((TrickyState*)sub)->waterLevel;
            if (dist < near)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400;
                ((TrickyState*)sub)->flags2DC &= 0xfffffdff;
            }
            else
            {
                f32 midf = ((BaddieState*)sub)->unk2A8;
                u16 mid = (u16)(int)midf;
                if (dist < mid)
                {
                    ((TrickyState*)sub)->flags2DC |= 0x200;
                    ((TrickyState*)sub)->flags2DC &= 0xfffffbff;
                }
                else
                {
                    u16 far = (u16)(int)(lbl_803E25D8 * midf);
                    if (dist > far)
                    {
                        ((TrickyState*)sub)->flags2DC &= 0xdffff9ff;
                    }
                }
            }
        }
    }
    else
    {
        ((TrickyState*)sub)->flags2DC &= 0xff7ff9ff;
        if ((((TrickyState*)sub)->controlFlags & 0x10000) != 0 ||
            (*(int**)&((TrickyState*)sub)->actionTargetObj == player && (((GameObject*)player)->objectFlags & 0x1000) !=
                0))
        {
            ((TrickyState*)sub)->flags2DC &= 0xdfffffff;
        }
    }
    ((TrickyState*)sub)->flags2DC &= 0xf890fff7;
    if (tricky != NULL)
    {
        u8 r = (*(u8(**)(int*))(*(int*)*(int*)((char*)tricky + 0x68) + 0x40))(tricky);
        if ((u8)r != 0) ((TrickyState*)sub)->flags2DC |= 0x200000;
    }
    if (*(int**)&((TrickyState*)sub)->actionTargetObj == player)
    {
        if (playerIsDisguised(player) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 8;
            if ((((TrickyState*)sub)->controlFlags & 0x2000) != 0)
            {
                ((TrickyState*)sub)->flags2DC &= 0xff7ff9ff;
            }
        }
    }
    if ((((TrickyState*)sub)->flags2DC & 0x20000600) != 0)
    {
        if ((((TrickyState*)sub)->controlFlags & 0x1000) != 0)
        {
            u8 r = baddieTargetFn_8014a150((int)arg1, (u8*)sub, (f32*)((char*)arg1 + 0x18),
                                           (void*)(*(char**)&((TrickyState*)sub)->actionTargetObj + 0x18));
            if ((u8)r != 0) ((TrickyState*)sub)->flags2DC |= 0x1000000;
            if ((((TrickyState*)sub)->flags2DC & 0x1000000) == 0)
            {
                ((TrickyState*)sub)->flags2DC &= 0xdfffffff;
            }
        }
        else
        {
            ((TrickyState*)sub)->flags2DC |= 0x1000000;
        }
        {
            u16 mode = ((TrickyState*)sub)->unk2A0;
            if (mode < 2 || mode > 5)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400000;
            }
            else if ((((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
            {
                ((TrickyState*)sub)->flags2DC |= 0x2000000;
            }
        }
        if ((((TrickyState*)sub)->controlFlags & 0x4000) == 0)
        {
            f32* t = (f32*)*(int**)&((TrickyState*)sub)->actionTargetObj;
            f32 mag = sqrtf(t[11] * t[11] + (t[9] * t[9] + t[10] * t[10]));
            if (mag > lbl_803E25D4) ((TrickyState*)sub)->flags2DC |= 0x4000000;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x600) != 0 &&
            (((TrickyState*)sub)->flags2DC & 0x6800000) != 0 &&
            (((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 0x20000000;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x20000000) != 0)
        {
            if ((((TrickyState*)sub)->controlFlags & 0x40) != 0)
            {
                baddieFn_8014a304(arg1, sub, ((TrickyState*)sub)->waterLevel);
            }
            else
            {
                ((TrickyState*)sub)->flags2DC |= 0xf0000;
            }
        }
    }
    if (((BaddieState*)sub)->hitCounter == 0)
    {
        ((TrickyState*)sub)->flags2DC |= 0x800;
    }
}

extern f32 PSVECMag(f32 * v);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * c);
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern f32 fn_80291FF4(f32 v);
extern void PSMTXRotAxisRad(void* mtx, f32* axis, f32 angle);
extern void PSMTXMultVecSR(void* mtx, f32* src, f32* dst);
extern f32 lbl_803E25C4;
extern f32 lbl_803E25E8;

void fn_8014C678(int* obj1, int* obj2, f32* vec3, u8 flag, f32 fa, f32 fb, f32 fc)
{
    f32 mag1, mag2, magcross, finalScale;
    f32 stk_8[3];
    f32 stk_14[3];
    f32 stk_20[3];
    f32 stk_2c[12];

    mag1 = PSVECMag((f32*)((char*)obj2 + 0x2b8));
    if (mag1 > lbl_803E2574)
    {
        f32 inv = lbl_803E256C / mag1;
        stk_20[0] = ((f32*)obj2)[174] * inv;
        stk_20[1] = ((f32*)obj2)[175] * inv;
        stk_20[2] = ((f32*)obj2)[176] * inv;
        PSVECNormalize(stk_20, stk_20);
    }
    else
    {
        stk_20[0] = lbl_803E2574;
        stk_20[1] = lbl_803E2574;
        stk_20[2] = lbl_803E2574;
    }

    mag2 = PSVECMag(vec3);
    if (mag2 > lbl_803E2574)
    {
        f32 inv = lbl_803E256C / mag2;
        stk_14[0] = vec3[0] * inv;
        stk_14[1] = vec3[1] * inv;
        stk_14[2] = vec3[2] * inv;
    }
    else
    {
        stk_14[0] = lbl_803E2574;
        stk_14[1] = lbl_803E2574;
        stk_14[2] = lbl_803E2574;
    }

    PSVECCrossProduct(stk_20, stk_14, stk_8);
    magcross = PSVECMag(stk_8);
    if (magcross > lbl_803E2574)
    {
        f32 angle;
        int gt;
        angle = fn_80291FF4(PSVECDotProduct(stk_20, stk_14));
        gt = (angle > fc);
        if ((f32)__fabs((f32)gt) != lbl_803E2574)
        {
            f32 rot = fc * ((angle > lbl_803E2574) ? lbl_803E256C : lbl_803E25C4);
            PSMTXRotAxisRad(stk_2c, stk_8, rot);
            PSMTXMultVecSR(stk_2c, stk_20, stk_14);
        }
    }

    finalScale = mag2 * lbl_803E25E8;
    {
        f32 cap_high = mag1 + fb;
        if (finalScale > cap_high)
        {
            finalScale = cap_high;
        }
        else
        {
            f32 cap_low = mag1 - fb;
            if (finalScale < cap_low) finalScale = cap_low;
        }
        if (finalScale > fa) finalScale = fa;
    }

    *(f32*)((char*)obj1 + 0x24) = stk_14[0] * finalScale;
    *(f32*)((char*)obj1 + 0x28) = stk_14[1] * finalScale;
    *(f32*)((char*)obj1 + 0x2c) = stk_14[2] * finalScale;

    if ((u8)flag != 0)
    {
        f32 y = *(f32*)((char*)obj1 + 0x28);
        if (y < lbl_803E2574)
        {
            f32 floor_height = *(f32*)((char*)obj1 + 0x10);
            int* target = *(int**)((char*)obj2 + 0x29c);
            f32 ground = lbl_803E25D0 + *(f32*)((char*)target + 0x10);
            if (floor_height < ground)
            {
                f32 t = (ground - floor_height) / lbl_803E25D0;
                *(f32*)((char*)obj1 + 0x28) = y * (lbl_803E256C - t);
            }
        }
    }
}

void fn_8014CD1C(int* node, int* sub, u16 p3, u8 p5, f32 fa, f32 fb)
{
    f32 dt;
    int angle;
    s32 delta;
    f32 delta_f;
    s16 newVal;

    dt = timeDelta / (f32)(u32)
    p3;
    if (dt > lbl_803E256C) dt = lbl_803E256C;

    angle = getAngle(-((TrickyState*)sub)->unk2B8, -((TrickyState*)sub)->unk2C0);
    delta = (u16)angle - (u16) * (s16*)node;
    delta_f = (f32)delta;
    if (delta_f > lbl_803E25B8) delta_f = lbl_803E25EC + delta_f;
    if (delta_f < lbl_803E25F4) delta_f = lbl_803E25F0 + delta_f;
    delta_f *= dt;
    newVal = (s16)(*(s16*)node + (s32)delta_f);
    *(s16*)node = newVal;

    if (fa != lbl_803E2574)
    {
        if ((u8)p5 != 0)
        {
            ((GameObject*)node)->anim.rotZ = (s16)(((GameObject*)node)->anim.rotZ + (s32)(fa * (delta_f * dt)));
        }
        else
        {
            s32 step = (s32)(oneOverTimeDelta * (delta_f * fa));
            ((GameObject*)node)->anim.rotZ = (s16)step;
            {
                s16 v = ((GameObject*)node)->anim.rotZ;
                if (v > 0x2000) ((GameObject*)node)->anim.rotZ = 0x2000;
                else if (v < -0x2000) ((GameObject*)node)->anim.rotZ = -0x2000;
            }
        }
    }

    if (lbl_803E2574 != fb)
    {
        f32 dz2 = ((TrickyState*)sub)->unk2C0 * ((TrickyState*)sub)->unk2C0;
        f32 dx2 = ((TrickyState*)sub)->unk2B8 * ((TrickyState*)sub)->unk2B8;
        f32 hyp = sqrtf(dz2 + dx2);
        int angle2 = getAngle(((TrickyState*)sub)->unk2BC * fb, hyp);
        s32 d2 = (u16)angle2 - (u16)((GameObject*)node)->anim.rotY;
        f32 d2f = (f32)d2;
        s16 newVal2;
        if (d2f > lbl_803E25B8) d2f = lbl_803E25EC + d2f;
        if (d2f < lbl_803E25F4) d2f = lbl_803E25F0 + d2f;
        newVal2 = (s16)(((GameObject*)node)->anim.rotY + (s32)(d2f * dt));
        ((GameObject*)node)->anim.rotY = newVal2;
    }
}

void fn_8014BC98(int* node, int* sub)
{
    int* target = *(int**)&((TrickyState*)sub)->actionTargetObj;
    if (target != NULL)
    {
        volatile f32 d[3];
        int angle;
        int raw;
        s32 delta;
        f32 dist;
        u16 d16;

        if ((((TrickyState*)sub)->controlFlags & 0x8000) != 0)
        {
            d[0] = ((GameObject*)node)->anim.worldPosX - *(f32*)((char*)target + 0x18);
            d[1] = lbl_803E2574;
            d[2] = ((GameObject*)node)->anim.worldPosZ - *(f32*)((char*)target + 0x20);
        }
        else
        {
            d[0] = ((GameObject*)node)->anim.worldPosX - *(f32*)((char*)target + 0x18);
            d[1] = ((GameObject*)node)->anim.worldPosY - *(f32*)((char*)target + 0x1c);
            d[2] = ((GameObject*)node)->anim.worldPosZ - *(f32*)((char*)target + 0x20);
        }
        angle = getAngle(-d[0], -d[2]);
        if (*(int**)&((GameObject*)node)->anim.parent != NULL)
        {
            raw = (s16)(*(s16*)node + **(s16**)&((GameObject*)node)->anim.parent);
        }
        else
        {
            raw = *(s16*)node;
        }
        delta = (u16)angle - (u16)(s16)
        raw;
        if (delta > 0x8000) delta -= 0xFFFF;
        if (delta < -0x8000) delta += 0xFFFF;
        d16 = (u16)delta;
        ((TrickyState*)sub)->unk2A2 = d16;
        ((TrickyState*)sub)->unk2A0 = d16 >> 13;

        dist = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
        *(s16*)&((TrickyState*)sub)->unk2A4 = (s16)(s32)
        dist;

        {
            int* t = *(int**)&((TrickyState*)sub)->actionTargetObj;
            *(s16*)&((TrickyState*)sub)->unk2A6 = (s16)(s32)(
                *(f32*)((char*)t + 0x1c) - ((GameObject*)node)->anim.worldPosY);
        }
    }
}

void fn_8014CF7C(int* node, int p2, u16 p3, int p4, f32 fa, f32 fb)
{
    s32 delta;
    f32 dt;
    s16 newVal;
    f32 t0 = *(f32*)((char*)node + 0xc) - fa;
    f32 t1 = *(f32*)((char*)node + 0x14) - fb;
    delta = getAngle(t0, t1);
    delta = (s16)(delta - (u16) * (s16*)node);
    if (delta > 0x8000) delta = (s16)(delta - 0xFFFF);
    if ((s16)delta < -0x8000) delta = (s16)(delta + 0xFFFF);
    delta += p4;
    dt = timeDelta / (f32)(u32)
    p3;
    if (dt > lbl_803E256C) dt = lbl_803E256C;
    newVal = (s16)(*(s16*)(int)node + (s32)((f32)(s16)delta * dt));
    *(s16*)node = newVal;
}
