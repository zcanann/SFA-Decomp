/*
 * DLL 0xC9 - the generic enemy/baddie controller. It runs several romlist
 * enemy types, including GCRobotPatrol ("GCRobotPatr[ol]"), the floating
 * patrol robot of CloudRunner Fortress (placed in fortress.romlist).
 * GCRobotPatrol carries the GCRobotLight scanning beam (DLL 0x150,
 * dll_0150_gcrobotlightbea.c) as childObjs[0] and reads that child's
 * "player caught in the beam" hit flag to react - the sharp-claw disguise
 * fools the beam. ("GC" = GameCube; see the dll_0150 header.)
 */
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_00CA_mediumbasket.h"
#include "main/dll/tricky_state.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/enemy_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/projswitch.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"

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

extern undefined4 ABS();
extern double FUN_80017714();
extern uint FUN_80017730();
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

extern f32 lbl_803E2598;
extern void playerTailFn_80026b3c(int* p1, int p2, int p3, void* p4);
extern void fn_8015983C(void);
extern u8 baddieTargetFn_8014a150(int obj, u8* state, f32* pos, void* dataOffset);
extern f32 lbl_803E25DC;
extern int getAngle(f32 x, f32 z);
extern uint lbl_8031DBF0[];
extern uint lbl_8031DC10[];
extern f32 lbl_803E25B8;
extern f32 lbl_803E25EC;
extern f32 lbl_803E25F0;
extern f32 lbl_803E25F4;
extern int playerIsDisguised(int* p);
extern void baddieFn_8014a304(int* a, int* s, f32 v);
extern f32 lbl_803E25D8;
extern f32 PSVECMag(f32 * v);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * c);
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern f32 fn_80291FF4(f32 v);
extern void PSMTXRotAxisRad(void* mtx, f32* axis, f32 angle);
extern void PSMTXMultVecSR(void* mtx, f32* src, f32* dst);
extern f32 lbl_803E25C4;
extern f32 lbl_803E25E8;
extern undefined4 FUN_800305f8();
extern uint ObjGroup_ContainsObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 fn_80154C24();
extern void rachnopInit(undefined4 param_1, int param_2);
extern void baddieInit_80156188(undefined4 param_1, int param_2);
extern void wbInit(undefined4 param_1, int param_2);
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E324C;
extern f32 lbl_803E3284;
extern f32 lbl_803E3288;
extern f32 lbl_803E328C;
extern void* lbl_803DDA50;
extern f32 lbl_803E25F8;
extern f32 lbl_803E25FC;
extern void objRenderFn_8003b8f4(f32 f);
extern int objCreateLight(int a, int b);
extern void objParticleFn_80099d84(int* obj, f32 f, int kind, f32 scale, int light);
extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int id);
extern int modelLightStruct_getActiveState(int light);
extern void ModelLightStruct_free(int light);
extern void mm_free(int p);
extern void smallbasket_stopLoopSfx(int obj, u8* state);
extern void Obj_FreeObject(int obj);
extern uint GameBit_Get(int bit);
extern int getCurUiDll(void);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int isInBounds(f32 x, f32 z);
extern int objIsFrozen(int obj);
extern void baddie_updateWhileFrozen(int obj, u8* state, int flag);
extern void hudFn_8011f38c(int a);
extern f32 lbl_803E2600;
extern void fn_80151954(int obj, u8* state);
extern void fn_801522E0(int obj, u8* state);
extern void fn_80152A94(int obj, u8* state);
extern void fn_80152EC0(int obj, u8* state);
extern void fn_801534D8(int obj, u8* state);
extern void fn_80153C90(int obj, u8* state);
extern void fn_801542AC(int obj, u8* state);
extern void mutatedEbaInit(int obj, u8* state);
extern void mediumbasket_initWhirlpoolState(int obj, u8* state);
extern void smallbasket_initVariantState(int obj, u8* state);
extern void smallbasket_initScaledVariantState(int obj, u8* state);
extern void fn_8014FF58(int obj, u8* state);
extern void smallbasket_initModelVariantState(int obj, u8* state);
extern void smallbasket_initTailModelState(int obj, u8* state);
extern void* memset(void* p, int c, int n);
extern f32 lbl_803DBC60;
extern f32 lbl_803DBC64;
extern f32 lbl_803DBC68;
extern u8 lbl_8031DBD8[];
extern u8 lbl_8031DBE4[];
extern f32 lbl_803E25B0;

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
                mediumbasket_enterWhirlpoolGroup((int)obj, (GroundBaddieState*)state);
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
                mediumbasket_enterWhirlpoolGroup((int)obj, (GroundBaddieState*)state);
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
            mediumbasket_leaveWhirlpoolGroup((int)obj, (GroundBaddieState*)state);
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
        vy = -(((TrickyState*)state)->unk300 * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
    v = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityX = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
    v = ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityY = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
    v = ((GameObject*)obj)->anim.velocityZ;
    ((GameObject*)obj)->anim.velocityZ = (v < lbl_803E25CC) ? lbl_803E25CC : ((v > lbl_803E25D0) ? lbl_803E25D0 : v);
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
            sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ),
            (ObjAnimComponent*)obj, &phase) != 0)
        {
            ((TrickyState*)state)->animPlaySpeed = phase;
        }
    }
    else if (mode == 3)
    {
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
        }
    }
    Tricky_applyFloorResponse(obj, state);
    if (((((TrickyState*)state)->controlFlags & 0x400000) != 0) || ((((TrickyState*)state)->flags2DC & 0x8100000) != 0))
    {
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
        }
    }
    else if ((((TrickyState*)state)->controlFlags & 0x20) != 0)
    {
        f32 newY = (((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY)
            - lbl_803E25D4 * (((TrickyState*)state)->unk300 * (timeDelta * timeDelta));
        if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
        {
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, newY - ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            ((GameObject*)obj)->anim.velocityY = vy;
        }
    }
    else if ((((TrickyState*)state)->unk2F1 & 0x80) == 0)
    {
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }
}

#pragma scheduling on
#pragma peephole on
void FUN_8014c78c(undefined4 param_1, undefined4 param_2, int param_3, int* param_4)
{
    extern double FUN_80293900();
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
                            local_40 = ((GameObject*)puVar2)->anim.worldPosX - *(float*)(iVar5 + 0x18);
                            local_3c = ((GameObject*)puVar2)->anim.worldPosY - *(float*)(iVar5 + 0x1c);
                            local_38 = ((GameObject*)puVar2)->anim.worldPosZ - *(float*)(iVar5 + 0x20);
                        }
                        else
                        {
                            local_40 = ((GameObject*)puVar2)->anim.worldPosX - *(float*)(*param_4 + 0x18);
                            local_3c = lbl_803E31FC;
                            local_38 = ((GameObject*)puVar2)->anim.worldPosZ - *(float*)(*param_4 + 0x20);
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
                    local_40 = ((GameObject*)puVar2)->anim.worldPosX - *(float*)(iVar7 + 0x18);
                    local_3c = ((GameObject*)puVar2)->anim.worldPosY - *(float*)(iVar7 + 0x1c);
                    local_38 = ((GameObject*)puVar2)->anim.worldPosZ - *(float*)(iVar7 + 0x20);
                }
                else
                {
                    local_40 = ((GameObject*)puVar2)->anim.worldPosX - *(float*)(*param_4 + 0x18);
                    local_3c = lbl_803E31FC;
                    local_38 = ((GameObject*)puVar2)->anim.worldPosZ - *(float*)(*param_4 + 0x20);
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

#pragma scheduling off
#pragma peephole off
void FUN_8014ccac(int param_1, undefined4 param_2)
{
    *(undefined4*)(*(int*)&((GameObject*)param_1)->extra + 0x29c) = param_2;
    return;
}

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

int Baddie_EnemygetExtraSize(void) { return 0x370; }
int enemy_getObjectTypeId(void) { return 0x14b; }

void fn_8014C66C(int* obj, int x) { *(int*)((char*)((int**)obj)[0xb8 / 4] + 0x29c) = x; }

#pragma scheduling off
#pragma peephole off
void fn_8014C5C0(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    *(s16*)((char*)state + 688) = 0;
}

void fn_8014C63C(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
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
    ObjHitsPriorityState* hitState;

    *(f32*)(p2 + 0x308) = lbl_803E256C / (lbl_803E2570 * mult);
    *(u8*)(p2 + 0x323) = c;
    ObjAnim_SetCurrentMove(obj, (u8)a, lbl_803E2574, b);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->suppressOutgoingHits = 0;
    }
}

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

/* sidekickToy_updateCurveTargetLatch: pre-curve probe + state-bit gate. If state's 0x2000 bit is
 * set, ask baddieTargetFn_8014a150 whether the target is locked on; on hit,
 * leave state[0x2dc] alone. Otherwise initialise the rom-curve walker with
 * (data, obj, lbl_803E25DC, &lbl_803DBC58, -1) and toggle
 * the 0x2000 bit based on the u8 result. */
void sidekickToy_updateCurveTargetLatch(int obj)
{
    extern u8 lbl_803DBC58;
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

int fn_8014C11C(short* obj, f32 radius, u8 flags, int max, TrickyTargetRec* out)
{
    extern f32 vec3f_distanceSquared(void* a, void* b);
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
                    d.x = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)out->obj)->anim.worldPosX;
                    d.y = lbl_803E2574;
                    d.z = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)out->obj)->anim.worldPosZ;
                }
                else
                {
                    d.x = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)out->obj)->anim.worldPosX;
                    d.y = ((GameObject*)obj)->anim.worldPosY - ((GameObject*)out->obj)->anim.worldPosY;
                    d.z = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)out->obj)->anim.worldPosZ;
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
                            d.x = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)cur->obj)->anim.worldPosX;
                            d.y = lbl_803E2574;
                            d.z = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)cur->obj)->anim.worldPosZ;
                        }
                        else
                        {
                            d.x = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)cur->obj)->anim.worldPosX;
                            d.y = ((GameObject*)obj)->anim.worldPosY - ((GameObject*)cur->obj)->anim.worldPosY;
                            d.z = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)cur->obj)->anim.worldPosZ;
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

int enemy_animEventCallback(int* node, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void fn_8014B878(int* node, int* sub);
    extern void fn_8014BC98(int* node, int* sub);
    extern void baddieInstantiateWeapon(int* node, int* sub);
    extern void* Obj_GetPlayerObject(void);
    extern int* getTrickyObject(void);
    char* sub = *(char**)&((GameObject*)node)->extra;
    s8* n29 = *(s8**)&((GameObject*)node)->anim.placementData;
    int i;
    int* obj;

    if (((GameObject*)node)->unkF4 != 0)
        return 0;
    ((TrickyState*)sub)->flags2DC |= 0x8000LL;
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
                ((TrickyState*)sub)->flags2DC |= 0x200000LL;
                *(int**)&((TrickyState*)sub)->actionTargetObj = obj;
            }
            break;
        case 4:
            obj = Obj_GetPlayerObject();
            if (obj != NULL)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x200000LL;
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
                ObjModelChain_SetEnabled(*(ObjModelChain**)&((TrickyState*)sub)->unk36C, 1);
            break;
        case 7:
            if (*(int**)&((TrickyState*)sub)->unk36C != NULL)
                ObjModelChain_SetEnabled(*(ObjModelChain**)&((TrickyState*)sub)->unk36C, 0);
            break;
        }
    }
    baddieInstantiateWeapon(node, (int*)sub);
    if (((GameObject*)node)->seqIndex == -1)
    {
        ((TrickyState*)sub)->unk2E8 &= ~3LL;
        ObjHits_DisableObject((u32)node);
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

void fn_8014B878(int* arg1, int* sub)
{
    extern void fn_8014B878(int* node, int* sub);
    extern void* Obj_GetPlayerObject(void);
    extern int* getTrickyObject(void);
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
        ((TrickyState*)sub)->flags2DC &= ~0x800000LL;
        camTarget = (int*)(*gCameraInterface)->getOverrideTarget();
        if (camTarget == arg1)
        {
            ((TrickyState*)sub)->flags2DC |= 0x800200LL;
        }
        {
            u16 dist = ((TrickyState*)sub)->unk2A4;
            u16 near = (u16)(int)((TrickyState*)sub)->waterLevel;
            if (dist < near)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400LL;
                ((TrickyState*)sub)->flags2DC &= ~0x200LL;
            }
            else
            {
                f32 midf = ((BaddieState*)sub)->unk2A8;
                u16 mid = (u16)(int)midf;
                if (dist < mid)
                {
                    ((TrickyState*)sub)->flags2DC |= 0x200LL;
                    ((TrickyState*)sub)->flags2DC &= ~0x400LL;
                }
                else
                {
                    u16 far = (u16)(int)(lbl_803E25D8 * midf);
                    if (dist > far)
                    {
                        ((TrickyState*)sub)->flags2DC &= ~0x20000600LL;
                    }
                }
            }
        }
    }
    else
    {
        ((TrickyState*)sub)->flags2DC &= ~0x800600LL;
        if ((((TrickyState*)sub)->controlFlags & 0x10000) != 0 ||
            (*(int**)&((TrickyState*)sub)->actionTargetObj == player && (((GameObject*)player)->objectFlags & 0x1000) !=
                0))
        {
            ((TrickyState*)sub)->flags2DC &= ~0x20000000LL;
        }
    }
    ((TrickyState*)sub)->flags2DC &= ~0x76f0008LL;
    if (tricky != NULL)
    {
        u8 r = (*(u8(**)(int*))(*(int*)*(int*)((char*)tricky + 0x68) + 0x40))(tricky);
        if ((u8)r != 0) ((TrickyState*)sub)->flags2DC |= 0x200000LL;
    }
    if (*(int**)&((TrickyState*)sub)->actionTargetObj == player)
    {
        if (playerIsDisguised(player) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 8LL;
            if ((((TrickyState*)sub)->controlFlags & 0x2000) != 0)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x800600LL;
            }
        }
    }
    if ((((TrickyState*)sub)->flags2DC & 0x20000600) != 0)
    {
        if ((((TrickyState*)sub)->controlFlags & 0x1000) != 0)
        {
            u8 r = baddieTargetFn_8014a150((int)arg1, (u8*)sub, (f32*)((char*)arg1 + 0x18),
                                           (void*)(*(char**)&((TrickyState*)sub)->actionTargetObj + 0x18));
            if ((u8)r != 0) ((TrickyState*)sub)->flags2DC |= 0x1000000LL;
            if ((((TrickyState*)sub)->flags2DC & 0x1000000) == 0)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x20000000LL;
            }
        }
        else
        {
            ((TrickyState*)sub)->flags2DC |= 0x1000000LL;
        }
        {
            u16 mode = ((TrickyState*)sub)->unk2A0;
            if (mode < 2 || mode > 5)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400000LL;
            }
            else if ((((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
            {
                ((TrickyState*)sub)->flags2DC |= 0x2000000LL;
            }
        }
        if ((((TrickyState*)sub)->controlFlags & 0x4000) == 0)
        {
            f32* t = (f32*)*(int**)&((TrickyState*)sub)->actionTargetObj;
            f32 mag = sqrtf(t[11] * t[11] + (t[9] * t[9] + t[10] * t[10]));
            if (mag > lbl_803E25D4) ((TrickyState*)sub)->flags2DC |= 0x4000000LL;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x600) != 0 &&
            (((TrickyState*)sub)->flags2DC & 0x6800000) != 0 &&
            (((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 0x20000000LL;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x20000000) != 0)
        {
            if ((((TrickyState*)sub)->controlFlags & 0x40) != 0)
            {
                baddieFn_8014a304(arg1, sub, ((TrickyState*)sub)->waterLevel);
            }
            else
            {
                ((TrickyState*)sub)->flags2DC |= 0xf0000LL;
            }
        }
    }
    if (((BaddieState*)sub)->hitCounter == 0)
    {
        ((TrickyState*)sub)->flags2DC |= 0x800LL;
    }
}

void fn_8014C678(int* obj1, int* obj2, f32* vec3, u8 flag, f32 fa, f32 fb, f32 fc)
{
    f32 mag1, mag2, magcross, finalScale;
    f32 stk_20[3];
    f32 stk_14[3];
    f32 stk_8[3];
    f32 stk_2c[12];

    mag1 = PSVECMag((f32*)((int)obj2 + 0x2b8));
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
        if (__fabs((f32)gt) != lbl_803E2574)
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
    extern void fn_8014BC98(int* node, int* sub);
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

typedef struct EnemyPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x28 - 0x1C];
    s8 unk28;
    u8 pad29[0x2A - 0x29];
    s8 unk2A;
    u8 pad2B[0x2C - 0x2B];
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x34 - 0x2F];
    u16 unk34;
    u8 pad36[0x38 - 0x36];
} EnemyPlacement;

void FUN_8014d164(double param_1, double param_2, ushort* param_3, int param_4, uint param_5,
                  char param_6)
{
    extern undefined4 FUN_80293900();
    uint uVar1;
    double dVar2;
    double dVar3;
    double dVar4;
    undefined8 local_50;
    undefined8 local_48;

    dVar4 = (double)(lbl_803DC074 /
        (float)((double)CONCAT44(0x43300000, param_5 & 0xffff) - DOUBLE_803e3278));
    if ((double)lbl_803E3200 < dVar4)
    {
        dVar4 = (double)lbl_803E3200;
    }
    uVar1 = FUN_80017730();
    local_50 = (double)CONCAT44(0x43300000, (uVar1 & 0xffff) - (uint) * param_3 ^ 0x80000000);
    dVar2 = (double)(float)(local_50 - DOUBLE_803e3218);
    if ((double)lbl_803E324C < dVar2)
    {
        dVar2 = (double)(float)((double)lbl_803E3284 + dVar2);
    }
    if (dVar2 < (double)lbl_803E328C)
    {
        dVar2 = (double)(float)((double)lbl_803E3288 + dVar2);
    }
    dVar3 = (double)(float)(dVar2 * dVar4);
    *param_3 = *param_3 + (short)(int)(dVar2 * dVar4);
    if (param_1 != (double)lbl_803E31FC)
    {
        if (param_6 == '\0')
        {
            param_3[2] = (ushort)(int)(lbl_803DC078 * (float)(dVar3 * param_1));
            if ((short)param_3[2] < 0x2001)
            {
                if ((short)param_3[2] < -0x2000)
                {
                    param_3[2] = 0xe000;
                }
            }
            else
            {
                param_3[2] = 0x2000;
            }
        }
        else
        {
            param_3[2] = param_3[2] + (short)(int)(param_1 * (double)(float)(dVar3 * dVar4));
        }
    }
    if ((double)lbl_803E31FC != param_2)
    {
        FUN_80293900((double)(*(float*)(param_4 + 0x2c0) * *(float*)(param_4 + 0x2c0) +
            *(float*)(param_4 + 0x2b8) * *(float*)(param_4 + 0x2b8)));
        uVar1 = FUN_80017730();
        local_48 = (double)CONCAT44(0x43300000, (uVar1 & 0xffff) - (uint)param_3[1] ^ 0x80000000);
        dVar2 = (double)(float)(local_48 - DOUBLE_803e3218);
        if ((double)lbl_803E324C < dVar2)
        {
            dVar2 = (double)(float)((double)lbl_803E3284 + dVar2);
        }
        if (dVar2 < (double)lbl_803E328C)
        {
            dVar2 = (double)(float)((double)lbl_803E3288 + dVar2);
        }
        param_3[1] = param_3[1] + (short)(int)(dVar2 * dVar4);
    }
    return;
}

void FUN_8014d3d0(short* param_1, undefined4 param_2, uint param_3, short param_4)
{
    float fVar1;
    short sVar2;
    int iVar3;

    iVar3 = FUN_80017730();
    sVar2 = (short)iVar3 - *param_1;
    if (0x8000 < sVar2)
    {
        sVar2 = sVar2 + 1;
    }
    if (sVar2 < -0x8000)
    {
        sVar2 = sVar2 + -1;
    }
    fVar1 = lbl_803DC074 / (float)((double)CONCAT44(0x43300000, param_3 & 0xffff) - DOUBLE_803e3278);
    if (lbl_803E3200 < fVar1)
    {
        fVar1 = lbl_803E3200;
    }
    *param_1 = *param_1 +
        (short)(int)((float)((double)CONCAT44(0x43300000,
                                              (int)(short)(sVar2 + param_4) ^ 0x80000000) -
            DOUBLE_803e3218) * fVar1);
    return;
}

void FUN_8014d4c8(double param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5
                  , undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
                  uint param_11, uint param_12, undefined4 param_13, undefined4 param_14,
                  undefined4 param_15, undefined4 param_16)
{
    ObjHitsPriorityState* hitState;

    if ((double)lbl_803E31FC == param_1)
    {
        *(float*)(param_10 + 0x308) = lbl_803E3208;
    }
    else
    {
        param_2 = (double)lbl_803E3200;
        *(float*)(param_10 + 0x308) =
            (float)(param_2 / (double)(float)((double)lbl_803E3204 * param_1));
    }
    *(char*)(param_10 + 0x323) = (char)param_13;
    FUN_800305f8((double)lbl_803E31FC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 param_9, param_11 & 0xff, param_12, param_12, param_13, param_14, param_15, param_16);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    if (hitState != NULL)
    {
        hitState->suppressOutgoingHits = 0;
    }
    return;
}

void enemy_release(void)
{
    if (lbl_803DDA50 != NULL)
    {
        Resource_Release(lbl_803DDA50);
        lbl_803DDA50 = NULL;
    }
}

void enemy_initialise(void) { if (lbl_803DDA50 == NULL) lbl_803DDA50 = Resource_Acquire(0x5a, 1); }

void enemy_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E256C);
            {
                u32 flags = *(u32*)&((EnemyState*)state)->unk2E8;
                if ((flags & 3) != 0)
                {
                    if ((flags & 1) != 0)
                    {
                        *(u32*)&((EnemyState*)state)->unk2E8 = flags & ~1LL;
                        *(u32*)&((EnemyState*)state)->unk2E8 = *(u32*)&((EnemyState*)state)->unk2E8 | 2;
                    }
                    if (*(void**)&((EnemyState*)state)->modelLight == NULL)
                    {
                        ((EnemyState*)state)->modelLight = objCreateLight(0, 1);
                    }
                    objParticleFn_80099d84(obj, lbl_803E256C, 3, ((EnemyState*)state)->particleScale,
                                           ((EnemyState*)state)->modelLight);
                }
            }
            if ((*(u32*)&((EnemyState*)state)->unk2E8 & 4) != 0)
            {
                if (*(void**)&((EnemyState*)state)->modelLight == NULL)
                {
                    ((EnemyState*)state)->modelLight = objCreateLight(0, 1);
                }
                objParticleFn_80099d84(obj, lbl_803E256C, 4, ((EnemyState*)state)->particleScale,
                                       ((EnemyState*)state)->modelLight);
            }
            if ((*(u32*)&((EnemyState*)state)->unk2E8 & 0x40) != 0)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
                objParticleFn_80099d84(obj, lbl_803E256C, 5, ((EnemyState*)state)->particleScale, 0);
            }
            if ((*(u32*)&((EnemyState*)state)->unk2E8 & 0x80) != 0)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
                objParticleFn_80099d84(obj, lbl_803E25F8, 6, ((EnemyState*)state)->particleScale, 0);
            }
            if ((*(u32*)&((EnemyState*)state)->unk2E8 & 0x100) != 0)
            {
                objParticleFn_80099d84(obj, lbl_803E25FC, 7, ((EnemyState*)state)->particleScale, 0);
            }
            break;
        }
    }
}

void enemy_hitDetect(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* childHitState;

    if (*(void**)&((EnemyState*)state)->modelLight != NULL && modelLightStruct_getActiveState(
        ((EnemyState*)state)->modelLight) == 0)
    {
        ModelLightStruct_free(((EnemyState*)state)->modelLight);
        ((EnemyState*)state)->modelLight = 0;
    }
    ((EnemyState*)state)->lastHitObject =
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (((GameObject*)obj)->childObjs[0] != NULL && *(void**)(*(int*)&((GameObject*)obj)->childObjs[0] + 0x54) != NULL
        && (childHitState = *(ObjHitsPriorityState**)(*(int*)&((GameObject*)obj)->childObjs[0] + 0x54))->lastHitObject
            != 0)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 1;
    }
    if (*(void**)&((EnemyState*)state)->tailSimHandle != NULL)
    {
        ObjModelChain_AdvancePhase((ObjModelChain*)((EnemyState*)state)->tailSimHandle);
    }
}

void enemy_free(int obj, int flag)
{
    u8* child;
    int i;
    int n;
    u8* state;

    state = ((GameObject*)obj)->extra;

    if (*(void**)&((EnemyState*)state)->tailSimHandle != NULL)
    {
        ObjModelChain_Free((ObjModelChain*)((EnemyState*)state)->tailSimHandle);
    }
    if (*(void**)&((EnemyState*)state)->modelLight != NULL)
    {
        ModelLightStruct_free(((EnemyState*)state)->modelLight);
        ((EnemyState*)state)->modelLight = 0;
    }
    if (*(void**)state != NULL)
    {
        mm_free(*(int*)state);
        *(int*)state = 0;
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x7c8:
        smallbasket_stopLoopSfx(obj, state);
        break;
    case 0x851:
        if ((int)ObjGroup_ContainsObject(obj, 0x50) != 0)
        {
            ObjGroup_RemoveObject(obj, 0x50);
        }
        break;
    }
    n = ((GameObject*)obj)->childCount;
    for (i = 0; i < n; i++)
    {
        child = ((GameObject*)obj)->childObjs[0];
        if (child != NULL)
        {
            ObjLink_DetachChild(obj, child);
            if (flag == 0 || (*(u16*)(child + 0xb0) & 0x10) == 0)
            {
                Obj_FreeObject((int)child);
            }
        }
    }
    (*gExpgfxInterface)->freeSource(obj);
    ObjGroup_RemoveObject(obj, 3);
}

void enemy_update(int obj)
{
    extern void objAnimFn_8014a9f0(int obj, u8* state);
    extern void fn_8014B878(int obj, u8* state);
    extern void fn_8014BC98(int obj, u8* state);
    extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
    extern void baddieInstantiateWeapon(int obj, u8* state);
    extern u8* Obj_GetPlayerObject(void);
    extern u8* getTrickyObject(void);
    u8* player;
    u8* state;
    u8* setup;
    u8* tricky;
    u32 flags;
    u8* s2;
    f32 fz;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();
    if (getCurUiDll() == 4)
    {
        return;
    }
    if ((((EnemyState*)state)->flags2E4 & 0x8000006) != 0)
    {
        if (objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                ((GameObject*)obj)->anim.localPosZ) == -1)
        {
            return;
        }
    }
    else
    {
        if (isInBounds(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0)
        {
            return;
        }
    }
    if (objIsFrozen(obj) != 0)
    {
        baddie_updateWhileFrozen(obj, state, 1);
        return;
    }
    if (((EnemyState*)state)->trackedObj == NULL)
    {
        ((EnemyState*)state)->trackedObj = Obj_GetPlayerObject();
    }
    else if ((*(u16*)(*(int*)&((EnemyState*)state)->trackedObj + 0xb0) & 0x40) != 0)
    {
        ((EnemyState*)state)->trackedObj = Obj_GetPlayerObject();
    }
    ((EnemyState*)state)->initialFlags = *(int*)&((EnemyState*)state)->controlFlags;
    baddieInstantiateWeapon(obj, state);
    flags = ((EnemyState*)state)->controlFlags;
    if ((flags & 1) != 0 && (flags & 2) == 0)
    {
        if (((EnemyPlacement*)setup)->unk2E == -1)
        {
            return;
        }
        if (setup != NULL && (setup[0x2b] & 8) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        }
        (*gObjectTriggerInterface)->runSequence(((EnemyPlacement*)setup)->unk2E, (void*)obj, -1);
        ((EnemyState*)state)->controlFlags |= 2;
        *(u32*)&((EnemyState*)state)->controlFlags = *(u32*)&((EnemyState*)state)->controlFlags & ~1LL;
        return;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((EnemyPlacement*)setup)->unk1A != -1)
        {
            if (GameBit_Get(((EnemyPlacement*)setup)->unk1A) == 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x800) != 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x1000) == 0)
            {
                return;
            }
            player = Obj_GetPlayerObject();
            if (((EnemyPlacement*)setup)->unk18 != -1)
            {
                if (GameBit_Get(((EnemyPlacement*)setup)->unk18) != 0)
                {
                    return;
                }
            }
            if (player != NULL)
            {
                if (vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(setup + 8)) > lbl_803E2600)
                {
                    enemy_init(obj, setup, 0);
                    ((EnemyState*)state)->controlFlags |= 0x1000;
                    *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else if (((EnemyPlacement*)setup)->unk18 != -1)
        {
            if (GameBit_Get(((EnemyPlacement*)setup)->unk18) != 0)
            {
                return;
            }
            if ((((EnemyState*)state)->controlFlags & 0x800) != 0)
            {
                return;
            }
            player = Obj_GetPlayerObject();
            if (player != NULL)
            {
                if (vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(setup + 8)) > lbl_803E2600)
                {
                    enemy_init(obj, setup, 0);
                    ((EnemyState*)state)->controlFlags |= 0x1000;
                    *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else
        {
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xFFFFFFFF)
            {
                return;
            }
            if (((EnemyPlacement*)setup)->unk2C == 0)
            {
                return;
            }
            if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
            {
                if ((((EnemyState*)state)->controlFlags & 0x800) == 0)
                {
                    player = Obj_GetPlayerObject();
                    if (player != NULL)
                    {
                        if (vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(setup + 8)) > lbl_803E2600)
                        {
                            enemy_init(obj, setup, 0);
                            ((EnemyState*)state)->controlFlags |= 0x1000;
                            *(u32*)&((EnemyState*)state)->initialFlags &= ~0x1000LL;
                        }
                        else
                        {
                            return;
                        }
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }
    }
    if ((((EnemyState*)state)->controlFlags & 0x8000) != 0)
    {
        hudFn_8011f38c(0);
        (*gPathControlInterface)->attachObject((void*)obj, state + 4);
        ((EnemyState*)state)->controlFlags &= ~0x8003LL;
        if ((((EnemyState*)state)->flags2E4 & 0x20000) != 0)
        {
            s2 = *(u8**)&((GameObject*)obj)->anim.placementData;
            ((GameObject*)obj)->anim.localPosX = ((EnemyPlacement*)s2)->unk8;
            ((GameObject*)obj)->anim.localPosY = ((EnemyPlacement*)s2)->unkC;
            ((GameObject*)obj)->anim.localPosZ = ((EnemyPlacement*)s2)->unk10;
            ((GameObject*)obj)->anim.rotZ = 0;
            ((GameObject*)obj)->anim.rotY = 0;
            *(s16*)obj = ((EnemyPlacement*)s2)->unk2A << 8;
            fz = lbl_803E2574;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
        }
    }
    if ((((EnemyState*)state)->flags2E4 & 0x80000) != 0)
    {
        if (tricky != NULL && GameBit_Get(0x9e) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        if (tricky != NULL && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
        {
            (**(void (**)(u8*, int, int, int))(*(int*)(*(int*)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    baddie_updateWhileFrozen(obj, state, 0);
    if ((((EnemyState*)state)->controlFlags & 0x1800) == 0)
    {
        fn_8014BC98(obj, state);
        fn_8014B878(obj, state);
    }
    objAnimFn_8014a9f0(obj, state);
}

void enemy_init(int obj, u8* setup, int flag)
{
    extern f32 lbl_803DBC58;
    extern void enemy_animEventCallback();
    u8* state = ((GameObject*)obj)->extra;
    f32 fz;

    ((GameObject*)obj)->unkF4 = 0;
    if (flag == 0)
    {
        if (*(s16*)(setup + 0x1a) != -1)
        {
            if (*(s16*)(setup + 0x18) != -1)
            {
                if (GameBit_Get(*(s16*)(setup + 0x18)) == 0)
                {
                    ((GameObject*)obj)->unkF4 = GameBit_Get(*(s16*)(setup + 0x1a)) == 0;
                }
            }
            else
            {
                ((GameObject*)obj)->unkF4 = GameBit_Get(*(s16*)(setup + 0x1a)) == 0;
            }
        }
        if (*(u32*)&((ObjPlacement*)setup)->mapId != 0xFFFFFFFF)
        {
            if (((GameObject*)obj)->unkF4 == 0)
            {
                if (*(s16*)(setup + 0x18) != -1)
                {
                    ((GameObject*)obj)->unkF4 = GameBit_Get(*(s16*)(setup + 0x18));
                }
                if (((GameObject*)obj)->unkF4 == 0)
                {
                    if (*(s16*)(setup + 0x2c) != 0)
                    {
                        if ((*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) == 0)
                        {
                            ((GameObject*)obj)->unkF4 = 1;
                        }
                    }
                }
            }
        }
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.alpha = 255;
    }
    ((EnemyState*)state)->unk2FC = (f32)setup[0x2f] / lbl_803E257C;
    ((EnemyState*)state)->unk2A8 = (f32)(u32)(setup[0x29] << 3);
    *(int*)&((EnemyState*)state)->controlFlags = 0;
    ((EnemyState*)state)->initialFlags = *(int*)&((EnemyState*)state)->controlFlags;
    *(s16*)obj = *(s8*)(setup + 0x2a) << 8;
    ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
    ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
    ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    if (flag == 0)
    {
        *(int*)&((EnemyState*)state)->flags2E4 = 0;
        ((EnemyState*)state)->unk2E8 = 0;
        state[0x2f1] = 0;
        state[0x2f2] = 0;
        ((EnemyState*)state)->unk2EC = 0;
        state[0x2f5] = 0;
        fz = lbl_803E2574;
        ((EnemyState*)state)->unk300 = fz;
        ((EnemyState*)state)->unk304 = fz;
        ((EnemyState*)state)->unk308 = fz;
        ((EnemyState*)state)->particleScale = fz;
        state[0x323] = 0;
        ((EnemyState*)state)->unk310 = fz;
        ((EnemyState*)state)->unk2F8 = 0;
        state[0x33a] = 0;
        state[0x33b] = 0;
        ((EnemyState*)state)->phaseAngle = 0;
        state[0x33c] = 0;
        state[0x33d] = 0;
        ((EnemyState*)state)->unk324 = fz;
        ((EnemyState*)state)->unk328 = fz;
        ((EnemyState*)state)->unk32C = fz;
        ((EnemyState*)state)->unk330 = fz;
        ((EnemyState*)state)->intervalTimer = fz;
        ((EnemyState*)state)->unk2B4 = -1;
        ((EnemyState*)state)->unk2B6 = ((EnemyState*)state)->unk2B4;
        ((GameObject*)obj)->objectFlags |= *(s8*)(setup + 0x28) & 7;
        ((EnemyState*)state)->unk2B0 = setup[0x32];
        ((GameObject*)obj)->animEventCallback = (void*)enemy_animEventCallback;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 17:
        case 314:
        case 1463:
        case 1464:
        case 1465:
        case 1505:
        case 1958:
            fn_80151954(obj, state);
            break;
        case 216:
        case 641:
            fn_801522E0(obj, state);
            break;
        case 1555:
            fn_80152A94(obj, state);
            break;
        case 1602:
            fn_80152EC0(obj, state);
            break;
        case 1022:
        case 1990:
            fn_801534D8(obj, state);
            break;
        case 1419:
            fn_80153C90(obj, state);
            break;
        case 873:
            fn_801542AC(obj, state);
            break;
        case 593:
            fn_80154C24(obj, state);
            break;
        case 605:
            rachnopInit(obj, (int)state);
            break;
        case 1111:
            baddieInit_80156188(obj, (int)state);
            break;
        case 1239:
            wbInit(obj, (int)state);
            break;
        case 1112:
            mutatedEbaInit(obj, state);
            break;
        case 2129:
            mediumbasket_initWhirlpoolState(obj, state);
            break;
        case 2114:
        case 2123:
            smallbasket_initVariantState(obj, state);
            break;
        case 1196:
            smallbasket_initScaledVariantState(obj, state);
            break;
        case 1063:
            fn_8014FF58(obj, state);
            break;
        case 1698:
        case 1699:
        case 1700:
        case 1701:
            smallbasket_initModelVariantState(obj, state);
            break;
        case 1992:
            smallbasket_initTailModelState(obj, state);
            break;
        default:
            fn_8014FF58(obj, state);
            break;
        }
        ((EnemyState*)state)->unk2B2 = *(u16*)&((EnemyState*)state)->unk2B0;
        if (*(u16*)(setup + 0x34) != 0)
        {
            *(int*)&((EnemyState*)state)->flags2E4 = *(int*)&((EnemyState*)state)->flags2E4 & -39;
        }
        ObjGroup_AddObject(obj, 3);
        state[0x2f0] = 7;
        state[0x2ef] = 2;
        if (*(void**)state == NULL)
        {
            *(int*)state = (int)mmAlloc(264, 26, 0);
        }
        if (*(void**)state != NULL)
        {
            memset(*(void**)state, 0, 264);
        }
        if ((*gRomCurveInterface)->initCurve(*(void**)state, (void*)obj, ((EnemyState*)state)->unk2AC,
                                             (int*)&lbl_803DBC58, -1) == 0)
        {
            ((EnemyState*)state)->controlFlags |= 0x2000;
        }
        (*gPathControlInterface)->init(state + 4, 0, 422, 1);
        if ((((EnemyState*)state)->flags2E4 & 8) != 0)
        {
            (*gPathControlInterface)->setLocalPointCollision(state + 4, 1, lbl_8031DBE4,
                                                             &lbl_803DBC64, 4);
        }
        if ((((EnemyState*)state)->flags2E4 & 4) != 0)
        {
            (*gPathControlInterface)->setup(state + 4, 1, lbl_8031DBD8, &lbl_803DBC60, &lbl_803DBC68);
        }
        (*gPathControlInterface)->attachObject((void*)obj, state + 4);
        if ((((EnemyState*)state)->flags2E4 & 0xc) != 0)
        {
            state[0x25f] = 1;
        }
        if ((((EnemyState*)state)->flags2E4 & 0x8000022) != 0 || *(u16*)(setup + 0x34) != 0
            || ((GameObject*)obj)->anim.seqId == 1022 || ((GameObject*)obj)->anim.seqId == 1990)
        {
            ((EnemyState*)state)->unk4 |= 0x40000;
        }
        else
        {
            ((EnemyState*)state)->unk4 &= ~0x40000;
        }
        if ((((EnemyState*)state)->flags2E4 & 4) == 0 && (((EnemyState*)state)->flags2E4 & 8) != 0)
        {
            ((EnemyState*)state)->unk4 &= ~0x3800;
        }
        if (((GameObject*)obj)->unkF4 != 0)
        {
            ((EnemyState*)state)->controlFlags |= 0x1000;
            *(u32*)&((EnemyState*)state)->initialFlags =
                *(u32*)&((EnemyState*)state)->initialFlags & ~0x1000LL;
            ObjHits_DisableObject((u32)obj);
        }
        else if ((((EnemyState*)state)->flags2E4 & 1) != 0)
        {
            ObjHits_EnableObject((u32)obj);
        }
    }
    ((EnemyState*)state)->unk2D8 = lbl_803E2574;
    if (((EnemyState*)state)->unk2A8 > *(f32*)&lbl_803E25B0)
    {
        ((EnemyState*)state)->unk2A8 = lbl_803E25B0;
    }
    if (((EnemyState*)state)->unk2AC > *(f32*)&lbl_803E25B0)
    {
        ((EnemyState*)state)->unk2AC = lbl_803E25B0;
    }
}
