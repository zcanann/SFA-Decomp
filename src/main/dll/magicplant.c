/*
 * magicplant - per-move behaviour handlers for the magic-plant enemy,
 * shared by the tricky (DLL 0x00C4) and enemy (DLL 0x00C9) object DLLs,
 * which dispatch to these by object seqId.
 *
 * Each fn_8015xxxx takes (GameObject* obj, BaddieState* state) and drives
 * one AI phase: per-move setup of speed/hitbox/path constants, curve-path
 * following via the RomCurve interface, a wind-up state machine that spits
 * projectiles toward the tracked object, line-of-sight gating through the
 * voxel maps, hit-reaction message handling, and particle-fx spawning.
 * BaddieState->controlFlags bit 0x2000 gates path advance; 0x40000000 the
 * attack window; inWhirlpoolGroup holds per-instance counters/flags.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
void fn_8014D08C(int obj, int state, u8 moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags) \
    fn_8014D08C((int)(obj), (int)(state), (moveId), (speed), (p5), (flags))
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000
extern const f32 lbl_803E28B0;
extern f32 lbl_803E28BC;
extern f32 lbl_803E28D0;
extern f32 lbl_803E28DC;
extern f32 lbl_803E28E0;
extern f32 lbl_803E28E4;
extern f32 lbl_803E28E8;
extern f32 lbl_803E286C;
extern f32 lbl_803E2894;
extern f32 lbl_803E28B4;
extern f32 lbl_803E28B8;
extern f32 lbl_803E28C0;
extern f32 lbl_803E28C4;
extern f32 lbl_803E28C8;
extern f32 lbl_803E28CC;
extern int lbl_803DBCB8;
extern f32 timeDelta;

extern void fn_8014CF7C(int obj, int state, f32 f1, f32 f2, int p3, int p4);
extern void fn_8014C678(int obj, int state, void* vec, f32 f1, f32 f2, f32 f3, int p6);
extern void fn_8014CD1C(int obj, int state, int p3, f32 f1, f32 f2, int p6);
extern f32 lbl_803E28A0;
extern f32 lbl_803E28A4;
extern f32 lbl_803E28A8;
extern f32 lbl_803E28F4;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f32 lbl_803E2924;
extern f32 lbl_803E2928;
extern f32 lbl_803E292C;
extern f32 lbl_803E2930;
extern f32 lbl_803E28D4;
extern f32 lbl_803E28D8;
extern f32 lbl_803E28F0;
extern f32 lbl_803E2900;
extern f32 lbl_803E2904;
extern f32 lbl_803E2908;
extern f64 lbl_803E2918;
extern f64 lbl_803E2938;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E2920;
extern f32 lbl_803E294C;
extern f32 lbl_803E2950;
extern f32 lbl_803E2954;
extern f32 lbl_803E2958;
extern u8 gMagicPlantSeqEntryTable[8];
extern int lbl_803DBCC8;
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern void voxmaps_worldToGrid(f32* pos, int* grid);
extern int voxmaps_traceLine(int* a, int* b, int c, u8* out, int e);
extern f32 PSVECMag(f32 * v);
extern int getAngle(float y, float x);

void fn_80152EC0(int obj, int state)
{
    f32 zero;
    f32 lblA;
    f32 a, b;

    zero = lbl_803E286C;
    ((BaddieState*)state)->speedScale = zero;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = lbl_803E28A0;
    ((BaddieState*)state)->animDeltaScale = lbl_803E28A4;
    lblA = lbl_803E2894;
    ((BaddieState*)state)->unk304 = lblA;
    ((BaddieState*)state)->unk320 = 1;
    *(f32*)&((BaddieState*)state)->eventFlags = lblA;
    ((BaddieState*)state)->unk321 = 3;
    ((BaddieState*)state)->unk318 = lblA;
    ((BaddieState*)state)->unk322 = 1;
    ((BaddieState*)state)->unk31C = lblA;
    *(f32*)(state + 0x324) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(state + 0x328) = ((GameObject*)obj)->anim.localPosY;
    *(f32*)(state + 0x32c) = ((GameObject*)obj)->anim.localPosZ;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    *(s16*)(state + 0x338) = 0;
    *(f32*)(state + 0x330) = zero;
    *(f32*)(state + 0x334) = zero;
    ((BaddieState*)state)->pathStep = lbl_803E28A8;

    fn_80293018((s32)(u32) * (u16*)(state + 0x338), &a, &b);
    ((GameObject*)obj)->anim.localPosX = a * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    ((GameObject*)obj)->anim.localPosZ = b * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
}

void fn_80152FA8(int obj, int state, int unused, int msgFlag)
{
    if (((BaddieState*)state)->inWhirlpoolGroup != 0)
    {
        if (msgFlag == 16)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x28;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt4);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
    }
    else if (msgFlag != 17)
    {
        if (msgFlag == 16)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt4);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
    }
}

void fn_80153040(int obj, int state)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    f32 vec[3];

    curve = *(RomCurveWalker**)state;
    if (((GameObject*)obj)->anim.hitReactState != NULL)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->suppressOutgoingHits = 0;
    }
    if (((BaddieState*)state)->inWhirlpoolGroup != 0)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState*)state)->pathStep) != 0 || curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E28B8,
                                                     &lbl_803DBCB8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }

        fn_8014CF7C(obj, state, curve->posX, curve->posZ, 0xf, 0);

        vec[0] = curve->posX - ((GameObject*)obj)->anim.localPosX;
        vec[1] = curve->posY - ((GameObject*)obj)->anim.localPosY;
        vec[2] = curve->posZ - ((GameObject*)obj)->anim.localPosZ;
        fn_8014C678(obj, state, vec, lbl_803E28BC, lbl_803E28C0, lbl_803E28C4, 1);

        *(f32*)(state + 0x324) = *(f32*)(state + 0x324) + timeDelta;
        if (*(f32*)(state + 0x324) > lbl_803E28C8)
        {
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~(u64)0x10000;
            *(f32*)(state + 0x324) = lbl_803E28B0;
        }
    }

    fn_8014CD1C(obj, state, 0xf, lbl_803E28CC, lbl_803E28D0, 0);

    *(f32*)(state + 0x328) = *(f32*)(state + 0x328) - timeDelta;
    if (*(f32*)(state + 0x328) <= lbl_803E28B0)
    {
        *(f32*)(state + 0x328) = lbl_803E28B4;
        Sfx_PlayFromObject(obj, SFXfox_healthgasp1);
    }
    *(f32*)(state + 0x32c) = lbl_803E28B0;
}

void fn_80153248(int obj, int state)
{
    RomCurveWalker* curve;
    f32 vec[3];
    f32 worldPos[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    int trackedObj;

    curve = *(RomCurveWalker**)state;
    if (((BaddieState*)state)->inWhirlpoolGroup != 0)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        Sfx_PlayFromObject(obj, SFXfox_climbgrunt3);
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, lbl_803E28D4 * ((BaddieState*)state)->pathStep) != 0
            || curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E28B8,
                                                     &lbl_803DBCB8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
    }
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
    vec[0] = ((GameObject*)trackedObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    vec[1] = (lbl_803E28D8 + ((GameObject*)trackedObj)->anim.localPosY) - ((GameObject*)obj)->anim.localPosY;
    vec[2] = ((GameObject*)trackedObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    PSVECMag(vec);
    *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) + timeDelta;
    if (*(u32*)(state + 0x340) != 0 || *(f32*)(state + 0x32c) > lbl_803E28C8)
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        *(f32*)(state + 0x324) = lbl_803E28B0;
        *(f32*)(state + 0x32c) = lbl_803E28B0;
    }
    else
    {
        worldPos[0] = ((GameObject*)obj)->anim.localPosX;
        worldPos[1] = ((GameObject*)obj)->anim.localPosY;
        worldPos[2] = ((GameObject*)obj)->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, gridA);
        worldPos[0] = curve->posX;
        worldPos[1] = curve->posY;
        worldPos[2] = curve->posZ;
        voxmaps_worldToGrid(worldPos, gridB);
        /* BUG: precedence - `!` binds before `&`, so this is (controlFlags == 0) & 0x01000000,
         * which is always false; the line-of-sight abort below can never fire. The author
         * almost certainly meant !(controlFlags & 0x01000000). */
        if (!((BaddieState*)state)->controlFlags & 0x01000000)
        {
            if (voxmaps_traceLine(gridB, gridA, 0, &hitOut, 0) == 0)
            {
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
                *(f32*)(state + 0x324) = lbl_803E28B0;
                *(f32*)(state + 0x32c) = lbl_803E28B0;
            }
        }
    }
    fn_8014C678(obj, state, vec, lbl_803E28BC, lbl_803E28C0, lbl_803E28C4, 1);
    fn_8014CD1C(obj, state, 0xf, lbl_803E28CC, lbl_803E28D0, 0);
}

void fn_801534D8(int obj, int state)
{
    f32 initSpeed;
    f32 zero;
    f32 pathStepInit;

    ((BaddieState*)state)->speedScale = lbl_803E28DC;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x1009;
    ((BaddieState*)state)->unk308 = lbl_803E28E0;
    ((BaddieState*)state)->animDeltaScale = lbl_803E28E4;
    ((BaddieState*)state)->unk304 = lbl_803E28E8;
    ((BaddieState*)state)->unk320 = 0;
    initSpeed = lbl_803E28BC;
    *(f32*)&((BaddieState*)state)->eventFlags = initSpeed;
    ((BaddieState*)state)->unk321 = 1;
    pathStepInit = lbl_803E28D0;
    ((BaddieState*)state)->unk318 = pathStepInit;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = initSpeed;
    zero = lbl_803E28B0;
    *(f32*)(state + 0x324) = zero;
    *(f32*)(state + 0x328) = zero;
    *(f32*)(state + 0x32c) = zero;
    ((BaddieState*)state)->pathStep = pathStepInit;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x7c6:
        ((BaddieState*)state)->inWhirlpoolGroup = 1;
        break;
    default:
        ((BaddieState*)state)->inWhirlpoolGroup = 0;
        break;
    }
}

#pragma dont_inline on
void fn_8015355C(int obj, int state)
{
    u8 count = 0;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 1:
        count = 1;
        break;
    case 2:
        count = 1;
        break;
    case 3:
        count = 1;
        break;
    case 5:
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
        {
            count = 0xa;
        }
        break;
    case 7:
        break;
    }
    if (count != 0 && (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) == 0)
    {
        u8 spawn = count;
        while (spawn != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x802, NULL, 2, -1, NULL);
            spawn--;
        }
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_80153640(int obj, int state)
{
    ObjPlacement* fx;
    int newObj;

    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        fx = (ObjPlacement*)Obj_AllocObjectSetup(0x24, 0x51b);
        fx->posX = ((GameObject*)obj)->anim.localPosX;
        fx->posY = lbl_803E28F0 + ((GameObject*)obj)->anim.localPosY;
        fx->posZ = ((GameObject*)obj)->anim.localPosZ;
        fx->color[0] = 1;
        fx->color[1] = 1;
        fx->color[2] = 0xff;
        fx->color[3] = 0xff;
        newObj = Obj_SetupObject((int)fx, 5, -1, -1, 0);
        if ((void*)newObj != NULL)
        {
            ((GameObject*)newObj)->anim.velocityX = 0.02f *
                (((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosX -
                 fx->posX);
            {
                ((GameObject*)newObj)->anim.velocityY = 0.02f *
                    ((lbl_803E28F0 +
                      ((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosY +
                      (f32)(s32)randomGetRange(-10, 10)) -
                     fx->posY);
                ((GameObject*)newObj)->anim.velocityZ = 0.02f *
                    (((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosZ -
                     fx->posZ);
            }
            *(int*)&((GameObject*)newObj)->ownerObj = obj;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_blooplaugh2);
    }
}
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_80153790(int obj, int state, int attacker, int msgFlag, int hitId, int damage)
{
    if (((GameObject*)obj)->anim.currentMove == 1)
    {
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            return;
        }
    }
    if (msgFlag == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
        if (damage > (s32)((BaddieState*)state)->hitCounter)
        {
            Sfx_PlayFromObject(obj, SFXfox_bigfallgrunt1);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXfox_bigfallgrunt2);
            ((BaddieState*)state)->hitCounter = (u16)(((BaddieState*)state)->hitCounter - damage);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void fn_8015383C(int obj, int state)
{
    u32 hit;
    u8 losDetected;
    f32 worldPos[3];
    f32 vec[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    u8 flagByte;
    u32 rnd;
    s16 angle;

    ((BaddieState*)state)->inWhirlpoolGroup = ((BaddieState*)state)->inWhirlpoolGroup & 0x7f;
    losDetected = 0;
    vec[0] = ((GameObject*)obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX;
    vec[1] = ((GameObject*)obj)->anim.localPosY - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosY;
    vec[2] = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ;
    if (PSVECMag(vec) < lbl_803E2900
        && (((GameObject*)((BaddieState*)state)->trackedObj)->objectFlags & MAGICPLANT_OBJFLAG_PARENT_SLACK) == 0)
    {
        worldPos[0] = ((GameObject*)obj)->anim.localPosX;
        worldPos[1] = lbl_803E2904 + ((GameObject*)obj)->anim.localPosY;
        worldPos[2] = ((GameObject*)obj)->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, gridA);
        {
            int trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
            worldPos[0] = ((GameObject*)trackedObj)->anim.localPosX;
            worldPos[1] = lbl_803E2908 + ((GameObject*)trackedObj)->anim.localPosY;
            worldPos[2] = ((GameObject*)trackedObj)->anim.localPosZ;
        }
        voxmaps_worldToGrid(worldPos, gridB);
        hit = voxmaps_traceLine(gridB, gridA, 0, &hitOut, 0) & 0xff;
        if (hit != 0)
        {
            int trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
            fn_8014CF7C(obj, state, ((GameObject*)trackedObj)->anim.localPosX, ((GameObject*)trackedObj)->anim.localPosZ, 0x14, 0);
            angle = (s16)(getAngle(vec[0], vec[2]) - (u16)((GameObject*)obj)->anim.rotX);
            if (angle > 0x8000) angle = (angle - 0x10000) + 1;
            if (angle < -0x8000) angle = (angle + 0x10000) - 1;
            if (angle < 0) angle = -angle;
            if (angle < 1000) losDetected = 1;
        }
    }
    else
    {
        hit = 0;
    }
    flagByte = ((BaddieState*)state)->inWhirlpoolGroup;
    if ((flagByte & 0x40) == 0)
    {
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_blooplaugh3, 2);
        Baddie_SetMove(obj, state, 2, lbl_803E290C, 0, 0);
        ((BaddieState*)state)->inWhirlpoolGroup = (u8)((((BaddieState*)state)->inWhirlpoolGroup) | 0x40);
        ((BaddieState*)state)->seqEntryIndex = 0;
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        u8 mode;
        if ((u8)hit != 0)
        {
            if (((BaddieState*)state)->seqEntryIndex != 0)
            {
                ((BaddieState*)state)->seqEntryIndex -= 1;
                mode = (u8)((GameObject*)obj)->anim.currentMove;
            }
            else if (((GameObject*)obj)->anim.currentMove != 5 && losDetected)
            {
                mode = 5;
                ((BaddieState*)state)->seqEntryIndex = gMagicPlantSeqEntryTable[((BaddieState*)state)->inWhirlpoolGroup & 3];
                ((BaddieState*)state)->inWhirlpoolGroup = (u8)(
                    (*(s8*)&((BaddieState*)state)->inWhirlpoolGroup + 1) & 0xc3);
            }
            else
            {
                mode = 4;
                rnd = randomGetRange(1, 2);
                ((BaddieState*)state)->seqEntryIndex = rnd;
            }
        }
        else
        {
            rnd = randomGetRange(2, 4);
            mode = rnd;
            if (mode == 2)
            {
                mode = 0;
            }
            else if (mode == 4)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_newtricky_01j);
            }
        }
        Baddie_SetMove(obj, state, mode, lbl_803E2910, 0, 0);
    }
    if (((GameObject*)obj)->anim.currentMove == 5)
    {
        f32 sct = ((GameObject*)obj)->anim.currentMoveProgress;
        if ((double)sct >= lbl_803E2918
            && (double)sct < lbl_803E2918 + ((BaddieState*)state)->unk308 * timeDelta)
        {
            fn_80153640(obj, state);
            goto sharedTail;
        }
    }
    *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
    if (*(f32*)(state + 0x324) <= lbl_803E2920)
    {
        rnd = randomGetRange(0x96, 0x12c);
        *(f32*)(state + 0x324) = (f32)(s32)rnd;
        Sfx_PlayFromObject(obj, SFXwatery_bubble3);
    }
sharedTail:
    fn_8015355C(obj, state);
}

void fn_80153BFC(int obj, int state)
{
    ((BaddieState*)state)->inWhirlpoolGroup = ((BaddieState*)state)->inWhirlpoolGroup & 0xbf;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 && ((GameObject*)obj)->anim.currentMove != 1)
    {
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_eggsnatch_movelp, 2);
        Baddie_SetMove(obj, state, 1, lbl_803E290C, 0, 0);
    }
    fn_8015355C(obj, state);
}

void fn_80153C90(int unused, int state)
{
    f32 eventFlagsVal;
    f32 pathStepInit;
    ((BaddieState*)state)->speedScale = lbl_803E2924;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = lbl_803E28F4;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2928;
    ((BaddieState*)state)->unk304 = lbl_803E292C;
    ((BaddieState*)state)->unk320 = 0;
    eventFlagsVal = lbl_803E2910;
    *(f32*)&((BaddieState*)state)->eventFlags = eventFlagsVal;
    ((BaddieState*)state)->unk321 = 7;
    pathStepInit = lbl_803E290C;
    ((BaddieState*)state)->unk318 = pathStepInit;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = eventFlagsVal;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    *(f32*)(state + 0x324) = lbl_803E2930;
    ((BaddieState*)state)->pathStep = pathStepInit;
}

void fn_80153CF8(int obj, int state, int attacker, int msgFlag)
{
    u8 cond = 0;
    int kind = ((GameObject*)obj)->anim.currentMove;
    if (kind == 5)
    {
    }
    else if (kind == 4)
    {
    }
    else if (kind == 6)
    {
        if ((double)((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2938)
        {
        }
        else
        {
            goto checkedKind;
        }
    }
    else
    {
        goto checkedKind;
    }

    if (msgFlag != 0xe)
    {
        cond = 1;
    }

checkedKind:
    {
    u32 condV = cond;
    if (msgFlag == 0x10)
    {
        if (condV != 0)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
    }
    else if (condV != 0)
    {
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject(obj, SFXfox_healthgasp4);
        }
    }
    else if (msgFlag == 0x11)
    {
        *(f32*)(state + 0x32c) = lbl_803E2940;
        *(f32*)(state + 0x324) = lbl_803E2944;
        Baddie_SetMove(obj, state, 4, lbl_803E2948, 0, 3);
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        ((BaddieState*)state)->inWhirlpoolGroup = 0x3c;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
    }
    }
}

void fn_80153E0C(int obj, int state)
{
    RomCurveWalker* curve;
    u32 rnd;
    u8 ctr;

    curve = *(RomCurveWalker**)state;
    ((BaddieState*)state)->seqEntryIndex = 0;
    *(f32*)(state + 0x328) = lbl_803E294C;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState*)state)->pathStep) != 0 || curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E2950,
                                                     &lbl_803DBCC8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        if (lbl_803E294C == *(f32*)(state + 0x32c))
        {
            if (((GameObject*)obj)->anim.currentMove == 0)
            {
                fn_8014CF7C(obj, state, curve->posX, curve->posZ, 0x3c, 0);
            }
            if (*(f32*)(state + 0x324) > lbl_803E294C)
            {
                f32 zero = lbl_803E294C;
                *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
                if (*(f32*)(state + 0x324) <= zero)
                {
                    *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~(u64)0x10000;
                    *(f32*)(state + 0x324) = zero;
                }
            }
        }
    }
    if (*(f32*)(state + 0x32c) > lbl_803E294C)
    {
        f32 zero = lbl_803E294C;
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= zero)
        {
            Baddie_SetMove(obj, state, 6, lbl_803E2948, 0, 3);
            *(f32*)(state + 0x32c) = lbl_803E294C;
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            Baddie_SetMove(obj, state, 5, lbl_803E2954, 0, 3);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Baddie_SetMove(obj, state, 0, lbl_803E2958, 0, 3);
    }
    ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
    ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E294C)
    {
        rnd = randomGetRange(0x3c, 0x78);
        *(f32*)(state + 0x330) = (f32)(s32)rnd;
        Sfx_PlayFromObject(obj, SFXfox_healthgasp3);
    }
    ctr = ((BaddieState*)state)->inWhirlpoolGroup;
    if (ctr != 0)
    {
        ((BaddieState*)state)->inWhirlpoolGroup--;
    }
}
