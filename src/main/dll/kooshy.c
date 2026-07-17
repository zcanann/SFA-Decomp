#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/voxmaps.h"

extern u8 gMagicPlantSeqEntryTable[8];

#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000

/* DLL-id of the object spawned by fn_80153640 (generic spawn; no cache field /
   named spawn-fn / kind name -> suffixless per role-gate). */
#define MAGICPLANT_CHILD_OBJ 0x51b

extern f32 lbl_803E2900;
extern f32 lbl_803E2904;
extern f32 lbl_803E2908;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f64 lbl_803E2918;
extern f32 lbl_803E2920;
extern f32 lbl_803E2924;
extern f32 lbl_803E2928;
extern f32 lbl_803E292C;
extern f32 lbl_803E2930;
void fn_8014D08C(GameObject* obj, int state, u8 moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags)                                                           \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (p5), (flags))
extern void fn_8014CF7C(int obj, int state, f32 f1, f32 f2, int p3, int p4);
extern void fn_8015355C(GameObject* obj, int state);

#pragma dont_inline on
void fn_80153640(GameObject* obj, int state)
{
    ObjPlacement* fx;
    int newObj;

    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        fx = (ObjPlacement*)Obj_AllocObjectSetup(0x24, MAGICPLANT_CHILD_OBJ);
        fx->posX = (obj)->anim.localPosX;
        fx->posY = 14.0f + (obj)->anim.localPosY;
        fx->posZ = (obj)->anim.localPosZ;
        fx->color[0] = 1;
        fx->color[1] = 1;
        fx->color[2] = 0xff;
        fx->color[3] = 0xff;
        newObj = (int)Obj_SetupObject(fx, 5, -1, -1, 0);
        if ((void*)newObj != NULL)
        {
            ((GameObject*)newObj)->anim.velocityX =
                0.02f * (((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosX - fx->posX);
            {
                ((GameObject*)newObj)->anim.velocityY =
                    0.02f * ((14.0f + ((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosY +
                              (f32)(s32)randomGetRange(-10, 10)) -
                             fx->posY);
                ((GameObject*)newObj)->anim.velocityZ =
                    0.02f * (((GameObject*)*(int*)&((BaddieState*)state)->trackedObj)->anim.localPosZ - fx->posZ);
            }
            *(int*)&((GameObject*)newObj)->ownerObj = (int)obj;
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_blooplaugh2);
    }
}
#pragma dont_inline reset

void kooshy_updateWhileFrozen(GameObject* obj, int state, int attacker, int msgFlag, int hitId, int damage)
{
    if ((obj)->anim.currentMove == 1)
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
            Sfx_PlayFromObject((int)obj, SFXTRIG_sc_walkstep);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
        else
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_sc_runstep);
            ((BaddieState*)state)->hitCounter = (u16)(((BaddieState*)state)->hitCounter - damage);
        }
    }
}
void fn_8015383C(GameObject* obj, int state)
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
    vec[0] = (obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX;
    vec[1] = (obj)->anim.localPosY - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosY;
    vec[2] = (obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ;
    if (PSVECMag(vec) < lbl_803E2900 &&
        (((GameObject*)((BaddieState*)state)->trackedObj)->objectFlags & MAGICPLANT_OBJFLAG_PARENT_SLACK) == 0)
    {
        worldPos[0] = (obj)->anim.localPosX;
        worldPos[1] = lbl_803E2904 + (obj)->anim.localPosY;
        worldPos[2] = (obj)->anim.localPosZ;
        voxmaps_worldToIntGrid(worldPos, gridA);
        {
            int trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
            worldPos[0] = ((GameObject*)trackedObj)->anim.localPosX;
            worldPos[1] = lbl_803E2908 + ((GameObject*)trackedObj)->anim.localPosY;
            worldPos[2] = ((GameObject*)trackedObj)->anim.localPosZ;
        }
        voxmaps_worldToIntGrid(worldPos, gridB);
        hit = voxmaps_traceIntGrid(gridB, gridA, NULL, &hitOut, 0) & 0xff;
        if (hit != 0)
        {
            int trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
            fn_8014CF7C((int)obj, state, ((GameObject*)trackedObj)->anim.localPosX,
                        ((GameObject*)trackedObj)->anim.localPosZ, 0x14, 0);
            angle = (s16)(getAngle(vec[0], vec[2]) - (u16)(obj)->anim.rotX);
            if (angle > 0x8000)
                angle = (angle - 0x10000) + 1;
            if (angle < -0x8000)
                angle = (angle + 0x10000) - 1;
            if (angle < 0)
                angle = -angle;
            if (angle < 1000)
                losDetected = 1;
        }
    }
    else
    {
        hit = 0;
    }
    flagByte = ((BaddieState*)state)->inWhirlpoolGroup;
    if ((flagByte & 0x40) == 0)
    {
        Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_baddie_blooplaugh3, 2);
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
                mode = (u8)(obj)->anim.currentMove;
            }
            else if ((obj)->anim.currentMove != 5 && losDetected)
            {
                mode = 5;
                ((BaddieState*)state)->seqEntryIndex =
                    gMagicPlantSeqEntryTable[((BaddieState*)state)->inWhirlpoolGroup & 3];
                ((BaddieState*)state)->inWhirlpoolGroup =
                    (u8)((*(s8*)&((BaddieState*)state)->inWhirlpoolGroup + 1) & 0xc3);
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
                Sfx_PlayFromObject((int)obj, SFXTRIG_newtricky_01j);
            }
        }
        Baddie_SetMove(obj, state, mode, lbl_803E2910, 0, 0);
    }
    if ((obj)->anim.currentMove == 5)
    {
        f32 sct = (obj)->anim.currentMoveProgress;
        if ((double)sct >= lbl_803E2918 && (double)sct < lbl_803E2918 + ((BaddieState*)state)->unk308 * timeDelta)
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
        Sfx_PlayFromObject((int)obj, SFXTRIG_sc_clubswipe);
    }
sharedTail:
    fn_8015355C(obj, state);
}

void fn_80153BFC(GameObject* obj, int state)
{
    ((BaddieState*)state)->inWhirlpoolGroup = ((BaddieState*)state)->inWhirlpoolGroup & 0xbf;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 && (obj)->anim.currentMove != 1)
    {
        Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_baddie_eggsnatch_movelp, 2);
        Baddie_SetMove(obj, state, 1, lbl_803E290C, 0, 0);
    }
    fn_8015355C(obj, state);
}

void kooshy_init(int unused, int state)
{
    f32 eventFlagsVal;
    f32 pathStepInit;
    ((BaddieState*)state)->speedScale = lbl_803E2924;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = 0.02f;
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
