/* DLL 0x243 - DBHoleControl1 [801FE118-801FEB30) */
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
extern void objRenderFn_8003b8f4(f32);

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */

#include "main/audio/sfx_ids.h"
#include "main/dll/anim.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/objhits.h"
#include "main/dll/fx_800944A0_shared.h"

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* chuka extra block (extraSize 0xC). */

typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s16 unk18;
    s16 gameBitA; /* copied into DbHoleControl1State.gameBitA */
    s16 gameBitB; /* copied into DbHoleControl1State.gameBitB */
    s16 hideGameBit;
    s16 triggerGameBit;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} Dbholecontrol1Placement;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern u32 FUN_80006824();
extern u32 FUN_80006ab8();
extern u64 FUN_80006ac4();

extern int FUN_80017a98();
extern u64 FUN_800305f8();
extern u32 ObjMsg_SendToObject();
extern u32 FUN_8003b818();
extern double FUN_80293900();
extern u32 DAT_8032a290;
extern f32 lbl_803DC074;
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F50;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;

int dbstealerworm_stateHandlerB04(int obj, int p);

int dbstealerworm_stateHandlerB02(int obj, int p);

extern void Obj_RemoveFromUpdateList(int* obj);
extern f32 lbl_803E6390;
extern int gDBStealerWormStateHandlersA[];
extern int gDBStealerWormStateHandlersB[];
extern int dbstealerworm_stateHandlerB06();
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA02();

/* dbstealerworm state handler: begin a "grab/carry target" move. Sets the
 * control-record grab flags, plays the run-toward move (0x11), stores the
 * grabbed target into the control record and queues a 0x11 message to it. */
u32
FUN_80200558(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, u32 obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    DbStealerwormControl* control;

    control = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    control->flags14 = control->flags14 | 2;
    control->flags15 = control->flags15 | 4;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6F80;
    if (*(char*)(state + 0x27a) != '\0')
    {
        arg1 = FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7,
                               arg8, obj, 0x11, 0, arg12, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 0x1f;
    if (*(char*)(state + 0x27a) != '\0')
    {
        control->linkedObj = *(int*)&((GroundBaddieState*)state)->baddie.targetObj;
        control->unk1C = 0x24;
        control->unk2C = 0;
        ObjMsg_SendToObject(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                            control->linkedObj, 0x11, obj, 0x12, arg13, arg14, arg15, arg16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        control->unk34 = 1;
    }
    return 0;
}

/* dbstealerworm state handler: carrying-target update. Halves the two turn
 * accumulators, runs the carry move (0x11); once the move is far enough along
 * (or the target has dropped below), either queues a 0xe "arrived" message if
 * within range, else queues the 9/7 "still travelling" message pair. */
u32
FUN_80200740(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, int obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    float divisor;
    u32 queueFull;
    int targetObj;
    short* msgQueue;
    DbStealerwormControl* ctrl;
    double dist;
    u32 msg1Id;
    u32 msg1Flag;
    u32 msg1Data;
    u32 msg3Id;
    u32 msg3Flag;
    u32 msg3Data;
    u32 msg2Id;
    u32 msg2Flag;
    u32 msg2Data;
    float deltaX;
    float deltaY;
    float deltaZ;

    ctrl = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    ctrl->flags14 = ctrl->flags14 | 2;
    ctrl->flags15 = ctrl->flags15 & 0xfb;
    divisor = lbl_803E6F88;
    *(float*)(state + 0x280) = *(float*)(state + 0x280) / lbl_803E6F88;
    *(float*)(state + 0x284) = *(float*)(state + 0x284) / divisor;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                     obj, 0x11, 0, arg12, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 0x1f;
    if ((((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)obj)->anim.localPosY < ((GameObject*)((GroundBaddieState*)state)->baddie.targetObj)->anim.localPosY - lbl_803E6F90))
    {
        targetObj = *(int*)&((GroundBaddieState*)state)->baddie.targetObj;
        deltaX = *(float*)(targetObj + 0xc) - ((GameObject*)obj)->anim.localPosX;
        deltaY = *(float*)(targetObj + 0x10) - (((GameObject*)obj)->anim.localPosY + lbl_803E6F94);
        deltaZ = *(float*)(targetObj + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        dist = FUN_80293900((double)(deltaZ * deltaZ + deltaX * deltaX + deltaY * deltaY));
        if (dist < (double)lbl_803E6F50)
        {
            msg1Data = *(u32*)&((GroundBaddieState*)state)->baddie.targetObj;
            msgQueue = (short*)ctrl->msgStack;
            msg1Id = 0xe;
            msg1Flag = 1;
            queueFull = FUN_80006ab8(msgQueue);
            if (queueFull == 0)
            {
                FUN_80006ac4(msgQueue,  & msg1Id);
            }
            ctrl->unk34 = 1;
        }
    }
    else
    {
        msgQueue = (short*)ctrl->msgStack;
        msg2Id = 9;
        msg2Flag = 0;
        msg2Data = 0x24;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue,  & msg2Id);
        }
        ctrl->unk34 = 1;
        msg3Data = *(u32*)&((GroundBaddieState*)state)->baddie.targetObj;
        msgQueue = (short*)ctrl->msgStack;
        msg3Id = 7;
        msg3Flag = 1;
        queueFull = FUN_80006ab8(msgQueue);
        if (queueFull == 0)
        {
            FUN_80006ac4(msgQueue,  & msg3Id);
        }
        ctrl->unk34 = 1;
    }
    return 0;
}

/* dbstealerworm state handler: release/drop the carried target. Plays the
 * drop move (0), clears the carried target, notifies the linked object (0x10),
 * plays a random spit sfx (hurt-dependent range), and flushes the pending
 * control-record message. */
u32
FUN_80201260(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, u32 obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    int hurt;
    u32 busy;
    short* hits;
    DbStealerwormControl* control;
    u32 msg;
    u32 msgArg;
    u32 msgTarget;

    control = (DbStealerwormControl*)*(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        arg1 = FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7,
                               arg8, obj, 0, 0, arg12, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        ((GroundBaddieState*)state)->baddie.targetObj = 0;
        if (control->linkedObj != 0)
        {
            ObjMsg_SendToObject(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                control->linkedObj, 0x11, obj, 0x10, arg13, arg14, arg15, arg16);
            control->linkedObj = 0;
        }
        hurt = FUN_80017a98();
        hurt = (**(VtableFn**)(**(int**)(*(int*)(hurt + 200) + 0x68) + 0x44))();
        if (hurt == 0)
        {
            busy = randomGetRange(0, 2);
            FUN_80006824(obj, (u16) * (u32*)(&DAT_8032a290 + busy * 4));
        }
        else
        {
            busy = randomGetRange(3, 4);
            FUN_80006824(obj, (u16) * (u32*)(&DAT_8032a290 + busy * 4));
        }
        msgTarget = control->unk30;
        msgArg = control->unk2C;
        hits = (short*)control->msgStack;
        msg = control->unk28;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits,  & msg);
        }
        control->unk3C = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 0x10;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6FD8;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E6F40;
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

/* dbstealerworm state handler: enter attack move 10. Enables hits, plays the
 * attack move, sets the control grab flag; if the baddie's 0x314 bit0 latch is
 * set, clears it and raises control flag bit0 (one-shot). */
u32
FUN_802014c8(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, int obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    u32 animId;
    int extra;
    DbStealerwormControl* control;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                     obj, 10, 0, animId, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 1;
    control = (DbStealerwormControl*)*(int*)(extra + 0x40c);
    control->flags14 = control->flags14 | 2;
    if ((*(u32*)(state + 0x314) & 1) != 0)
    {
        *(u32*)(state + 0x314) = *(u32*)(state + 0x314) & ~1;
        control->flags14 = control->flags14 | 1;
    }
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p);

/* dbstealerworm state handler: enter move 5 (hit-enabled variant, no control
 * record touched). */
u32
FUN_80201658(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, int obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    u32 animId;

    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E6F8C;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                     obj, 5, 0, animId, arg13, arg14, arg15, arg16);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 1;
    return 0;
}

/* dbstealerworm state handler: idle/taunt. Randomly picks move 7 or 6, sets
 * move speed from the baddie's damage counter (extra+0x406), and raises the
 * control grab flag. */
u32
FUN_802017a0(u64 arg1, double arg2, double arg3, u64 arg4, u64 arg5,
             u64 arg6, u64 arg7, u64 arg8, int obj, int state,
             u32 arg11, u32 arg12, u32 arg13, u32 arg14,
             u32 arg15, u32 arg16)
{
    u32 pick;
    u32 animId;
    int extra;
    DbStealerwormControl* control;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)*(int*)(extra + 0x40c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (*(char*)(state + 0x27a) != '\0')
    {
        pick = randomGetRange(0, 1);
        if (pick == 0)
        {
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                             obj, 7, 0, animId, arg13, arg14, arg15, arg16);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        else if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                         obj, 6, 0, animId, arg13, arg14, arg15, arg16);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
        ((GroundBaddieState*)state)->baddie.unk34D = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed =
            lbl_803E6FDC +
            (float)((double)(u32) * (u8*)(extra + 0x406)) /
            lbl_803E6FE0;
    }
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E6F40;
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveDone != '\0')
    {
        control->unk34 = 1;
    }
    control->flags14 = control->flags14 | 2;
    return 0;
}

/* dbstealerworm steering: turn toward target by yaw error. Returns 1 (done)
 * until the scaled range error clears a threshold, then nudges the baddie turn
 * accumulator (state+0x280) toward the yaw-error-derived rate and returns 0. */
u32
FUN_80202004(double rangeThreshold, double turnGain, u64 unused3, double rangeScale, u16* obj,
             int target)
{
    int yawDelta;
    u32 result;
    int baddie;
    double absDist;
    double signedDist;
    float info[5];

    baddie = *(int*)&((GameObject*)obj)->extra;
    yawDelta = Obj_GetYawDeltaToObject(obj, target, info);
    if ((double)lbl_803E6F40 == rangeScale)
    {
        result = 0;
    }
    else
    {
        signedDist = (double)(float)((double)(float)((double)info[0] - rangeThreshold) / rangeScale);
        absDist = signedDist;
        if (signedDist < (double)lbl_803E6F40)
        {
            absDist = -signedDist;
        }
        if ((double)lbl_803E7008 <= absDist)
        {
            if (signedDist < (double)lbl_803E6F40)
            {
                turnGain = -turnGain;
            }
            *(float*)(baddie + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(turnGain *
                    (double)(lbl_803E6F60 -
                        (float)((double)(int)(short)yawDelta) / lbl_803E700C)) - *(float*)(baddie + 0x280)) +
                *(float*)(baddie + 0x280);
            *(float*)(baddie + 0x284) = lbl_803E6F40;
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

int dbstealerworm_stateHandlerA06(int obj, int p2);

/* dbstealerworm steering: turn toward target, but bail (return 1) if within
 * range AND the vertical gap is tiny (already on top of the target). Otherwise
 * nudges the baddie turn accumulator toward the yaw-error rate. */
u32
FUN_80202130(double rangeThreshold, double turnGain, u64 unused3, double rangeScale, u16* obj,
             int target)
{
    int yawDelta;
    int baddie;
    double absDy;
    float info[7];

    baddie = *(int*)&((GameObject*)obj)->extra;
    if ((obj != 0x0) && (target != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(obj, target, info);
        if ((double)lbl_803E6F40 != rangeScale)
        {
            if ((double)info[0] < rangeThreshold)
            {
                absDy = (double)(*(float*)(obj + 8) - *(float*)(target + 0x10));
                if (absDy < (double)lbl_803E6F40)
                {
                    absDy = -absDy;
                }
                if (absDy < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(baddie + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(turnGain *
                    (double)(lbl_803E6F60 -
                        (float)((double)(int)(short)yawDelta) / lbl_803E700C)) - *(float*)(baddie + 0x280)) +
                *(float*)(baddie + 0x280);
            *(float*)(baddie + 0x284) = lbl_803E6F40;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA05(int obj, int p);

int dbstealerworm_stateHandlerA03(int obj, int p);

int dbstealerworm_stateHandlerA01(int obj, int p);

/* dbstealerworm render: draw only when the visible flag is set. */
void FUN_80204320(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
    return;
}

void fn_80204320(int obj);

void dbholecontrol1_hitDetect(void)
{
}

void dbholecontrol1_release(void)
{
}

void dbholecontrol1_initialise(void)
{
}

void dbholecontrol1_update(int* obj)
{

    u8* def;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dbholecontrol1Placement*)def)->hideGameBit) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    }
    else if (GameBit_Get(((Dbholecontrol1Placement*)def)->triggerGameBit) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(*(s8*)(def + 0x19), obj, -1);
    }
}

void dbholecontrol1_init(int* obj, u8* params)
{
    extern u32 ObjGroup_AddObject();
    DbHoleControl1State* sub = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = dbholecontrol1_SeqFn;
    sub->gameBitA = ((Dbholecontrol1Placement*)params)->gameBitA;
    sub->gameBitB = ((Dbholecontrol1Placement*)params)->gameBitB;
}

int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }

void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E6390);
}

void dbholecontrol1_free(int x) { extern u64 ObjGroup_RemoveObject(); ObjGroup_RemoveObject(x, 0x1e); }

int dbstealerworm_stateHandlerB00(int p1, int p2);

int dbstealerworm_stateHandlerB03(int p1, int p2);

int dbstealerworm_stateHandlerB01(int p1, int p2);

int dbstealerworm_stateHandlerA00(int obj, int p2);

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{

    extern void*mapRomListFindItem(int, int, int, int, int);
    extern int Obj_AllocObjectSetup(int, int);
    extern void memcpy(int, void*, int);
    extern void loadObjectAtObject(int, int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern void ObjMsg_SendToObjects(int, int, int, int, int);
    extern int lbl_803DDCE0;
    int newObj;
    void* res;
    int* objs;
    int count;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if (GameBit_Get((s32)(s8) * (u8*)(data + 0x19) + 2601) != 0) continue;
            if (Obj_IsLoadingLocked() == 0) continue;
            res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
            if (res == NULL) continue;
            newObj = Obj_AllocObjectSetup(56, 1337);
            memcpy(newObj, res, 56);
            ((GameObject*)newObj)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)newObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)newObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
            *(int*)&((GameObject*)newObj)->anim.localPosZ = -1;
            *(s16*)(newObj + 26) = 149;
            loadObjectAtObject(obj, newObj);
            break;
        }
    }

    if (GameBit_Get(((Dbholecontrol1Placement*)data)->hideGameBit) != 0 || lbl_803DDCE0 != 0)
    {
        objs = ObjGroup_GetObjects(36, &count);
        ObjMsg_SendToObjects(0, 3, obj, 17, 0);
        while (count-- != 0)
        {
            ObjGroup_RemoveObject(*objs++, 36);
        }
        return 4;
    }
    return 0;
}

int dbstealerworm_func0B(int obj, u8 msg, int* out);

void DBstealerwo_setFuncPtrs_80203c78(void)
{
    gDBStealerWormStateHandlersA[0] = (int)dbstealerworm_stateHandlerA00;
    gDBStealerWormStateHandlersA[1] = (int)dbstealerworm_stateHandlerA01;
    gDBStealerWormStateHandlersA[2] = (int)dbstealerworm_stateHandlerA02;
    gDBStealerWormStateHandlersA[3] = (int)dbstealerworm_stateHandlerA03;
    gDBStealerWormStateHandlersA[4] = (int)dbstealerworm_stateHandlerA04;
    gDBStealerWormStateHandlersA[5] = (int)dbstealerworm_stateHandlerA05;
    gDBStealerWormStateHandlersA[6] = (int)dbstealerworm_stateHandlerA06;
    gDBStealerWormStateHandlersA[7] = (int)dbstealerworm_stateHandlerA07;
    gDBStealerWormStateHandlersA[8] = (int)dbstealerworm_stateHandlerA08;
    gDBStealerWormStateHandlersA[9] = (int)dbstealerworm_stateHandlerA09;
    gDBStealerWormStateHandlersA[10] = (int)dbstealerworm_stateHandlerA0A;
    gDBStealerWormStateHandlersA[11] = (int)dbstealerworm_stateHandlerA0B;
    gDBStealerWormStateHandlersA[12] = (int)dbstealerworm_stateHandlerA0C;
    gDBStealerWormStateHandlersA[13] = (int)dbstealerworm_stateHandlerA0D;
    gDBStealerWormStateHandlersA[14] = (int)dbstealerworm_stateHandlerA0E;
    gDBStealerWormStateHandlersA[15] = (int)dbstealerworm_stateHandlerA0F;
    gDBStealerWormStateHandlersB[0] = (int)dbstealerworm_stateHandlerB00;
    gDBStealerWormStateHandlersB[1] = (int)dbstealerworm_stateHandlerB01;
    gDBStealerWormStateHandlersB[2] = (int)dbstealerworm_stateHandlerB02;
    gDBStealerWormStateHandlersB[3] = (int)dbstealerworm_stateHandlerB03;
    gDBStealerWormStateHandlersB[4] = (int)dbstealerworm_stateHandlerB04;
    gDBStealerWormStateHandlersB[5] = (int)dbstealerworm_stateHandlerB05;
    gDBStealerWormStateHandlersB[6] = (int)dbstealerworm_stateHandlerB06;
}

int dbstealerworm_stateHandlerA04(int obj, int param2);

int dbstealerworm_stateHandlerA0E(int obj, int param2);

int dbstealerworm_stateHandlerA02(int obj, int p2);

int dbstealerworm_stateHandlerA0D(int obj, int p2);

int dbstealerworm_stateHandlerB05(int obj, int p2);

int dbstealerworm_stateHandlerB06(int obj, int p2);

int dbstealerworm_stateHandlerA0A(int obj, int p2);

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408). */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
