#include "main/game_object.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"
#include "main/objlib.h"

typedef struct DbStealerwormFlags44
{
    u8 b6_7 : 2;
    u8 bit5 : 1;
    u8 bit4 : 1;
    u8 b0_3 : 4;
} DbStealerwormFlags44;

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/resource.h"

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
#include "main/dll/baddie/chuka.h"

typedef struct DbstealerwormPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u32 eventConfigId;
    s16 incrementGameBit;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DbstealerwormPlacement;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern undefined4 FUN_80006824();
extern uint FUN_80006ab8();
extern undefined8 FUN_80006ac4();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined8 FUN_800305f8();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObjectForObject();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4 DAT_8032a290;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
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

extern void Stack_Free(int* stack);
extern void Obj_FreeObject(int obj);
extern void** gBaddieControlInterface;
extern int* gPlayerInterface;
extern f32 lbl_803E62A8;
extern f32 lbl_803E62FC;
extern u8 lbl_80329514[];
extern void* memset(void* dst, int v, int n);
extern int gDBStealerWormStateHandlersA[];
extern void DBstealerwo_setFuncPtrs_80203c78(void);
extern f32 lbl_803E62BC;
extern f32 timeDelta;
extern int dbstealerworm_stateHandlerA02();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerB06();
extern void fn_80202EF0(int obj, int p2);
extern f32 lbl_803E62F4;
extern f32 lbl_803E62E8;
extern f32 lbl_803E62EC;

int dbstealerworm_stateHandlerB04(int obj, int p)
{
    extern int* gPlayerInterface;
    extern f32 lbl_803E62A8;
    float fz;
    int b8;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)p)->moveJustStartedB != '\0')
    {
        (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 1);
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->unk10 = fz;
        ((DbStealerwormControl*)b8)->unk04 = fz;
    }
    return 0;
}

int dbstealerworm_stateHandlerB02(int obj, int p)
{
    extern int* gPlayerInterface;
    extern f32 lbl_803E62A8;
    int b8;
    float fz;
    s8 flag2;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)p)->moveJustStartedB != '\0')
    {
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->unk10 = fz;
        ((DbStealerwormControl*)b8)->unk04 = fz;
        (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 6);
    }
    else
    {
        flag2 = *(char*)&((BaddieState*)p)->moveDone;
        if (flag2 != 0)
        {
            if (((GameObject*)obj)->anim.alpha == 0)
            {
                if (flag2 != 0)
                {
                    return 7;
                }
            }
        }
    }
    return 0;
}

undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 |= 4;
    state->moveSpeed = lbl_803E6F80;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    if (state->moveJustStartedA != '\0')
    {
        control->linkedObj = (int)state->targetObj;
        control->unk1C = 0x24;
        control->unk2C = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            control->linkedObj, 0x11, obj, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(obj, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float invScale;
    uint busy;
    GameObject* targetObj;
    short* hits;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    double dist;
    undefined4 local_48;
    undefined4 local_44;
    undefined4 local_40;
    undefined4 local_3c;
    undefined4 local_38;
    undefined4 local_34;
    undefined4 local_30;
    undefined4 local_2c;
    undefined4 local_28;
    float dx;
    float dy;
    float dz;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    control->flags15 &= 0xfb;
    invScale = lbl_803E6F88;
    state->animSpeedA = state->animSpeedA / lbl_803E6F88;
    state->animSpeedB = state->animSpeedB / invScale;
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 0x1f;
    targetObj = (GameObject*)state->targetObj;
    if ((((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)obj)->anim.localPosY < targetObj->anim.localPosY - lbl_803E6F90))
    {
        dx = targetObj->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        dy = targetObj->anim.localPosY - (((GameObject*)obj)->anim.localPosY + lbl_803E6F94);
        dz = targetObj->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        dist = FUN_80293900((double)(dz * dz + dx * dx + dy * dy));
        if (dist < (double)lbl_803E6F50)
        {
            local_40 = (undefined4)state->targetObj;
            hits = (short*)control->msgStack;
            local_48 = 0xe;
            local_44 = 1;
            busy = FUN_80006ab8(hits);
            if (busy == 0)
            {
                FUN_80006ac4(hits, (uint) & local_48);
            }
            control->unk34 = 1;
        }
    }
    else
    {
        hits = (short*)control->msgStack;
        local_30 = 9;
        local_2c = 0;
        local_28 = 0x24;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & local_30);
        }
        control->unk34 = 1;
        local_34 = (undefined4)state->targetObj;
        hits = (short*)control->msgStack;
        local_3c = 7;
        local_38 = 1;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & local_3c);
        }
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int onFire;
    uint busy;
    short* hits;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;
    undefined4 local_28;
    undefined4 dx;
    undefined4 dy;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    if (state->moveJustStartedA != '\0')
    {
        state->targetObj = 0;
        if (control->linkedObj != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                control->linkedObj, 0x11, obj, 0x10, param_13, param_14, param_15, param_16);
            control->linkedObj = 0;
        }
        onFire = FUN_80017a98();
        onFire = (**(code**)(**(int**)(*(int*)(onFire + 200) + 0x68) + 0x44))();
        if (onFire == 0)
        {
            busy = randomGetRange(0, 2);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + busy * 4));
        }
        else
        {
            busy = randomGetRange(3, 4);
            FUN_80006824(obj, (ushort) * (undefined4*)(&DAT_8032a290 + busy * 4));
        }
        dy = control->unk30;
        dx = control->unk2C;
        hits = (short*)control->msgStack;
        local_28 = control->unk28;
        busy = FUN_80006ab8(hits);
        if (busy == 0)
        {
            FUN_80006ac4(hits, (uint) & local_28);
        }
        control->unk3C = 0;
    }
    state->unk34D = 0x10;
    state->moveSpeed = lbl_803E6FD8;
    state->animSpeedA = lbl_803E6F40;
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_802014c8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 animId;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)obj)->extra;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, animId, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 1;
    control = (DbStealerwormControl*)groundState->control;
    control->flags14 |= 2;
    if ((state->eventFlags & 1) != 0)
    {
        state->eventFlags &= ~1;
        control->flags14 |= 1;
    }
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 lbl_803E62A8;
    BaddieState* bs = (BaddieState*)p;
    DbStealerwormControl* sub_40c;
    int sub_40c_30;
    int frame[3];
    int frame2[3];
    f32 resetValue;

    sub_40c = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    sub_40c_30 = sub_40c->unk30;
    sub_40c->flags14 |= 0x2;
    resetValue = lbl_803E62A8;
    bs->animSpeedA = resetValue;
    bs->animSpeedB = resetValue;
    {
        void* p2d0 = *(void**)&bs->targetObj;
        if (p2d0 == NULL || (**(int (**)(void*))(*(int*)(*(int*)((char*)p2d0 + 0x68)) + 0x20))(p2d0) == 0)
        {
            sub_40c->unk34 = 1;
        }
    }
    if (*(void**)&sub_40c->linkedObj == NULL)
    {
        s16 r26 = sub_40c->unk1C;
        if (r26 != -1)
        {
            int sp_handle;
            int v2c;
            int v30;
            v30 = sub_40c->unk30;
            v2c = sub_40c->unk2C;
            sp_handle = sub_40c->msgStack;
            frame[0] = sub_40c->unk28;
            frame[1] = v2c;
            frame[2] = v30;
            if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame);
            sp_handle = sub_40c->msgStack;
            frame2[0] = 7;
            frame2[1] = 0;
            frame2[2] = r26;
            if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame2);
            sub_40c->unk34 = 1;
            sub_40c->unk1C = -1;
        }
    }
    if ((s32)(bs->eventFlags & 0x200) != 0)
    {
        sub_40c->linkedObj = *(int*)&bs->targetObj;
        sub_40c->unk1C = (s16)sub_40c_30;
        sub_40c->unk2C = 0;
        ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 18);
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
    }
    *(s8*)&bs->unk34D = 18;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 16, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        sub_40c->unk34 = 1;
    }
    return 0;
}

undefined4
FUN_80201658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 animId;
    BaddieState* state;

    state = (BaddieState*)param_10;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    animId = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    state->moveSpeed = lbl_803E6F8C;
    if (state->moveJustStartedA != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, animId, param_13, param_14, param_15, param_16);
        state->moveDone = 0;
    }
    state->unk34D = 1;
    return 0;
}

undefined4
FUN_802017a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    uint animId;
    undefined4 busy;
    BaddieState* state;
    GroundBaddieState* groundState;
    DbStealerwormControl* control;

    state = (BaddieState*)param_10;
    groundState = ((GameObject*)obj)->extra;
    control = (DbStealerwormControl*)groundState->control;
    if (state->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    busy = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (state->moveJustStartedA != '\0')
    {
        animId = randomGetRange(0, 1);
        if (animId == 0)
        {
            if (state->moveJustStartedA != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 7, 0, busy, param_13, param_14, param_15, param_16);
                state->moveDone = 0;
            }
        }
        else if (state->moveJustStartedA != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 6, 0, busy, param_13, param_14, param_15, param_16);
            state->moveDone = 0;
        }
        state->unk34D = 1;
        state->moveSpeed =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint)groundState->aggression) - DOUBLE_803e6f78) / lbl_803E6FE0;
    }
    state->animSpeedA = lbl_803E6F40;
    if (state->moveDone != '\0')
    {
        control->unk34 = 1;
    }
    control->flags14 |= 2;
    return 0;
}

undefined4
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* obj,
             int target)
{
    int yawDelta;
    undefined4 result;
    int control;
    double absDist;
    double signedDist;
    float local_48[5];

    control = *(int*)(obj + 0x5c);
    yawDelta = Obj_GetYawDeltaToObject(obj, target, local_48);
    if ((double)lbl_803E6F40 == param_4)
    {
        result = 0;
    }
    else
    {
        signedDist = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
        absDist = signedDist;
        if (signedDist < (double)lbl_803E6F40)
        {
            absDist = -signedDist;
        }
        if ((double)lbl_803E7008 <= absDist)
        {
            if (signedDist < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(control + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(control + 0x280)) +
                *(float*)(control + 0x280);
            *(float*)(control + 0x284) = lbl_803E6F40;
            result = 0;
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

int dbstealerworm_stateHandlerA06(int obj, int p2)
{
    extern void ObjHits_DisableObject(int);
    extern void ObjGroup_RemoveObject(int, int);
    extern int gameBitIncrement(int);
    extern void Obj_FreeObject(int);
    extern void Stack_Pop(int, int*);
    extern int Stack_IsEmpty(int);
    extern MapEventInterface** gMapEventInterface;
    extern int* gPlayerInterface;
    extern int lbl_80329634[];
    extern int lbl_80329640[];
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6334;
    extern f32 lbl_803E6338;
    extern f32 lbl_803E633C;

    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)p2;

    *(s8*)&bs->unk34D = 0x11;

    if ((s32)(s8)bs->moveJustStartedA != 0
    )
    {
        f32 fz = lbl_803E62A8;
        bs->animSpeedB = fz;
        bs->animSpeedA = fz;
        *(int*)&bs->targetObj = 0;
        bs->physicsActive = 1;
        bs->hasTarget = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
        ObjHits_DisableObject(obj);
        ObjGroup_RemoveObject(obj, 3);
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 16);
            sub_40c->unk1C = -1;
            sub_40c->linkedObj = 0;
        }
    }
    if ((s32)(s8)bs->moveJustStartedA != 0
    )
    {
        ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->moveSpeed = lbl_803E6334;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E6338)
    {
        int local;
        gameBitIncrement(((DbstealerwormPlacement*)data)->incrementGameBit);
        if ((((DbstealerwormPlacement*)data)->eventConfigId + 0x10000) == 0xffff)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        while (Stack_IsEmpty(sub_40c->msgStack) == 0)
        {
            Stack_Pop(sub_40c->msgStack, &local);
        }
        if (((DbstealerwormPlacement*)data)->unk2C == 0)
        {
            (*gMapEventInterface)->
                addTime(*(int*)&((DbstealerwormPlacement*)data)->eventConfigId, lbl_803E633C);
        }
        sub->configFlags |= ((DbstealerwormPlacement*)data)->unk2B;
    }
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))(obj, p2, 0, 2, lbl_80329634);
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
    return 0;
}

undefined4
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* obj,
             int target)
{
    int yawDelta;
    int control;
    double absDy;
    float local_58[7];

    control = *(int*)(obj + 0x5c);
    if ((obj != (ushort*)0x0) && (target != 0))
    {
        yawDelta = Obj_GetYawDeltaToObject(obj, target, local_58);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)local_58[0] < param_1)
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
            *(float*)(control + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)yawDelta ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(control + 0x280)) +
                *(float*)(control + 0x280);
            *(float*)(control + 0x284) = lbl_803E6F40;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA05(int obj, int p)
{
    extern void*Obj_GetPlayerObject(void);
    extern int lbl_80329650[];
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6340;
    BaddieState* bs = (BaddieState*)p;
    DbStealerwormControl* sub_40c;
    int frame[3];

    sub_40c = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        int r;
        int player_c8;
        *(u32*)&bs->targetObj = 0;
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 16);
            sub_40c->linkedObj = 0;
        }
        player_c8 = *(int*)((char*)Obj_GetPlayerObject() + 0xc8);
        r = (**(int (**)(int))(*(int*)(*(int*)(player_c8 + 0x68)) + 0x44))(player_c8);
        if (r != 0)
        {
            Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(3, 4)]);
        }
        else
        {
            Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(0, 2)]);
        }
        {
            int frame1;
            int frame2;
            int sp_handle;
            int frame0;
            frame2 = sub_40c->unk30;
            frame1 = sub_40c->unk2C;
            sp_handle = sub_40c->msgStack;
            frame0 = sub_40c->unk28;
            frame[0] = frame0;
            frame[1] = frame1;
            frame[2] = frame2;
            if (Stack_IsFull(sp_handle) == 0)
            {
                Stack_Push(sp_handle, frame);
            }
        }
        sub_40c->unk3C = 0;
    }
    *(s8*)&bs->unk34D = 16;
    bs->moveSpeed = lbl_803E6340;
    bs->animSpeedA = lbl_803E62A8;
    if (*(s8*)&bs->moveDone != 0)
    {
        sub_40c->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA03(int obj, int p)
{
    extern void ObjHits_EnableObject(int obj);
    extern void ObjHits_SetHitVolumeSlot(int obj, int slot, int a, int b);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62F4;

    if (*(char*)&((BaddieState*)p)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((BaddieState*)p)->moveSpeed = lbl_803E62F4;
    if (*(char*)&((BaddieState*)p)->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E62A8, 0);
        *(s8*)&((BaddieState*)p)->moveDone = 0;
    }
    *(s8*)&((BaddieState*)p)->unk34D = 1;
    return 0;
}

int dbstealerworm_stateHandlerA01(int obj, int p)
{
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    extern int* gPlayerInterface;
    extern int lbl_80329640[];
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E634C;
    BaddieState* bs = (BaddieState*)p;
    GroundBaddieState* sub;
    DbStealerwormControl* sub_40c;
    int p4c;

    sub = ((GameObject*)obj)->extra;
    p4c = *(int*)&((GameObject*)obj)->anim.placementData;
    sub_40c = (DbStealerwormControl*)sub->control;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E634C)
    {
        sub_40c->flags14 |= 0x2;
        ObjHits_DisableObject(obj);
    }
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        bs->moveSpeed = lbl_803E62F4;
        bs->animSpeedA = lbl_803E62A8;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_2);
        sub_40c->unk04 = lbl_803E62C8;
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
        *(u32*)&bs->targetObj = 0;
        bs->physicsActive = 0;
        bs->hasTarget = 0;
        sub->targetState = 0;
        sub->configFlags |= ((DbstealerwormPlacement*)p4c)->unk2B;
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 19);
            sub_40c->linkedObj = 0;
            sub_40c->unk1C = -1;
        }
        if ((sub_40c->flags15 & 0x2) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
        }
        sub_40c->unk34 = 1;
    }
    (**(int (**)(int, int, int, int, int*))(*gPlayerInterface + 0x34))(obj, p, 7, 0, lbl_80329640);
    return 0;
}

void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);

void dbstealerworm_release(void)
{
}


void dbstealerworm_init(int* obj, u8* def, int param3)
{
    extern undefined4 ObjMsg_AllocQueue(); /* #57 */
    extern undefined4 ObjGroup_AddObject(); /* #57 */
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    u8* sub;
    int* p40c;
    u8 mode;
    int r;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (param3 != 0)
    {
        mode |= 1;
    }
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*gBaddieControlInterface)[22])(
        obj, def, sub, 0x10, 7, 0x10a, mode, lbl_803E62FC);
    ObjGroup_AddObject(obj, 3);
    ((GameObject*)obj)->animEventCallback = NULL;
    p40c = *(int**)&((GroundBaddieState*)sub)->control;
    memset(p40c, 0, 0x50);
    ((DbStealerwormControl*)p40c)->unk08 = lbl_803E62FC;
    ((DbStealerwormControl*)p40c)->cfg = (int)&lbl_80329514[((s16) * (s16*)(def + 0x24)) * 8];
    r = randomGetRange(0xa, 0x12c);
    ((DbStealerwormControl*)p40c)->countdown = (f32)(s32)
    r;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->bit5 = def[0x2b] & 1;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->bit4 = 1;
    ((DbStealerwormControl*)p40c)->linkedObj = 0;
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
    ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, sub, 3);
    ((GroundBaddieState*)sub)->baddie.substate = 0;
    ((GroundBaddieState*)sub)->baddie.physicsActive = 1;
    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4008;
    }
}

void dbstealerworm_free(int* obj)
{
    extern undefined8 ObjGroup_RemoveObject(); /* #57 */
    u8* sub = ((GameObject*)obj)->extra;
    int* p40c = *(int**)&((GroundBaddieState*)sub)->control;
    ObjGroup_RemoveObject(obj, 3);
    Stack_Free((int*)((DbStealerwormControl*)p40c)->msgStack);
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(int*)&((GameObject*)obj)->childObjs[0]);
        *(int*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    ((void(*)(int*, u8*, int))((void**)*gBaddieControlInterface)[16])(obj, sub, 3);
}


int dbstealerworm_getExtraSize(void) { return 0x460; }
int dbstealerworm_getObjectTypeId(void) { return 0x49; }

s16 DBstealerworm_setScale(int* obj) { return ((BaddieState*)((int**)obj)[0xb8 / 4])->controlMode; }

void dbstealerworm_hitDetect(int obj)
{
    int* inner = ((GameObject*)obj)->extra;
    (*(void (*)(int, int*, int*))(*(int*)(*gPlayerInterface + 0xc)))(obj, inner, gDBStealerWormStateHandlersA);
}


void dbstealerworm_initialise(void) { DBstealerwo_setFuncPtrs_80203c78(); }

int dbstealerworm_stateHandlerB00(int p1, int p2)
{
    BaddieState* p = (BaddieState*)p2;
    f32 fz;
    if (*(void**)&p->targetObj != NULL)
    {
        if ((s8)p->moveJustStartedB != 0)
        {
            fz = lbl_803E62A8;
            p->animSpeedB = fz;
            p->animSpeedA = fz;
            return 7;
        }
        if ((s8)p->moveDone != 0) return 7;
    }
    return 0;
}

int dbstealerworm_stateHandlerB03(int p1, int p2)
{
    GroundBaddieState* state = ((GameObject*)p1)->extra;
    if ((s8)((BaddieState*)p2)->moveJustStartedB != 0)
    {
        (*(void (**)(int, s16, int, int))((char*)*gBaddieControlInterface + 0x4c))(
            p1, state->unk3F0, -1, 0);
    }
    return 0;
}

int dbstealerworm_stateHandlerB01(int p1, int p2)
{
    GroundBaddieState* state = ((GameObject*)p1)->extra;
    if ((s8)((BaddieState*)p2)->hitPoints < 1) return 3;
    if ((s8)((BaddieState*)p2)->moveDone != 0)
    {
        ((DbStealerwormControl*)state->control)->unk38 += lbl_803E62BC;
        return 7;
    }
    return 0;
}

void fn_80204B6C(int p1);

int dbstealerworm_stateHandlerA00(int obj, int p2)
{
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
    extern int* gPlayerInterface;
    extern int lbl_80329640[];
    extern f32 lbl_803E6350;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6358;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)p2;

    if ((s32)(s8)bs->moveJustStartedA != 0
    )
    {
        bs->physicsActive = 1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
        ((GameObject*)obj)->anim.alpha = 255;
        bs->unk34D = 1;
        bs->moveSpeed = lbl_803E6350 + (f32)(u32)
        sub->aggression / lbl_803E6354;
        ObjHits_EnableObject(obj);
        sub_40c->linkedObj = 0;
        sub_40c->unk1C = -1;
    }
    else
    {
        ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    }

    if ((s32)(s8)bs->moveDone != 0
    )
    {
        sub->targetState = 1;
        sub_40c->unk34 = 1;
    }

    if ((*(int*)&bs->eventFlags & 0x200) != 0)
    {
        *(int*)&bs->eventFlags = *(int*)&bs->eventFlags & ~0x200;
        sub_40c->flags14 = (u8)(sub_40c->flags14 | 0x4);
    }

    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E6358)
    {
        sub_40c->flags14 = (u8)(sub_40c->flags14 | 0x2);
    }

    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
    return 0;
}


int dbstealerworm_func0B(int obj, u8 msg, int* out)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    int result = 0;
    u8 b;
    switch (msg)
    {
    case 0x80:
        break;
    case 0x81:
        b = state->configFlags;
        if ((b & 2) == 0)
        {
            break;
        }
        state->configFlags = b & ~2;
        if (out != 0)
        {
            *out = 1;
        }
        result = 1;
        break;
    case 0x82:
        if (state->baddie.controlMode != 0xb)
        {
            break;
        }
        if (out == 0)
        {
            break;
        }
        sub->unk3C = (int)out;
        result = 1;
        break;
    case 0x83:
        result = sub->unk3C;
        break;
    }
    return result;
}

void DBstealerwo_setFuncPtrs_80203c78(void);

#pragma dont_inline on
void fn_80203000(int obj, int param2)
{
    int i;
    int state = *(int*)(param2 + 0x40c);
    if ((*(u8*)(state + 0x14) & 1) && *(void**)&((GroundBaddieState*)param2)->baddie.targetObj != 0)
    {
        fn_80202EF0(obj, param2);
    }
    if (*(u8*)(state + 0x14) & 2)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 2, -1, NULL);
    }
    if (*(u8*)(state + 0x14) & 4)
    {
        for (i = 0; i < 0xa; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x343, NULL, 1, -1, NULL);
        }
    }
    *(u8*)(state + 0x14) = 0;
}
#pragma dont_inline reset

int dbstealerworm_stateHandlerA04(int obj, int param2)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    BaddieState* bs = (BaddieState*)param2;
    u32 v;
    DbStealerwormControl* sub;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 0xa, 1, -1);
    bs->moveSpeed = lbl_803E62F4;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xa, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 1;
    sub = (DbStealerwormControl*)state->control;
    sub->flags14 = sub->flags14 | 0x2;
    v = bs->eventFlags;
    if (v & 1)
    {
        bs->eventFlags = v & ~1;
        sub->flags14 = sub->flags14 | 0x1;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        sub->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA0E(int obj, int param2)
{
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    BaddieState* bs = (BaddieState*)param2;
    sub->flags14 = sub->flags14 | 0x2;
    sub->flags15 = sub->flags15 | 0x4;
    bs->moveSpeed = lbl_803E62E8;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 0x1f;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        sub->linkedObj = *(int*)&bs->targetObj;
        sub->unk1C = 0x24;
        sub->unk2C = 0;
        ObjMsg_SendToObject(sub->linkedObj, 0x11, obj, 0x12);
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E62EC)
    {
        sub->unk34 = 1;
    }
    return 0;
}

void fn_80202EF0(int obj, int p2)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern u8*Obj_AllocObjectSetup(int, int);
    extern u8*Obj_SetupObject(u8*, int, int, int, int);
    extern f32 lbl_803E637C;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6380;
    u8* setup;
    u8* newObj;
    f32 dur;
    f32 t;

    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x24, 0x30a);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E637C + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        setup[4] = 1;
        setup[5] = 1;
        setup[6] = 0xff;
        setup[7] = 0xff;
        newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
        if (newObj != NULL)
        {
            t = ((BaddieState*)p2)->targetDistance / lbl_803E62B4;
            dur = lbl_803E62B8 * t;
            ((GameObject*)newObj)->anim.velocityX = (*(f32*)(*(int*)&((BaddieState*)p2)->targetObj + 0xc) - ((GameObject
                *)obj)->anim.localPosX) / dur;
            ((GameObject*)newObj)->anim.velocityY = ((lbl_803E6380 * t + *(f32*)(*(int*)&((BaddieState*)p2)->targetObj +
                0x10)) - ((GameObject*)obj)->anim.localPosY) / dur;
            ((GameObject*)newObj)->anim.velocityZ = (*(f32*)(*(int*)&((BaddieState*)p2)->targetObj + 0x14) - ((
                GameObject*)obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)newObj)->ownerObj = obj;
        }
    }
}

#pragma opt_common_subs off
#pragma dont_inline on
int fn_80202C78(int obj, int p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(int, int, f32*);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6370;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    BaddieState* state = ((GameObject*)obj)->extra;
    f32 yawF;
    int yaw;
    f32 zero;
    f32 a;
    f32 ratio;
    f32 k;
    f32 cur;
    f32 prod;

    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4)
    {
        return 0;
    }
    yawF -= p1;
    ratio = yawF / p4;
    yawF = ratio;
    if (ratio >= zero)
    {
        a = ratio;
    }
    else
    {
        a = -ratio;
    }
    if (a < lbl_803E6370)
    {
        return 1;
    }
    if (ratio < lbl_803E62A8)
    {
        p2 = -p2;
    }
    cur = state->animSpeedA;
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)
    yaw / lbl_803E6374
    )
    ;
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}
#pragma dont_inline reset
#pragma opt_common_subs reset

#pragma dont_inline on
int fn_80202DA4(u8* obj, u8* p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(u8*, u8*, f32*);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6378;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    BaddieState* state = ((GameObject*)obj)->extra;
    f32 yawF;
    int yaw;
    f32 dy;
    f32 zero;
    f32 k;
    f32 cur;
    f32 prod;

    if (obj == NULL || p6 == NULL)
    {
        return 0;
    }
    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4)
    {
        return 0;
    }
    if (yawF < p1)
    {
        dy = ((GameObject*)obj)->anim.localPosY - *(f32*)(p6 + 0x10);
        if (dy >= zero) {} else { dy = -dy; }
        if (dy < lbl_803E6378)
        {
            return 1;
        }
    }
    cur = state->animSpeedA;
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)
    yaw / lbl_803E6374
    )
    ;
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}

#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2)
{
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6344;
    extern f32 lbl_803E6348;
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    BaddieState* bs = (BaddieState*)p2;

    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        if ((int)randomGetRange(0, 1) != 0)
        {
            if (*(s8*)&bs->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E62A8, 0);
                bs->moveDone = 0;
            }
        }
        else
        {
            if (*(s8*)&bs->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E62A8, 0);
                bs->moveDone = 0;
            }
        }
        bs->unk34D = 1;
        bs->moveSpeed = lbl_803E6344 + (f32)state->aggression / lbl_803E6348;
    }
    bs->animSpeedA = lbl_803E62A8;
    if (*(s8*)&bs->moveDone != 0)
    {
        sub->unk34 = 1;
    }
    sub->flags14 |= 2;
    return 0;
}

void dbstealerworm_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void fn_8003B5E0(int, int, int, int);
    extern void objParticleFn_80099d84(int, f32, int, f32, int);
    extern void ObjPath_GetPointWorldPosition(int, int, char*, char*, char*, int);
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C8;
    DbStealerwormControl* sub;
    GroundBaddieState* state;
    char* path;

    state = ((GameObject*)obj)->extra;
    sub = (DbStealerwormControl*)state->control;
    if (*(void**)&sub->linkedObj != NULL)
    {
        *(f32*)(sub->linkedObj + 0xc) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(sub->linkedObj + 0x10) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(sub->linkedObj + 0x14) = ((GameObject*)obj)->anim.localPosZ;
        *(f32*)(sub->linkedObj + 0x10) += lbl_803E62D0;
    }
    if (visible != 0 && ((GameObject*)obj)->unkF4 == 0 && state->targetState != 0)
    {
        {
            if (state->unk3E8 != lbl_803E62A8)
            {
                fn_8003B5E0(0xc8, 0, 0, (int)state->unk3E8);
            }
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E62C8);
            if ((state->flags400 & 0x60) != 0)
            {
                objParticleFn_80099d84(obj, lbl_803E62C8, 3, state->unk3E8, 0);
            }
            path = *(char**)&sub->linkedObj;
            if (path != NULL && *(void**)(path + 0x50) != NULL)
            {
                ObjPath_GetPointWorldPosition(obj, 3, path + 0xc, path + 0x10, path + 0x14, 0);
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(
                    sub->linkedObj, p2, p3, p4, p5, lbl_803E62C8);
            }
        }
    }
}

int dbstealerworm_stateHandlerA0D(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62F0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62EC;
    extern f32 lbl_803E62F8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E62B8;
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    BaddieState* bs = (BaddieState*)p2;
    int q;
    int tmp;
    f32 v;
    f32 d;
    struct
    {
        int msgE[3];
        int msg7[3];
        int msg9[3];
        f32 pos[3];
    } stk;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    v = bs->animSpeedA;
    d = lbl_803E62F0;
    bs->animSpeedA = v / d;
    bs->animSpeedB = bs->animSpeedB / d;
    bs->moveSpeed = lbl_803E62F4;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 0x1f;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E62EC
        && *(f32*)(*(int*)&bs->targetObj + 0x10) - lbl_803E62F8 <= ((GameObject*)obj)->anim.localPosY)
    {
        q = sub->msgStack;
        stk.msg9[0] = 9;
        stk.msg9[1] = 0;
        stk.msg9[2] = 0x24;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, stk.msg9);
        }
        sub->unk34 = 1;
        tmp = *(int*)&bs->targetObj;
        q = sub->msgStack;
        stk.msg7[0] = 7;
        stk.msg7[1] = 1;
        stk.msg7[2] = tmp;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, stk.msg7);
        }
        sub->unk34 = 1;
    }
    else
    {
        stk.pos[0] = ((GameObject*)obj)->anim.localPosX;
        stk.pos[1] = ((GameObject*)obj)->anim.localPosY;
        stk.pos[2] = ((GameObject*)obj)->anim.localPosZ;
        stk.pos[1] = stk.pos[1] + lbl_803E62FC;
        stk.pos[0] = *(f32*)(*(int*)&bs->targetObj + 0xc) - stk.pos[0];
        stk.pos[1] = *(f32*)(*(int*)&bs->targetObj + 0x10) - stk.pos[1];
        stk.pos[2] = *(f32*)(*(int*)&bs->targetObj + 0x14) - stk.pos[2];
        if (sqrtf(stk.pos[2] * stk.pos[2] + (stk.pos[0] * stk.pos[0] + stk.pos[1] * stk.pos[1])) < lbl_803E62B8)
        {
            tmp = *(int*)&bs->targetObj;
            q = sub->msgStack;
            stk.msgE[0] = 0xe;
            stk.msgE[1] = 1;
            stk.msgE[2] = tmp;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, stk.msgE);
            }
            sub->unk34 = 1;
        }
    }
    return 0;
}

typedef struct
{
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
} AnimFlags44;

int dbstealerworm_stateHandlerB05(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int*);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32*);
    extern int* gPlayerInterface;
    extern int lbl_803296FC[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    GroundBaddieState* tmp = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int base;
    int n;
    u32 found;
    int i;
    int* p;
    u32 o;
    int buf[3];
    f32 range;

    range = lbl_803E62AC;
    sub = (DbStealerwormControl*)tmp->control;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedB != 0 || ((u32)sub->flags44 >> 6 & 1) != 0)
    {
        sub->flags15 &= ~4;
        ((AnimFlags44*)&sub->flags44)->flag40 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, buf);
        }
        base = sub->cfg;
        n = (sub->unk20 - *(int*)base) / 12;
        if (n >= *(s16*)(base + 4))
        {
            sub->unk20 = 0;
        }
        if (*(void**)&sub->unk20 == NULL)
        {
            sub->unk20 = *(int*)sub->cfg;
            ((GameObject*)obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->unk8;
            ((GameObject*)obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->unkC;
            ((GameObject*)obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->unk10;
        }
        if (*(int*)(sub->unk20 + 4) != 0)
        {
            *(int*)&((BaddieState*)p2)->targetObj = ObjGroup_FindNearestObjectForObject(
                *(int*)(sub->unk20 + 4), obj, &range);
        }
        if (*(void**)&((BaddieState*)p2)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, p2, *(int*)sub->unk20);
        }
        return 0;
    }
    else
    {
        f32 t;
        if (*(void**)&sub->linkedObj == NULL && (t = sub->unk38) > lbl_803E62B0)
        {
            sub->unk38 = t - lbl_803E62B0;
            range = lbl_803E62B4;
            i = 3;
            found = 0;
            p = &lbl_803296FC[3];
            for (; p--, --i >= 0;)
            {
                o = ObjGroup_FindNearestObjectForObject(*p, obj, &range);
                if (o != 0)
                {
                    found = o;
                }
            }
            *(int*)&((BaddieState*)p2)->targetObj = found;
            if (found != 0)
            {
                if (range < lbl_803E62B8)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, p2, 2);
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, p2, 4);
                }
            }
        }
    }
    return 0;
}

void fn_80203144(int obj, int p2, int p3)
{
    extern int ObjGroup_FindNearestObject(int, int, f32*);
    extern void ObjGroup_AddObject(int, int);
    extern void*Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int, u16);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern void** gBaddieControlInterface;
    extern int lbl_80329640[];
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6384;
    extern f32 timeDelta;
    GroundBaddieState* st = (GroundBaddieState*)p2;
    DbStealerwormControl* sub = (DbStealerwormControl*)st->control;
    u32 near;
    int data;
    char* player;
    f32 dist;
    struct
    {
        f32 range;
        f32 d[3];
    } stk;

    stk.range = lbl_803E62B0;
    data = *(int*)&((GameObject*)obj)->anim.placementData;
    near = (**(u32 (**)(int, int, f32, int))((char*)*gBaddieControlInterface + 0x48))(
        obj, p3, (f32)st->aggroRange, 0x8000);
    if (near == 0 && (st->configFlags & 0x10) != 0)
    {
        near = ObjGroup_FindNearestObject(0x24, obj, &stk.range);
    }
    if (near == 0 && (st->configFlags & 0x10) != 0 && (st->configFlags & 2) == 0 && (*(u8*)(data + 0x2b) & 2) != 0)
    {
        near = ObjGroup_FindNearestObject(0x24, obj, 0);
    }
    if (near != 0 && (st->configFlags & 2) == 0)
    {
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)*gBaddieControlInterface + 0x28))(
            obj, p3, p2 + 0x35c, st->gameBitB, 0, 0, 0, 8, -1);
        *(int*)&((BaddieState*)p3)->targetObj = near;
        ((BaddieState*)p3)->hasTarget = 0;
        ObjGroup_AddObject(obj, 3);
        *(u16*)&st->targetState = 1;
    }
    else
    {
        player = Obj_GetPlayerObject();
        if (player != NULL)
        {
            stk.d[0] = *(f32*)(player + 0x18) - ((GameObject*)obj)->anim.worldPosX;
            stk.d[1] = *(f32*)(player + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
            stk.d[2] = *(f32*)(player + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        }
        else
        {
            dist = lbl_803E6354;
        }
        if (sub->countdown > sub->unk10 && dist < lbl_803E6384)
        {
            Sfx_PlayFromObject(obj, (u16)lbl_80329640[1]);
            sub->unk10 = sub->unk10 + (f32)(int)
            randomGetRange(0x32, 0xfa);
        }
        sub->countdown += timeDelta;
    }
}


int fn_80202A2C(int obj, int* objs, f32* weights, int n, f32 limit)
{
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32*);
    extern f32 mathSinf(f32);
    extern f32 mathCosf(f32);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E635C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6360;
    extern f32 lbl_803E6364;
    int* po;
    f32* pw;
    BaddieState* state = ((GameObject*)obj)->extra;
    int i;
    f32 rangeInit;
    f32 accX;
    f32 accZ;
    u32 o;
    f32 k;
    f32 scale;
    f32 cosv;
    f32 sinv;
    f32 neg;
    f32 v;
    struct
    {
        f32 range;
        f32 d[3];
    } stk;

    accX = lbl_803E62A8;
    accZ = *(f32 *)&lbl_803E62A8;
    i = 0;
    po = objs;
    pw = weights;
    rangeInit = lbl_803E635C;
    for (; i < n; i++)
    {
        stk.range = rangeInit;
        o = ObjGroup_FindNearestObjectForObject(*po, obj, &stk.range);
        if (o != 0)
        {
            if (stk.range == lbl_803E62A8)
            {
                return 0;
            }
            k = lbl_803E62C8 - stk.range / lbl_803E635C;
            k = k * k;
            k = k * k;
            stk.d[0] = ((GameObject*)o)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            stk.d[1] = ((GameObject*)o)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
            stk.d[2] = ((GameObject*)o)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
            scale = lbl_803E62C8 / stk.range;
            stk.d[0] *= scale;
            stk.d[1] *= scale;
            stk.d[2] *= scale;
            accX = accX - limit * (stk.d[0] * k * *pw);
            accZ = accZ - limit * (stk.d[2] * k * *pw);
        }
        po++;
        pw++;
    }
    cosv = mathSinf(lbl_803E6360 * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6364);
    sinv = mathCosf(lbl_803E6360 * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6364);
    state->animSpeedB = state->animSpeedB + (accX * sinv - accZ * cosv);
    state->animSpeedA = state->animSpeedA + (-accZ * sinv - accX * cosv);
    v = state->animSpeedA;
    neg = -limit;
    if (v < neg)
    {
        v = neg;
    }
    else if (v > limit)
    {
        v = limit;
    }
    state->animSpeedA = v;
    v = state->animSpeedB;
    state->animSpeedB = (v < neg) ? neg : (v > limit) ? limit : v;
    return 0;
}


int dbstealerworm_stateHandlerB06(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int*);
    extern void Stack_Push(int, int*);
    extern void Obj_FreeObject(int);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32*);
    extern int ObjGroup_ContainsObject(int, int);
    extern int* gPlayerInterface;
    extern u8 lbl_80329514[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62A8;
    GroundBaddieState* tmp = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int off;
    int n;
    char* entry;
    char* ptr;
    f32 range;

    range = lbl_803E62AC;
    sub = (DbStealerwormControl*)tmp->control;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedB != 0 || sub->unk34 != 0)
    {
        sub->flags15 &= ~4;
        sub->unk34 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, (int*)&sub->unk28);
        }
        else
        {
            if (((DbstealerwormPlacement*)data)->eventConfigId == 0xFFFFFFFF)
            {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = (char*)&lbl_80329514[((DbstealerwormPlacement*)data)->unk24 * 8];
            n = *(s16*)(entry + 4);
            off = n * 12;
            while (n != 0)
            {
                n--;
                Stack_Push(sub->msgStack, (int*)(*(int*)entry + (off -= 12)));
            }
            sub->unk34 = 1;
            ((GameObject*)obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->unk8;
            ((GameObject*)obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->unkC;
            ((GameObject*)obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->unk10;
        }
        switch (sub->unk2C)
        {
        case 0:
            if (sub->unk30 != 0)
            {
                *(int*)&((BaddieState*)p2)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, &range);
            }
            break;
        case 1:
            *(int*)&((BaddieState*)p2)->targetObj = sub->unk30;
            break;
        }
        if (*(void**)&((BaddieState*)p2)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, p2, *(int*)&sub->unk28);
        }
        return 0;
    }
    else
    {
        switch (sub->unk2C)
        {
        case 0:
            if (*(void**)&((BaddieState*)p2)->targetObj == NULL)
            {
                sub->unk34 = 1;
            }
            else if (sub->unk30 != 0)
            {
                if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)p2)->targetObj, sub->unk30) == 0)
                {
                    *(int*)&((BaddieState*)p2)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, 0);
                    if (*(void**)&((BaddieState*)p2)->targetObj == NULL)
                    {
                        sub->unk34 = 1;
                    }
                    ((BaddieState*)p2)->animSpeedA = lbl_803E62A8;
                }
            }
            break;
        case 1:
            if (*(void**)&((BaddieState*)p2)->targetObj == NULL)
            {
                sub->unk34 = 1;
            }
            break;
        }
        if (sub->unk1C == -1 && (ptr = *(char**)&sub->unk3C) != NULL)
        {
            if ((**(int (**)(char*))(*(int*)(*(int*)(ptr + 0x68)) + 0x20))(ptr) == 0)
            {
                sub->unk3C = 0;
                sub->unk34 = 1;
            }
        }
        return 0;
    }
}

#pragma opt_propagation off
int dbstealerworm_stateHandlerA0A(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern int Obj_GetYawDeltaToObject(int, int, f32*);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6310;
    extern f32 lbl_803E6314;
    extern f32 lbl_803E6318;
    extern f32 lbl_803E631C;
    extern f32 lbl_803E6320;
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    int c30 = sub->unk30;
    int c2c = sub->unk2C;
    int tmpB;
    int tmpA;
    int t;
    int q;
    f32 z;
    f32 dist;
    struct
    {
        f32 v[3];
        f32 out[3];
    } stk;
    int msgA[3];
    int msgB[3];
    int msgC[3];

    z = lbl_803E62A8;
    ((BaddieState*)p2)->animSpeedA = lbl_803E62A8;
    ((BaddieState*)p2)->animSpeedB = z;
    sub->flags14 |= 2;
    if (*(void**)&sub->linkedObj == NULL && sub->unk1C != -1)
    {
        tmpB = sub->unk2C;
        tmpA = sub->unk30;
        q = sub->msgStack;
        msgA[0] = sub->unk28;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgA);
        }
        q = sub->msgStack;
        msgB[0] = 8;
        msgB[1] = c2c;
        msgB[2] = c30;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgB);
        }
        sub->unk34 = 1;
        tmpA = sub->unk1C;
        q = sub->msgStack;
        msgC[0] = 9;
        msgC[1] = 0;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgC);
        }
        sub->unk34 = 1;
        return 0;
    }
    else
    {
        sub->flags15 |= 4;
        if (*(void**)&sub->linkedObj != NULL && (int)(((BaddieState*)p2)->eventFlags & 0x200) != 0)
        {
            t = *(int*)&((BaddieState*)p2)->targetObj;
            stk.v[0] = *(f32*)(t + 0xc) - ((GameObject*)obj)->anim.localPosX;
            stk.v[1] = *(f32*)(t + 0x10) - ((GameObject*)obj)->anim.localPosY;
            stk.v[2] = *(f32*)(t + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(stk.v[0] * stk.v[0] + stk.v[2] * stk.v[2]);
            stk.v[1] = stk.v[1] * lbl_803E6310;
            dist = dist / lbl_803E6314;
            stk.out[1] = -(dist * (lbl_803E6318 * dist) - stk.v[1]) / dist;
            stk.out[1] = stk.out[1] * lbl_803E631C;
            stk.out[0] = lbl_803E62A8;
            stk.out[2] = lbl_803E6320;
            ObjMsg_SendToObject(sub->linkedObj, 0x11, obj, 0x11);
            (**(void (**)(int, f32*))(*(int*)(*(int*)(sub->linkedObj + 0x68)) + 0x24))(sub->linkedObj, stk.out);
            sub->linkedObj = 0;
            sub->unk1C = -1;
        }
        ((GameObject*)obj)->anim.rotX += Obj_GetYawDeltaToObject(obj, *(int*)&((BaddieState*)p2)->targetObj, 0);
        ((BaddieState*)p2)->unk34D = 0x11;
        if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x12, lbl_803E62A8, 0);
            ((BaddieState*)p2)->moveDone = 0;
        }
        if (*(s8*)&((BaddieState*)p2)->moveDone != 0)
        {
            sub->unk34 = 1;
        }
        return 0;
    }
}
#pragma opt_propagation reset

int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern int ObjGroup_ContainsObject(int, int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern int ObjGroup_FindNearestObject(int, int, f32*);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32*);
    extern int*seqFn_800394a0(void);
    extern s16*objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern int lbl_8032971C[];
    extern f32 lbl_8032972C[];
    GroundBaddieState* blob = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int c30 = sub->unk30;
    int tmpA;
    int tmpB;
    int i;
    int found;
    int q;
    int* objs;
    int player;
    int d;
    int flag;
    int zero;
    int* ptr;
    s16* vec;
    f32 frac;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    int msgE[3];
    int msgF[3];
    int msgG[3];
    int msgH[3];
    int msgI[3];
    int cnt1;
    int cnt2;
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)p2)->targetObj, c30) == 0)
    {
        ObjGroup_GetObjects(c30, &cnt1);
        if (cnt1 == 0)
        {
            player = Obj_GetPlayerObject();
            q = sub->msgStack;
            msg0[0] = 0xf;
            msg0[1] = 1;
            msg0[2] = player;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msg0);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    q = *(int*)&((BaddieState*)p2)->targetObj;
    found = 0;
    objs = ObjGroup_GetObjects(3, &cnt2);
    for (i = 0; i < cnt2; i++)
    {
        if (*(s16*)(*objs + 0x46) == 0x539)
        {
            if ((u32)(**(int (**)(int, int, int))(*(int*)(*(int*)(*objs + 0x68)) + 0x24))(*objs, 0x83, 0) == (u32)q)
            {
                found = 1;
            }
        }
        objs++;
    }
    if (found == 0)
    {
        if ((u32)obj == (u32)ObjGroup_FindNearestObject(3, *(int*)&((BaddieState*)p2)->targetObj, 0))
        {
            sub->unk3C = *(int*)&((BaddieState*)p2)->targetObj;
            tmpB = sub->unk2C;
            tmpA = sub->unk30;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 0xc;
            msgB[1] = 0;
            msgB[2] = 3;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            q = sub->msgStack;
            msgC[0] = 9;
            msgC[1] = 0;
            msgC[2] = c30;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgC);
            }
            sub->unk34 = 1;
            tmpA = sub->unk3C;
            q = sub->msgStack;
            msgD[0] = 7;
            msgD[1] = 1;
            msgD[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    sub = (DbStealerwormControl*)blob->control;
    ((BaddieState*)p2)->unk34D = 0x1f;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
        ((BaddieState*)p2)->moveDone = 0;
    }
    if (*(void**)&sub->unk3C != NULL)
    {
        if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)p2)->targetObj, c30) != 0)
        {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgE[0] = sub->unk28;
            msgE[1] = tmpB;
            msgE[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgE);
            }
            q = sub->msgStack;
            msgF[0] = 0xc;
            msgF[1] = 0;
            msgF[2] = 3;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgF);
            }
            sub->unk34 = 1;
            tmpA = sub->unk3C;
            q = sub->msgStack;
            msgG[0] = 0xd;
            msgG[1] = 1;
            msgG[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgG);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    frac = (f32)blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int*)&((BaddieState*)p2)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032971C, lbl_8032972C, 4, frac);
    }
    player = Obj_GetPlayerObject();
    d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
    flag = 0;
    if (d >= 0)
    {
    }
    else
    {
        d = -d;
    }
    if (d < 0x1c71 && yawf < lbl_803E62D0)
    {
        flag = 1;
    }
    if (flag != 0)
    {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
        player = Obj_GetPlayerObject();
        *(int*)&((BaddieState*)p2)->targetObj = player;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgH[0] = sub->unk28;
        msgH[1] = tmpB;
        msgH[2] = tmpA;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgH);
        }
        q = sub->msgStack;
        msgI[0] = 2;
        msgI[1] = 0;
        msgI[2] = 0;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgI);
        }
        sub->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern int RandomTimer_UpdateRangeTrigger(void*, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32*);
    extern int*seqFn_800394a0(void);
    extern s16*objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern f32 lbl_803E632C;
    extern f32 lbl_803E6330;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    GroundBaddieState* blob = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    s16 h;
    register int q;
    register int* ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16* vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    Sfx_KeepAliveLoopedObjectSound(obj, 0x441);
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_ClearHitVolumes(obj);
    ((BaddieState*)p2)->moveSpeed = lbl_803E62F4;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->unk1C;
        if (h != -1)
        {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
        if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
            ((BaddieState*)p2)->moveDone = 0;
        }
        frac = (f32)blob->aggression / lbl_803E62C4;
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer4C, lbl_803E62C8, lbl_803E632C) != 0)
        {
            Sfx_PlayFromObject(obj, 0x43f);
        }
    }
    else
    {
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer48, lbl_803E62C8, lbl_803E632C) != 0)
        {
            Sfx_PlayFromObject(obj, 0x440);
        }
        if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)p2)->moveDone = 0;
        }
        ((BaddieState*)p2)->moveSpeed = lbl_803E6300;
        frac = (f32)blob->aggression / lbl_803E6324;
    }
    ((BaddieState*)p2)->unk34D = 0x1f;
    if (fn_80202DA4((u8*)obj, *(u8**)&((BaddieState*)p2)->targetObj, lbl_803E6330, frac, lbl_803E62CC, t) != 0)
    {
        sub->unk34 = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        d = (d >= 0) ? d : -d;
        if (d < 0x1c71 && yawf < lbl_803E62D0)
        {
            flag = 1;
        }
        if (flag != 0)
        {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++)
            {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0)
                {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int*)&((BaddieState*)p2)->targetObj = player;
            tmp2A = sub->unk30;
            tmp2B = sub->unk2C;
            q = sub->msgStack;
            msgC[0] = sub->unk28;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgC);
            }
            q = sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0)
    {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = -(lbl_803E6328 * ((BaddieState*)p2)->animSpeedA);
        flag = -(lbl_803E6328 * ((BaddieState*)p2)->animSpeedB);
        d = (s16)d;
        if (d < -0x500)
        {
            d = -0x500;
        }
        else if (d > 0x500)
        {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500)
        {
            flag = -0x500;
        }
        else if (flag > 0x500)
        {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)p2)->animSpeedA,
                                                                        (float*)(p2 + 0x2a0));
    return 0;
}

#pragma opt_loop_invariants off
void dbstealerworm_update(u8* objp)
{
    extern void Stack_Push(int sp, int* args);
    extern int allocModelStruct_800139e8(int, int);
    extern uint GameBit_Get(int);
    extern void ObjGroup_AddObject(int, int);
    extern int ObjMsg_Pop(int, u32*, int*, int*);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern f32 sqrtf(f32);
    extern MapEventInterface** gMapEventInterface;
    extern void** gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E6388;
    extern f32 lbl_803E638C;
    extern u8 lbl_803AD0C0[];
    extern u8 lbl_803293B8[];
    char* st = (char*)lbl_803AD0C0;
    char* tbl = (char*)lbl_803293B8;
    int blob = *(int*)(objp + 0xb8);
    int data = *(int*)(objp + 0x4c);
    int sub = *(int*)&((GroundBaddieState*)blob)->control;
    int obj = (int)objp;
    int off;
    char* entry;
    int n;
    int sub2;
    int sub3;
    int t;
    struct
    {
        u32 msg;
        int argA;
        int argB;
        f32 v[3];
    } stk;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    if ((u32)((DbStealerwormControl*)sub)->flags44 >> 4 & 1)
    {
        entry = (char*)((int)(tbl + *(s16*)(data + 0x24) * 8) + 0x15c);
        ((DbStealerwormControl*)sub)->msgStack = allocModelStruct_800139e8(0x14, 0xc);
        n = *(s16*)(entry + 4);
        off = n * 0xc;
        for (; n != 0; n--)
        {
            Stack_Push(((DbStealerwormControl*)sub)->msgStack, (int*)(*(int*)entry + (off -= 12)));
        }
        ((DbStealerwormControl*)sub)->unk34 = 1;
        ((AnimFlags44*)&((DbStealerwormControl*)sub)->flags44)->flag10 = 0;
    }
    if (GameBit_Get(((GroundBaddieState*)blob)->gameBitC) != 0)
    {
        if (((GameObject*)obj)->unkF4 != 0)
        {
            if ((((GroundBaddieState*)blob)->configFlags & 4) == 0 &&
                (*gMapEventInterface)->shouldNotSaveTime(*(int*)(data + 0x14)) != 0)
            {
                ((void (*)(int, int, int, int, int, int, int, f32))((void**)*gBaddieControlInterface)[22])(
                    obj, data, blob, 0x10, 7, 0x10a, 0x26, lbl_803E62FC);
                ObjGroup_AddObject(obj, 3);
                ((GroundBaddieState*)blob)->targetState = 0;
                ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0x10);
                ((GroundBaddieState*)blob)->baddie.moveDone = 0;
                ((GameObject*)obj)->anim.alpha = 0xff;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->anim.localPosX = *(f32*)(data + 8);
            ((GameObject*)obj)->anim.localPosY = *(f32*)(data + 0xc);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)(data + 0x10);
            (*gObjectTriggerInterface)->runSequence(*(s8*)(data + 0x2e), (void*)obj, -1);
            ((GameObject*)obj)->unkF8 = 1;
        }
        else
        {
            if (((int (*)(int, int, int))((void**)*gBaddieControlInterface)[12])(obj, blob, 0) == 0)
            {
                ((GroundBaddieState*)blob)->targetState = 0;
            }
            else
            {
                t = *(int*)&((GroundBaddieState*)blob)->baddie.targetObj;
                if (*(void**)&((GroundBaddieState*)blob)->baddie.targetObj != NULL)
                {
                    stk.v[0] = *(f32*)(t + 0x18) - ((GameObject*)obj)->anim.worldPosX;
                    stk.v[1] = *(f32*)(t + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
                    stk.v[2] = *(f32*)(t + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
                    ((GroundBaddieState*)blob)->baddie.targetDistance = sqrtf(
                        stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
                while (ObjMsg_Pop(obj, &stk.msg, &stk.argB, &stk.argA) != 0)
                {
                    if (stk.msg == 0x11 && ((DbStealerwormControl*)sub2)->unk1C != -1)
                    {
                        ObjMsg_SendToObject(((DbStealerwormControl*)sub2)->linkedObj, 0x11, obj, 0x14);
                        ((DbStealerwormControl*)sub2)->linkedObj = 0;
                        ((DbStealerwormControl*)sub2)->unk1C = -1;
                        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
                    }
                }
                if (((int (*)(int, int, int, int, char*, char*, int, char*))((void**)*gBaddieControlInterface)[20])(
                    obj, blob, blob + 0x35c, ((GroundBaddieState*)blob)->gameBitB, tbl + 0x2ac, tbl + 0x324, 1,
                    st) != 0)
                {
                    *(f32*)(st + 0xc) = ((GameObject*)obj)->anim.localPosX;
                    *(f32*)(st + 0x10) = ((GameObject*)obj)->anim.localPosY;
                    ((GroundBaddieState*)st)->baddie.posX = ((GameObject*)obj)->anim.localPosZ;
                    objLightFn_8009a1dc((void*)obj, lbl_803E638C, st, 1, 0);
                }
                if (((GroundBaddieState*)blob)->targetState == 0)
                {
                    fn_80203144(obj, blob, blob);
                }
                else
                {
                    sub3 = *(int*)&((GroundBaddieState*)blob)->control;
                    fn_80203000(obj, blob);
                    ((void (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[11])(obj, blob, lbl_803E6388, -1);
                    if ((((DbStealerwormControl*)sub3)->flags15 & 4) == 0)
                    {
                        ((void (*)(int, int, f32, int))((void**)*(int*)gPlayerInterface)[12])(obj, blob, timeDelta, 4);
                    }
                    ((GroundBaddieState*)blob)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
                    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
                    ((void (*)(int, int, f32, f32, int, int))((void**)*(int*)gPlayerInterface)[2])(
                        obj, blob, timeDelta, timeDelta, (int)(st + 0x34), (int)(st + 0x18));
                    *(int*)&((GameObject*)obj)->pendingParentObj = ((GroundBaddieState*)blob)->savedObjC0;
                }
            }
        }
    }
}
#pragma opt_loop_invariants reset

int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32*);
    extern int*seqFn_800394a0(void);
    extern s16*objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    GroundBaddieState* blob = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    s16 h;
    int q;
    int* ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16* vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
        ObjHits_ClearHitVolumes(obj);
    }
    ((BaddieState*)p2)->moveSpeed = lbl_803E62F4;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->unk1C;
        if (h != -1)
        {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
    }
    else
    {
        if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)p2)->moveDone = 0;
        }
        ((BaddieState*)p2)->moveSpeed = lbl_803E6300;
        frac = (f32)blob->aggression / lbl_803E6324;
    }
    ((BaddieState*)p2)->unk34D = 0x1f;
    if (fn_80202C78(obj, *(int*)&((BaddieState*)p2)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t) != 0)
    {
        sub->unk34 = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        d = (d >= 0) ? d : -d;
        if (d < 0x1c71 && yawf < lbl_803E62D0)
        {
            flag = 1;
        }
        if (flag != 0)
        {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++)
            {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0)
                {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int*)&((BaddieState*)p2)->targetObj = player;
            tmp2A = sub->unk30;
            tmp2B = sub->unk2C;
            q = sub->msgStack;
            msgC[0] = sub->unk28;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgC);
            }
            q = sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0)
    {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = -(lbl_803E6328 * ((BaddieState*)p2)->animSpeedA);
        flag = -(lbl_803E6328 * ((BaddieState*)p2)->animSpeedB);
        d = (s16)d;
        if (d < -0x500)
        {
            d = -0x500;
        }
        else if (d > 0x500)
        {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500)
        {
            flag = -0x500;
        }
        else if (flag > 0x500)
        {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)p2)->animSpeedA,
                                                                        (float*)(p2 + 0x2a0));
    return 0;
}

void fn_80204BF8(int obj);

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void fn_80137948(char*, ...);
    extern int Obj_GetPlayerObject(void);
    extern int*ObjGroup_GetObjects(int, int*);
    extern f32 Vec_xzDistance(int, int);
    extern f32 vec3f_distanceSquared(int, int);
    extern f32 sqrtf(f32);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6304;
    extern f32 lbl_803E6308;
    extern f32 lbl_803E630C;
    extern f32 lbl_803E62CC;
    extern u8 lbl_803293B8[];
    char* tbl = (char*)lbl_803293B8;
    GroundBaddieState* blob = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int c30 = sub->unk30;
    s16 h;
    int n;
    int q;
    int* objs;
    int player;
    int o;
    int best;
    int i;
    int tmpB;
    int tmpA;
    f32 frac;
    f32 ratio;
    f32 ds;
    f32 bestD;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int cnt;

    sub->flags15 &= ~4;
    sub->flags14 |= 2;
    fn_80137948(tbl + 0x430, sub->unk3C, sub->linkedObj);
    if (*(void**)&sub->unk3C == NULL)
    {
        player = Obj_GetPlayerObject();
        q = sub->msgStack;
        msg0[0] = 0xf;
        msg0[1] = 1;
        msg0[2] = player;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msg0);
        }
        sub->unk34 = 1;
        return 0;
    }
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        ((BaddieState*)p2)->moveDone = 0;
    }
    ((BaddieState*)p2)->moveSpeed = lbl_803E6300;
    frac = (f32)blob->aggression / lbl_803E62B8;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->unk1C;
        if (h != -1)
        {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0)
            {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, (int*)(tbl + 0x344), (f32*)(tbl + 0x354), 4, frac);
    }
    player = Obj_GetPlayerObject();
    ratio = (Vec_xzDistance(obj + 0x18, player + 0x18) - lbl_803E6304) / (lbl_803E6308 * (f32)blob->aggression);
    n = (int)(ratio < lbl_803E62A8 ? lbl_803E62A8 : (ratio > lbl_803E62B0 ? lbl_803E62B0 : ratio));
    fn_80137948(tbl + 0x444, n);
    player = Obj_GetPlayerObject();
    best = 0;
    bestD = lbl_803E62A8;
    objs = ObjGroup_GetObjects(c30, &cnt);
    for (i = 0; i < cnt; i++)
    {
        o = *objs;
        if ((u32)o != (u32)player)
        {
            ds = vec3f_distanceSquared(player + 0x18, o + 0x18);
            if (ds > bestD)
            {
                bestD = ds;
                best = *objs;
            }
        }
        objs++;
    }
    if ((u32)best != 0)
    {
        sqrtf(bestD);
    }
    if ((u32)best != 0)
    {
        if ((u32)best != (u32)obj)
        {
            if (*(s16*)(best + 0x46) == 0x539)
            {
                *(int*)&((BaddieState*)p2)->targetObj = best;
                if (randomGetRange(0, n) == 0)
                {
                    if ((**(int (**)(int, int, int))(*(int*)(*(int*)(best + 0x68)) + 0x24))(best, 0x82, sub->linkedObj)
                        != 0)
                    {
                        sub->unk3C = 0;
                        q = sub->msgStack;
                        msgC[0] = 0xa;
                        msgC[1] = 1;
                        msgC[2] = best;
                        if (Stack_IsFull(q) == 0)
                        {
                            Stack_Push(q, msgC);
                        }
                        sub->unk34 = 1;
                    }
                }
                else
                {
                    fn_80202C78(obj, best, lbl_803E630C, frac, lbl_803E62CC, t);
                }
            }
        }
    }
    return 0;
}

void chuka_update(int obj);

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 Vec_xzDistance(int, int);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C0;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62D4;
    extern f32 lbl_803E62D8;
    extern int lbl_8032973C[];
    extern f32 lbl_8032974C[];
    GroundBaddieState* blob = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int n = 0x1f40 / blob->aggression;
    int tmpA;
    int tmpB;
    int q;
    int target;
    f32 frac;
    f32 d;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (*(u16*)(*(int*)&((BaddieState*)p2)->targetObj + 0xb0) & 0x1000)
    {
        ((BaddieState*)p2)->animSpeedA = lbl_803E62A8;
        ((BaddieState*)p2)->animSpeedB = lbl_803E62A8;
        ((BaddieState*)p2)->moveSpeed = lbl_803E62C0;
        return 0;
    }
    frac = (f32)blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int*)&((BaddieState*)p2)->targetObj, lbl_803E62C8, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032973C, lbl_8032974C, 4, frac);
    }
    d = Vec_xzDistance(obj + 0x18, *(int*)&((BaddieState*)p2)->targetObj + 0x18);
    ((BaddieState*)p2)->unk34D = 1;
    if (d < lbl_803E62D0)
    {
        {
            f32 k = lbl_803E62D4;
            ((BaddieState*)p2)->animSpeedA *= k;
            ((BaddieState*)p2)->animSpeedB *= k;
        }
        target = *(int*)&((BaddieState*)p2)->targetObj;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgA[0] = sub->unk28;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgA);
        }
        q = sub->msgStack;
        msgB[0] = 2;
        msgB[1] = 1;
        msgB[2] = target;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgB);
        }
        sub->unk34 = 1;
        return 0;
    }
    if (d < lbl_803E62D8 && randomGetRange(0, n) == 0)
    {
        ((BaddieState*)p2)->animSpeedA = lbl_803E62A8;
        ((BaddieState*)p2)->animSpeedB = lbl_803E62A8;
        target = *(int*)&((BaddieState*)p2)->targetObj;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgC[0] = sub->unk28;
        msgC[1] = tmpB;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgC);
        }
        q = sub->msgStack;
        msgD[0] = 4;
        msgD[1] = 1;
        msgD[2] = target;
        if (Stack_IsFull(q) == 0)
        {
            Stack_Push(q, msgD);
        }
        sub->unk34 = 1;
        return 0;
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)p2)->animSpeedA,
                                                                        (float*)(p2 + 0x2a0));
    return 0;
}


/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
