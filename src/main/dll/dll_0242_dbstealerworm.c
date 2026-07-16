/*
 * dbstealerworm (DLL 0x242, object type id 0x49) - a burrowing "stealer
 * worm" ground baddie.
 *
 * It is a GroundBaddieState/BaddieState baddie driven through the shared
 * baddie-control interface (gBaddieControlInterface). Per-object state is
 * extraSize 0x460 = the 0x410 GroundBaddieState plus a 0x50 private
 * DbStealerwormControl record hung off GroundBaddieState.control (memset
 * to zero in dbstealerworm_init).
 *
 * Behaviour is a move/transition state machine: the A00..A0F handlers
 * (gDBStealerWormStateHandlersA, invoked from hitDetect/update) run the
 * burrow / surface / lunge / grab / steal / flee moves, while the B00..B06
 * handlers gate transitions between them. The worm surfaces and lunges at a
 * target, links to a grabbed object (DbStealerwormControl.linkedObj) via
 * ObjMsg, plays the ice-run footstep sfx, spawns burrow/impact particle fx
 * (fn_80203000), and on a successful steal increments a placement game bit
 * and adds map time (dbstealerworm_stateHandlerA06). chuka is the linked
 * thrown sub-object.
 *
 * Unimplemented trailing functions (not in scope here):
 *   Trivial 0-returner.
 *   Trivial 0-returner.
 *   if (p6) objRenderModelAndHitVolumes(lbl_803E6408).
 *   if (b->_8 && (b->_8->_6 & 0x40)) clear.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/objfx_api.h"
#include "main/objanim.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/object_render_legacy.h"
#include "main/debug.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/dfp_types.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/player_control_interface.h"
#include "main/objprint_api.h"
#include "main/vecmath.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0243_dbholecontrol1.h"
#include "main/dll/dll_0242_dbstealerworm.h"
#include "main/dll/dll_022C_dll22c.h"
#include "main/dll/DF/dll_0229_dfplevelcontrol.h"
#include "main/dll/DF/dll_022A_dfpobjcreator.h"
#include "main/dll/DF/dll_022E_dfpdoorswitch.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "string.h"

#define ObjGroup_FindNearestObjectForObjectLegacy(group, obj, distance) \
    ((int (*)())ObjGroup_FindNearestObjectForObject)((group), (obj), (distance))
#define Obj_GetYawDeltaToObjectLegacy(obj, target, distance) \
    ((s16 (*)())Obj_GetYawDeltaToObject)((obj), (target), (distance))
typedef f32 (*VecXzDistanceIntFn)(int a, int b);
#define Vec_xzDistanceInt ((VecXzDistanceIntFn)Vec_xzDistance)

typedef struct DbstealerwormPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;              /* 0x04 */
    u8 unk5;              /* 0x05 */
    u8 unk6;              /* 0x06 */
    u8 unk7;              /* 0x07 */
    f32 homePosX;         /* 0x08: worm home/spawn position */
    f32 homePosY;         /* 0x0C */
    f32 homePosZ;         /* 0x10 */
    u32 eventConfigId;    /* 0x14: 0xFFFFFFFF = no map-event config */
    s16 incrementGameBit; /* 0x18: game bit bumped on a successful steal */
    s16 unk1A;            /* 0x1A */
    s16 unk1C;            /* 0x1C */
    s16 unk1E;            /* 0x1E */
    s16 unk20;            /* 0x20 */
    u8 pad22[0x24 - 0x22];
    s16 cfgTableIndex; /* 0x24: index into the per-worm config table (entry stride 8) */
    u8 pad26[0x2B - 0x26];
    u8 configFlags;          /* 0x2B: config flag bits OR'd into the state's configFlags */
    s16 disableMapEventTime; /* 0x2C: nonzero suppresses the on-activate addTime() map-event grant */
    s8 seqId;                /* 0x2E: sequence run when activated */
    u8 pad2F[0x30 - 0x2F];
} DbstealerwormPlacement;

STATIC_ASSERT(sizeof(DbstealerwormPlacement) == 0x30);

typedef struct DbStealerwormFlags44
{
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
    u8 low : 4;
} DbStealerwormFlags44;

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
extern u32 lbl_80329514[];
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E62A8 = 0.0f;
#pragma explicit_zero_data off

int fn_80202C78(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused, f32 range);
int fn_80202DA4(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused, f32 range);
int fn_80202A2C(GameObject* obj, int* objs, f32* weights, int n, f32 limit);

int dbstealerworm_stateHandlerB06(GameObject* obj, int baddie)
{

    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub;
    int data = *(int*)&(obj)->anim.placementData;
    int count;
    char* entry;
    char* ptr;
    f32 range;

    range = 1500.0f;
    sub = (DbStealerwormControl*)state->control;
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedB != 0 || sub->msgAdvance != 0)
    {
        sub->flags15 &= ~4;
        sub->msgAdvance = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, &sub->msgCode);
        }
        else
        {
            if (((DbstealerwormPlacement*)data)->eventConfigId == 0xFFFFFFFF)
            {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = (char*)&lbl_80329514[((DbstealerwormPlacement*)data)->cfgTableIndex * 2];
            count = *(s16*)(entry + 4);
            for (; count != 0;)
            {
                Stack_Push(sub->msgStack, (int*)(*(int*)entry + --count * 12));
            }
            sub->msgAdvance = 1;
            (obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->homePosX;
            (obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->homePosY;
            (obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->homePosZ;
        }
        switch (sub->msgMode)
        {
        case 0:
            if (sub->objGroup != 0)
            {
                *(int*)&((BaddieState*)baddie)->targetObj =
                    ObjGroup_FindNearestObjectForObject(sub->objGroup, (int)obj, &range);
            }
            break;
        case 1:
            *(int*)&((BaddieState*)baddie)->targetObj = sub->objGroup;
            break;
        }
        if (*(void**)&((BaddieState*)baddie)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))((int)obj, baddie, *(int*)&sub->msgCode);
        }
        return 0;
    }
    else
    {
        switch (sub->msgMode)
        {
        case 0:
            if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
            {
                sub->msgAdvance = 1;
            }
            else if (sub->objGroup != 0)
            {
                if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, sub->objGroup) == 0)
                {
                    *(int*)&((BaddieState*)baddie)->targetObj =
                        ObjGroup_FindNearestObjectForObject(sub->objGroup, (int)obj, 0);
                    if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
                    {
                        sub->msgAdvance = 1;
                    }
                    ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
                }
            }
            break;
        case 1:
            if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
            {
                sub->msgAdvance = 1;
            }
            break;
        }
        if (sub->msgSlotIndex == -1 && (ptr = *(char**)&sub->savedTargetObj) != NULL)
        {
            if ((**(int (**)(char*))(*(int*)(*(int*)(ptr + 0x68)) + 0x20))(ptr) == 0)
            {
                sub->savedTargetObj = 0;
                sub->msgAdvance = 1;
            }
        }
        return 0;
    }
}

int dbstealerworm_stateHandlerB05(GameObject* obj, int baddie)
{
    extern int lbl_803296FC[];
    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub;
    int data = *(int*)&(obj)->anim.placementData;
    int base;
    int routeIndex;
    u32 found;
    int i;
    int* p;
    u32 nearest;
    int buf[3];
    f32 range;

    range = 1500.0f;
    sub = (DbStealerwormControl*)state->control;
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedB != 0 || ((u32)sub->flags44 >> 6 & 1) != 0)
    {
        sub->flags15 &= ~4;
        ((DbStealerwormFlags44*)&sub->flags44)->flag40 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, buf);
        }
        base = sub->cfg;
        routeIndex = (sub->routeCursor - *(int*)base) / 12;
        if (routeIndex >= *(s16*)(base + 4))
        {
            sub->routeCursor = 0;
        }
        if (*(void**)&sub->routeCursor == NULL)
        {
            sub->routeCursor = *(int*)sub->cfg;
            (obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->homePosX;
            (obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->homePosY;
            (obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->homePosZ;
        }
        if (*(int*)(sub->routeCursor + 4) != 0)
        {
            *(int*)&((BaddieState*)baddie)->targetObj =
                ObjGroup_FindNearestObjectForObject(*(int*)(sub->routeCursor + 4), (int)obj, &range);
        }
        if (*(void**)&((BaddieState*)baddie)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))((int)obj, baddie,
                                                                              *(int*)sub->routeCursor);
        }
        return 0;
    }
    else
    {
        f32 t;
        if (*(void**)&sub->linkedObj == NULL && (t = sub->spawnAccumulator) > 100.0f)
        {
            sub->spawnAccumulator = t - 100.0f;
            range = 200.0f;
            i = 3;
            found = 0;
            p = &lbl_803296FC[3];
            for (; p--, --i >= 0;)
            {
                nearest = ObjGroup_FindNearestObjectForObject(*p, (int)obj, &range);
                if (nearest != 0)
                {
                    found = nearest;
                }
            }
            *(int*)&((BaddieState*)baddie)->targetObj = found;
            if (found != 0)
            {
                if (range < 50.0f)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))((int)obj, baddie, 2);
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))((int)obj, baddie, 4);
                }
            }
        }
    }
    return 0;
}

#define DBSTEALERWORM_OBJGROUP 3
#define DBEGG_OBJGROUP         0x24

/* projectile spat at the baddie target: velocity aimed at targetObj, ownerObj = worm */
#define DBSTEALERWORM_CHILD_OBJ_PROJECTILE 0x30a

/* small dust burst (spawned 3x when DBWORM_FLAG14_FX_DUST is set) */
#define DBSTEALERWORM_PARTFX_DUST 0x345
/* spray burst (spawned 10x when DBWORM_FLAG14_FX_SPRAY is set) */
#define DBSTEALERWORM_PARTFX_SPRAY 0x343

/* hit-volume slot reconfigured across the worm's movement states */
#define DBSTEALERWORM_HIT_VOLUME_SLOT 10

extern void** gBaddieControlInterface;
extern int lbl_80329634[];
extern int lbl_80329640[];
extern int gDbStealerwormSfxIds[];
extern u8 lbl_803AD0C0[];
extern u32 lbl_803293B8[];

int dbstealerworm_stateHandlerB04(int obj, int baddie)
{
    float fz;
    int b8;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)baddie)->moveJustStartedB != '\0')
    {
        (**(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, baddie, 1);
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->nextSfxTime = fz;
        ((DbStealerwormControl*)b8)->unk04 = fz;
    }
    return 0;
}

int dbstealerworm_stateHandlerB03(int obj, int baddie)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    if ((s8)((BaddieState*)baddie)->moveJustStartedB != 0)
    {
        (*(void (**)(int, s16, int, int))((char*)*gBaddieControlInterface + 0x4c))(obj, state->triggerId, -1, 0);
    }
    return 0;
}

int dbstealerworm_stateHandlerB02(int obj, int baddie)
{
    int b8;
    float fz;
    s8 flag2;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)baddie)->moveJustStartedB != '\0')
    {
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->nextSfxTime = fz;
        ((DbStealerwormControl*)b8)->unk04 = fz;
        (**(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, baddie, 6);
    }
    else
    {
        flag2 = *(char*)&((BaddieState*)baddie)->moveDone;
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

int dbstealerworm_stateHandlerB01(GameObject* obj, int baddie)
{
    GroundBaddieState* state = obj->extra;
    if ((s8)((BaddieState*)baddie)->hitPoints < 1)
        return 3;
    if ((s8)((BaddieState*)baddie)->moveDone != 0)
    {
        ((DbStealerwormControl*)state->control)->spawnAccumulator += 170.0f;
        return 7;
    }
    return 0;
}

int dbstealerworm_stateHandlerB00(int obj, int baddie)
{
    BaddieState* p = (BaddieState*)baddie;
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
        if ((s8)p->moveDone != 0)
            return 7;
    }
    return 0;
}


int dbstealerworm_stateHandlerA0F(GameObject* obj, int baddie, f32 t)
{
    extern int lbl_8032973C[];
    extern f32 lbl_8032974C[];
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int n = 0x1f40 / blob->aggression;
    int tmpB;
    int tmpA;
    int tmpD;
    int tmpC;
    f32 frac;
    f32 d;
    f32 k;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    if (((GameObject*)((BaddieState*)baddie)->targetObj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)
    {
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
        ((BaddieState*)baddie)->moveSpeed = 0.001f;
        return 0;
    }
    frac = blob->aggression / 40.0f;
    fn_80202C78(obj, ((BaddieState*)baddie)->targetObj, 1.0f, frac, 0.2f, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032973C, lbl_8032974C, 4, frac);
    }
    d = Vec_xzDistanceInt((int)obj + 0x18, (int)&((GameObject*)((BaddieState*)baddie)->targetObj)->anim.worldPosX);
    ((BaddieState*)baddie)->stateTag = 1;
    if (d < 30.0f)
    {
        ((BaddieState*)baddie)->animSpeedA = ((BaddieState*)baddie)->animSpeedA * (k = 0.5f);
        ((BaddieState*)baddie)->animSpeedB *= k;
        obj = (GameObject*)*(int*)&((BaddieState*)baddie)->targetObj;
        tmpA = sub->objGroup;
        tmpB = sub->msgMode;
        baddie = (int)sub->msgStack;
        msgA[0] = sub->msgCode;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0)
        {
            Stack_Push((RingBufferQueue*)baddie, msgA);
        }
        baddie = (int)sub->msgStack;
        msgB[0] = 2;
        msgB[1] = 1;
        msgB[2] = (int)obj;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0)
        {
            Stack_Push((RingBufferQueue*)baddie, msgB);
        }
        sub->msgAdvance = 1;
        return 0;
    }
    if (d < 150.0f && randomGetRange(0, n) == 0)
    {
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
        obj = (GameObject*)*(int*)&((BaddieState*)baddie)->targetObj;
        tmpC = sub->objGroup;
        tmpD = sub->msgMode;
        baddie = (int)sub->msgStack;
        msgC[0] = sub->msgCode;
        msgC[1] = tmpD;
        msgC[2] = tmpC;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0)
        {
            Stack_Push((RingBufferQueue*)baddie, msgC);
        }
        baddie = (int)sub->msgStack;
        msgD[0] = 4;
        msgD[1] = 1;
        msgD[2] = (int)obj;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0)
        {
            Stack_Push((RingBufferQueue*)baddie, msgD);
        }
        sub->msgAdvance = 1;
        return 0;
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}

int dbstealerworm_stateHandlerA0E(GameObject* obj, int baddie)
{
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    BaddieState* bs = (BaddieState*)baddie;
    sub->flags14 = sub->flags14 | DBWORM_FLAG14_FX_DUST;
    sub->flags15 = sub->flags15 | 0x4;
    bs->moveSpeed = 0.02f;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->stateTag = 0x1f;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        sub->linkedObj = *(int*)&bs->targetObj;
        sub->msgSlotIndex = 0x24;
        sub->msgMode = 0;
        ObjMsg_SendToObject((void*)sub->linkedObj, 0x11, obj, 0x12);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_mn_dimspit6);
    }
    if ((obj)->anim.currentMoveProgress > 0.3f)
    {
        sub->msgAdvance = 1;
    }
    return 0;
}
#pragma fp_contract off
#pragma opt_common_subs off
#pragma opt_propagation off
int dbstealerworm_stateHandlerA0D(GameObject* obj, int baddie)
{
    extern f32 lbl_803E62FC;
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&obj->extra)->control;
    BaddieState* bs = (BaddieState*)baddie;
    int targetObj;
    f32 v;
    f32 d;
    struct
    {
        int msgE[3];
        int msg7[3];
        int msg9[3];
        f32 pos[3];
    } stk;

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    v = bs->animSpeedA;
    d = 1.5f;
    bs->animSpeedA = v / d;
    bs->animSpeedB = bs->animSpeedB / d;
    bs->moveSpeed = 0.01f;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->stateTag = 0x1f;
    if (obj->anim.currentMoveProgress > 0.3f &&
        ((GameObject*)bs->targetObj)->anim.localPosY - 5.0f <= obj->anim.localPosY)
    {
        obj = (GameObject*)sub->msgStack;
        stk.msg9[0] = 9;
        stk.msg9[1] = 0;
        stk.msg9[2] = 0x24;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0)
        {
            Stack_Push((RingBufferQueue*)obj, stk.msg9);
        }
        sub->msgAdvance = 1;
        targetObj = *(int*)&bs->targetObj;
        obj = (GameObject*)sub->msgStack;
        stk.msg7[0] = 7;
        stk.msg7[1] = 1;
        stk.msg7[2] = targetObj;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0)
        {
            Stack_Push((RingBufferQueue*)obj, stk.msg7);
        }
        sub->msgAdvance = 1;
        return 0;
    }
    else
    {
        stk.pos[0] = obj->anim.localPosX;
        stk.pos[1] = obj->anim.localPosY;
        stk.pos[2] = obj->anim.localPosZ;
        stk.pos[1] = stk.pos[1] + lbl_803E62FC;
        stk.pos[0] = ((GameObject*)bs->targetObj)->anim.localPosX - stk.pos[0];
        stk.pos[1] = ((GameObject*)bs->targetObj)->anim.localPosY - stk.pos[1];
        stk.pos[2] = ((GameObject*)bs->targetObj)->anim.localPosZ - stk.pos[2];
        if (sqrtf(stk.pos[2] * stk.pos[2] + (stk.pos[0] * stk.pos[0] + stk.pos[1] * stk.pos[1])) < 50.0f)
        {
            targetObj = *(int*)&bs->targetObj;
            obj = (GameObject*)sub->msgStack;
            stk.msgE[0] = 0xe;
            stk.msgE[1] = 1;
            stk.msgE[2] = targetObj;
            if (Stack_IsFull((RingBufferQueue*)obj) == 0)
            {
                Stack_Push((RingBufferQueue*)obj, stk.msgE);
            }
            sub->msgAdvance = 1;
        }
    }
    return 0;
}
#pragma fp_contract reset
#pragma opt_propagation reset
__declspec(section ".sdata2") f32 lbl_803E62FC = 20.0f;
int dbstealerworm_stateHandlerA0C(GameObject* obj, int baddie, f32 t)
{
    char* tbl = (char*)lbl_803293B8;
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int c30 = sub->objGroup;
    s16 h;
    int n;
    int q;
    int* objs;
    int best;
    int player;
    int o;
    int* cursor;
    int i;
    int tmpB;
    int tmpA;
    f32 bestD;
    f32 frac;
    f32 ratio;
    f32 ds;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int cnt;

    sub->flags15 &= ~4;
    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    logPrintf(tbl + 0x430, sub->savedTargetObj, sub->linkedObj);
    if (*(void**)&sub->savedTargetObj == NULL)
    {
        player = (int)Obj_GetPlayerObject();
        obj = (GameObject*)sub->msgStack;
        msg0[0] = 0xf;
        msg0[1] = 1;
        msg0[2] = player;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0)
        {
            Stack_Push((RingBufferQueue*)obj, msg0);
        }
        sub->msgAdvance = 1;
        return 0;
    }
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        ((BaddieState*)baddie)->moveDone = 0;
    }
    ((BaddieState*)baddie)->moveSpeed = 0.018f;
    frac = blob->aggression / 50.0f;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->msgSlotIndex;
        if (h != -1)
        {
            tmpA = sub->objGroup;
            tmpB = sub->msgMode;
            q = (int)sub->msgStack;
            msgA[0] = sub->msgCode;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgA);
            }
            q = (int)sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgB);
            }
            sub->msgAdvance = 1;
            sub->msgSlotIndex = -1;
        }
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, (int*)(tbl + 0x344), (f32*)(tbl + 0x354), 4, frac);
    }
    player = (int)Obj_GetPlayerObject();
    ratio = (Vec_xzDistanceInt((int)obj + 0x18, player + 0x18) - 60.0f) / (0.05f * blob->aggression);
    n = (int)(ratio < lbl_803E62A8 ? lbl_803E62A8 : (ratio > 100.0f ? 100.0f : ratio));
    logPrintf(tbl + 0x444, n);
    player = (int)Obj_GetPlayerObject();
    best = 0;
    bestD = lbl_803E62A8;
    objs = (int*)ObjGroup_GetObjects(c30, &cnt);
    for (i = 0, cursor = objs; i < cnt; i++)
    {
        o = *cursor;
        if ((u32)o != player)
        {
            ds = vec3f_distanceSquared((f32*)(player + 0x18), (f32*)(o + 0x18));
            if (ds > bestD)
            {
                bestD = ds;
                best = *cursor;
            }
        }
        cursor++;
    }
    if ((u32)best != 0)
    {
        sqrtf(bestD);
    }
    if ((u32)best != 0)
    {
        if ((u32)best != (u32)obj)
        {
            if (((GameObject*)best)->anim.seqId == 0x539)
            {
                *(int*)&((BaddieState*)baddie)->targetObj = best;
                if (randomGetRange(0, n) == 0)
                {
                    if ((**(int (**)(int, int, int))(*(int*)(*(int*)(best + 0x68)) + 0x24))(best, 0x82,
                                                                                            sub->linkedObj) != 0)
                    {
                        sub->savedTargetObj = 0;
                        objs = (int*)sub->msgStack;
                        msgC[0] = 0xa;
                        msgC[1] = 1;
                        msgC[2] = best;
                        if (Stack_IsFull((RingBufferQueue*)objs) == 0)
                        {
                            Stack_Push((RingBufferQueue*)objs, msgC);
                        }
                        sub->msgAdvance = 1;
                    }
                }
                else
                {
                    fn_80202C78(obj, (GameObject*)best, 204.0f, frac, 0.2f, t);
                }
            }
        }
    }
    return 0;
}
#pragma opt_common_subs reset

int dbstealerworm_stateHandlerA0B(GameObject* obj, int baddie, f32 t)
{

    extern int lbl_8032971C[];
    extern f32 lbl_8032972C[];
    GroundBaddieState* blob = (obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int c30 = sub->objGroup;
    int tmpA;
    int tmpB;
    int i;
    int found;
    int q;
    int* objs;
    GameObject* player;
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

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, c30) == 0)
    {
        ObjGroup_GetObjects(c30, &cnt1);
        if (cnt1 == 0)
        {
            player = Obj_GetPlayerObject();
            q = (int)sub->msgStack;
            msg0[0] = 0xf;
            msg0[1] = 1;
            msg0[2] = (int)player;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msg0);
            }
            sub->msgAdvance = 1;
            return 0;
        }
    }
    q = *(int*)&((BaddieState*)baddie)->targetObj;
    found = 0;
    objs = (int*)ObjGroup_GetObjects(DBSTEALERWORM_OBJGROUP, &cnt2);
    for (i = 0; i < cnt2; i++)
    {
        if (((GameObject*)*objs)->anim.seqId == 0x539)
        {
            if (q == (u32)(**(int (**)(int, int, int))(*(int*)(*(int*)(*objs + 0x68)) + 0x24))(*objs, 0x83, 0))
            {
                found = 1;
            }
        }
        objs++;
    }
    if (found == 0)
    {
        if ((u32)obj ==
            ObjGroup_FindNearestObject(DBSTEALERWORM_OBJGROUP, *(int*)&((BaddieState*)baddie)->targetObj, 0))
        {
            sub->savedTargetObj = *(int*)&((BaddieState*)baddie)->targetObj;
            {
                RingBufferQueue* qA;
                int tmpB;
                int tmpA;
                tmpA = sub->objGroup;
                tmpB = sub->msgMode;
                qA = sub->msgStack;
                msgA[0] = sub->msgCode;
                msgA[1] = tmpB;
                msgA[2] = tmpA;
                if (Stack_IsFull(qA) == 0)
                {
                    Stack_Push(qA, msgA);
                }
            }
            {
                RingBufferQueue* qB;
                qB = sub->msgStack;
                msgB[0] = 0xc;
                msgB[1] = 0;
                msgB[2] = 3;
                if (Stack_IsFull(qB) == 0)
                {
                    Stack_Push(qB, msgB);
                }
            }
            sub->msgAdvance = 1;
            {
                RingBufferQueue* qC;
                qC = sub->msgStack;
                msgC[0] = 9;
                msgC[1] = 0;
                msgC[2] = c30;
                if (Stack_IsFull(qC) == 0)
                {
                    Stack_Push(qC, msgC);
                }
            }
            sub->msgAdvance = 1;
            {
                RingBufferQueue* qD;
                int tD;
                tD = sub->savedTargetObj;
                qD = sub->msgStack;
                msgD[0] = 7;
                msgD[1] = 1;
                msgD[2] = tD;
                if (Stack_IsFull(qD) == 0)
                {
                    Stack_Push(qD, msgD);
                }
            }
            sub->msgAdvance = 1;
            return 0;
        }
    }
    sub = (DbStealerwormControl*)blob->control;
    ((BaddieState*)baddie)->stateTag = 0x1f;
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
        ((BaddieState*)baddie)->moveDone = 0;
    }
    if (*(void**)&sub->savedTargetObj != NULL)
    {
        if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, c30) != 0)
        {
            {
                RingBufferQueue* qE;
                int tEb;
                int tEa;
                tEa = sub->objGroup;
                tEb = sub->msgMode;
                qE = sub->msgStack;
                msgE[0] = sub->msgCode;
                msgE[1] = tEb;
                msgE[2] = tEa;
                if (Stack_IsFull(qE) == 0)
                {
                    Stack_Push(qE, msgE);
                }
            }
            {
                RingBufferQueue* qF;
                qF = sub->msgStack;
                msgF[0] = 0xc;
                msgF[1] = 0;
                msgF[2] = 3;
                if (Stack_IsFull(qF) == 0)
                {
                    Stack_Push(qF, msgF);
                }
            }
            sub->msgAdvance = 1;
            {
                RingBufferQueue* qG;
                int tG;
                tG = sub->savedTargetObj;
                qG = sub->msgStack;
                msgG[0] = 0xd;
                msgG[1] = 1;
                msgG[2] = tG;
                if (Stack_IsFull(qG) == 0)
                {
                    Stack_Push(qG, msgG);
                }
            }
            sub->msgAdvance = 1;
            return 0;
        }
    }
    frac = blob->aggression / 40.0f;
    fn_80202C78(obj, ((BaddieState*)baddie)->targetObj, 200.0f, frac, 0.2f, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032971C, lbl_8032972C, 4, frac);
    }
    player = Obj_GetPlayerObject();
    d = Obj_GetYawDeltaToObject(obj, player, &yawf);
    flag = 0;
    if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < 30.0f)
    {
        flag = 1;
    }
    if (flag != 0)
    {
        ptr = seqFn_800394a0();
        zero = 0;
        for (q = 1, ptr = ptr + 1; q < 9; ptr++, q++)
        {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
        }
        player = Obj_GetPlayerObject();
        ((BaddieState*)baddie)->targetObj = player;
        {
            RingBufferQueue* qH;
            int tHb;
            int tHa;
            tHa = sub->objGroup;
            tHb = sub->msgMode;
            qH = sub->msgStack;
            msgH[0] = sub->msgCode;
            msgH[1] = tHb;
            msgH[2] = tHa;
            if (Stack_IsFull(qH) == 0)
            {
                Stack_Push(qH, msgH);
            }
        }
        {
            RingBufferQueue* qI;
            qI = sub->msgStack;
            msgI[0] = 2;
            msgI[1] = 0;
            msgI[2] = 0;
            if (Stack_IsFull(qI) == 0)
            {
                Stack_Push(qI, msgI);
            }
        }
        sub->msgAdvance = 1;
    }
    return 0;
}
__declspec(section ".sdata2") f32 lbl_803E6310 = 0.015625f;
#pragma opt_common_subs off
int dbstealerworm_stateHandlerA0A(GameObject* obj, int baddie)
{
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    int c30 = sub->objGroup;
    int c2c = sub->msgMode;
    int tmpB;
    int tmpA;
    int target;
    RingBufferQueue* msgStack;
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
    ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
    ((BaddieState*)baddie)->animSpeedB = z;
    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    if (*(void**)&sub->linkedObj == NULL && sub->msgSlotIndex != -1)
    {
        tmpA = sub->objGroup;
        tmpB = sub->msgMode;
        msgStack = sub->msgStack;
        msgA[0] = sub->msgCode;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(msgStack) == 0)
        {
            Stack_Push(msgStack, msgA);
        }
        msgStack = sub->msgStack;
        msgB[0] = 8;
        msgB[1] = c2c;
        msgB[2] = c30;
        if (Stack_IsFull(msgStack) == 0)
        {
            Stack_Push(msgStack, msgB);
        }
        sub->msgAdvance = 1;
        tmpA = sub->msgSlotIndex;
        msgStack = sub->msgStack;
        msgC[0] = 9;
        msgC[1] = 0;
        msgC[2] = tmpA;
        if (Stack_IsFull(msgStack) == 0)
        {
            Stack_Push(msgStack, msgC);
        }
        sub->msgAdvance = 1;
        return 0;
    }
    else
    {
        sub->flags15 |= 4;
        if (*(void**)&sub->linkedObj != NULL && (s32)(((BaddieState*)baddie)->eventFlags & BADDIE_EVENT_LANDING) != 0)
        {
            target = *(int*)&((BaddieState*)baddie)->targetObj;
            stk.v[0] = ((GameObject*)target)->anim.localPosX - (obj)->anim.localPosX;
            stk.v[1] = ((GameObject*)target)->anim.localPosY - (obj)->anim.localPosY;
            stk.v[2] = ((GameObject*)target)->anim.localPosZ - (obj)->anim.localPosZ;
            {
                f32 sqx = stk.v[0] * stk.v[0];
                f32 sqz = stk.v[2] * stk.v[2];
                dist = sqrtf(sqx + sqz);
            }
            stk.v[1] = stk.v[1] * lbl_803E6310;
            dist = dist / 140.0f;
            stk.out[1] = -(dist * (-1.7f * dist) - stk.v[1]) / dist;
            stk.out[1] *= 1.0666667f;
            stk.out[0] = lbl_803E62A8;
            stk.out[2] = 2.3333333f;
            ObjMsg_SendToObject((void*)sub->linkedObj, 0x11, obj, 0x11);
            (**(void (**)(int, f32*))(*(int*)(*(int*)(sub->linkedObj + 0x68)) + 0x24))(sub->linkedObj, stk.out);
            sub->linkedObj = 0;
            sub->msgSlotIndex = -1;
        }
        obj->anim.rotX +=
            Obj_GetYawDeltaToObjectLegacy((int)obj, *(int*)&((BaddieState*)baddie)->targetObj, 0);
        ((BaddieState*)baddie)->stateTag = 0x11;
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x12, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        if (*(s8*)&((BaddieState*)baddie)->moveDone != 0)
        {
            sub->msgAdvance = 1;
        }
        return 0;
    }
}
#pragma opt_common_subs reset

int dbstealerworm_stateHandlerA09(GameObject* obj, int baddie)
{
    BaddieState* bs = (BaddieState*)baddie;
    DbStealerwormControl* sub_40c;
    int slotIndex;
    int frame[3];
    int frame2[3];
    f32 resetValue;

    sub_40c = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    slotIndex = sub_40c->objGroup;
    sub_40c->flags14 |= DBWORM_FLAG14_FX_DUST;
    resetValue = lbl_803E62A8;
    bs->animSpeedA = resetValue;
    bs->animSpeedB = resetValue;
    {
        void* p2d0 = *(void**)&bs->targetObj;
        if (p2d0 == NULL || (**(int (**)(void*))(*(int*)(*(int*)((char*)p2d0 + 0x68)) + 0x20))(p2d0) == 0)
        {
            sub_40c->msgAdvance = 1;
        }
    }
    if (*(void**)&sub_40c->linkedObj == NULL)
    {
        s16 r26 = sub_40c->msgSlotIndex;
        if (r26 != -1)
        {
            RingBufferQueue* sp_handle;
            int v2c;
            int v30;
            v30 = sub_40c->objGroup;
            v2c = sub_40c->msgMode;
            sp_handle = sub_40c->msgStack;
            frame[0] = sub_40c->msgCode;
            frame[1] = v2c;
            frame[2] = v30;
            if (Stack_IsFull(sp_handle) == 0)
                Stack_Push(sp_handle, frame);
            sp_handle = sub_40c->msgStack;
            frame2[0] = 7;
            frame2[1] = 0;
            frame2[2] = r26;
            if (Stack_IsFull(sp_handle) == 0)
                Stack_Push(sp_handle, frame2);
            sub_40c->msgAdvance = 1;
            sub_40c->msgSlotIndex = -1;
        }
    }
    if ((s32)(bs->eventFlags & BADDIE_EVENT_LANDING) != 0)
    {
        sub_40c->linkedObj = *(int*)&bs->targetObj;
        sub_40c->msgSlotIndex = slotIndex;
        sub_40c->msgMode = 0;
        ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 18);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_mn_dimspit6);
    }
    *(s8*)&bs->stateTag = 18;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 16, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        sub_40c->msgAdvance = 1;
    }
    return 0;
}
#pragma opt_common_subs off
int dbstealerworm_stateHandlerA08(GameObject* obj, int baddie, f32 t)
{
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    int q;
    int* ptr;
    int* p2;
    int i2;
    int* p3;
    int i3;
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int tmpB;
    s16 h;
    int tmpA;
    int tmp2B;
    int tmp2A;
    GameObject* player;
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

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject((int)obj);
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    }
    ((BaddieState*)baddie)->moveSpeed = 0.01f;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->msgSlotIndex;
        if (h != -1)
        {
            tmpA = sub->objGroup;
            tmpB = sub->msgMode;
            q = (int)sub->msgStack;
            msgA[0] = sub->msgCode;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgA);
            }
            q = (int)sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgB);
            }
            sub->msgAdvance = 1;
            sub->msgSlotIndex = -1;
        }
    }
    else
    {
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        ((BaddieState*)baddie)->moveSpeed = 0.018f;
        frac = blob->aggression / 80.0f;
    }
    ((BaddieState*)baddie)->stateTag = 0x1f;
    if (fn_80202C78(obj, ((BaddieState*)baddie)->targetObj, 200.0f, frac, 0.2f,
                    t) != 0)
    {
        sub->msgAdvance = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        player = Obj_GetPlayerObject();
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < 30.0f)
        {
            flag = 1;
        }
        if (flag != 0)
        {
            ptr = seqFn_800394a0();
            zero = 0;
            for (q = 1, ptr = ptr + 1; q < 9; ptr++, q++)
            {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0)
                {
                    vec[2] = zero;
                    vec[0] = zero;
                }
            }
            player = Obj_GetPlayerObject();
            ((BaddieState*)baddie)->targetObj = player;
            tmp2A = sub->objGroup;
            tmp2B = sub->msgMode;
            ptr = (int*)sub->msgStack;
            msgC[0] = sub->msgCode;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull((RingBufferQueue*)ptr) == 0)
            {
                Stack_Push((RingBufferQueue*)ptr, msgC);
            }
            ptr = (int*)sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull((RingBufferQueue*)ptr) == 0)
            {
                Stack_Push((RingBufferQueue*)ptr, msgD);
            }
            sub->msgAdvance = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0)
    {
        p2 = seqFn_800394a0();
        zero = 0;
        for (i2 = 1, p2 = p2 + 1; i2 < 9; p2++, i2++)
        {
            vec = objModelGetVecFn_800395d8(obj, *p2);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
        }
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = -(2535.0f * ((BaddieState*)baddie)->animSpeedA);
        flag = -(2535.0f * ((BaddieState*)baddie)->animSpeedB);
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
        p3 = seqFn_800394a0();
        i3 = 1;
        p3 = p3 + 1;
        for (; i3 < 9; i3++)
        {
            vec = objModelGetVecFn_800395d8(obj, *p3);
            if (vec != 0)
            {
                vec[2] = sb;
                vec[0] = sa;
            }
            p3++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}
int dbstealerworm_stateHandlerA07(GameObject* obj, int baddie, f32 t)
{
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    s16 h;
    register int q;
    register int* ptr;
    int* p2;
    int i2;
    int* p3;
    int i3;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    GameObject* player;
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

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_baddie_vambat_death);
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
    ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    ((BaddieState*)baddie)->moveSpeed = 0.01f;
    if (*(void**)&sub->linkedObj == NULL)
    {
        h = sub->msgSlotIndex;
        if (h != -1)
        {
            tmpA = sub->objGroup;
            tmpB = sub->msgMode;
            q = (int)sub->msgStack;
            msgA[0] = sub->msgCode;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgA);
            }
            q = (int)sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull((RingBufferQueue*)q) == 0)
            {
                Stack_Push((RingBufferQueue*)q, msgB);
            }
            sub->msgAdvance = 1;
            sub->msgSlotIndex = -1;
        }
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        frac = blob->aggression / 40.0f;
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer4C, 1.0f, 3.0f) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_weev);
        }
    }
    else
    {
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer48, 1.0f, 3.0f) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie);
        }
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        ((BaddieState*)baddie)->moveSpeed = 0.018f;
        frac = blob->aggression / 80.0f;
    }
    ((BaddieState*)baddie)->stateTag = 0x1f;
    if (fn_80202DA4(obj, ((BaddieState*)baddie)->targetObj, 16.0f, frac, 0.2f, t) != 0)
    {
        sub->msgAdvance = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        player = Obj_GetPlayerObject();
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < 30.0f)
        {
            flag = 1;
        }
        if (flag != 0)
        {
            ptr = seqFn_800394a0();
            zero = 0;
            for (q = 1, ptr = ptr + 1; q < 9; ptr++, q++)
            {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0)
                {
                    vec[2] = zero;
                    vec[0] = zero;
                }
            }
            player = Obj_GetPlayerObject();
            ((BaddieState*)baddie)->targetObj = player;
            tmp2A = sub->objGroup;
            tmp2B = sub->msgMode;
            ptr = (int*)sub->msgStack;
            msgC[0] = sub->msgCode;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull((RingBufferQueue*)ptr) == 0)
            {
                Stack_Push((RingBufferQueue*)ptr, msgC);
            }
            ptr = (int*)sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull((RingBufferQueue*)ptr) == 0)
            {
                Stack_Push((RingBufferQueue*)ptr, msgD);
            }
            sub->msgAdvance = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0)
    {
        p2 = seqFn_800394a0();
        zero = 0;
        for (i2 = 1, p2 = p2 + 1; i2 < 9; p2++, i2++)
        {
            vec = objModelGetVecFn_800395d8(obj, *p2);
            if (vec != 0)
            {
                vec[2] = zero;
                vec[0] = zero;
            }
        }
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = -(2535.0f * ((BaddieState*)baddie)->animSpeedA);
        flag = -(2535.0f * ((BaddieState*)baddie)->animSpeedB);
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
        p3 = seqFn_800394a0();
        i3 = 1;
        p3 = p3 + 1;
        for (; i3 < 9; i3++)
        {
            vec = objModelGetVecFn_800395d8(obj, *p3);
            if (vec != 0)
            {
                vec[2] = sb;
                vec[0] = sa;
            }
            p3++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}
#pragma opt_common_subs reset

int dbstealerworm_stateHandlerA06(GameObject* obj, int baddie)
{


    GroundBaddieState* sub = (obj)->extra;
    int data = *(int*)&(obj)->anim.placementData;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)baddie;

    *(s8*)&bs->stateTag = 0x11;

    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        f32 fz = lbl_803E62A8;
        bs->animSpeedB = fz;
        bs->animSpeedA = fz;
        *(int*)&bs->targetObj = 0;
        bs->physicsActive = 1;
        bs->hasTarget = 0;
        *(u8*)&(obj)->anim.resetHitboxMode = (u8)(*(u8*)&(obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        ObjHits_DisableObject((int)obj);
        ObjGroup_RemoveObject((int)obj, DBSTEALERWORM_OBJGROUP);
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 16);
            sub_40c->msgSlotIndex = -1;
            sub_40c->linkedObj = 0;
        }
    }
    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->moveSpeed = 0.008f;
    if ((obj)->anim.currentMoveProgress > 0.8f)
    {
        int popBuf;
        gameBitIncrement(((DbstealerwormPlacement*)data)->incrementGameBit);
        if ((((DbstealerwormPlacement*)data)->eventConfigId + 0x10000) == 0xffff)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        while (Stack_IsEmpty(sub_40c->msgStack) == 0)
        {
            Stack_Pop(sub_40c->msgStack, &popBuf);
        }
        if (((DbstealerwormPlacement*)data)->disableMapEventTime == 0)
        {
            (*gMapEventInterface)->addTime(*(int*)&((DbstealerwormPlacement*)data)->eventConfigId, 360.0f);
        }
        sub->configFlags |= ((DbstealerwormPlacement*)data)->configFlags;
    }
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))((int)obj, baddie, 0, 2, lbl_80329634);
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))((int)obj, baddie, 7, 0, lbl_80329640);
    return 0;
}

int dbstealerworm_stateHandlerA05(GameObject* obj, int baddie)
{

    BaddieState* bs = (BaddieState*)baddie;
    DbStealerwormControl* sub_40c;
    int frame[3];

    sub_40c = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        int result;
        int player_c8;
        *(u32*)&bs->targetObj = 0;
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 16);
            sub_40c->linkedObj = 0;
        }
        player_c8 = *(int*)&((GameObject*)Obj_GetPlayerObject())->childObjs[0];
        result = (**(int (**)(int))(*(int*)(*(int*)(player_c8 + 0x68)) + 0x44))(player_c8);
        if (result != 0)
        {
            Sfx_PlayFromObject((int)obj, gDbStealerwormSfxIds[randomGetRange(3, 4)]);
        }
        else
        {
            Sfx_PlayFromObject((int)obj, gDbStealerwormSfxIds[randomGetRange(0, 2)]);
        }
        {
            int frame1;
            int frame2;
            RingBufferQueue* sp_handle;
            int frame0;
            frame2 = sub_40c->objGroup;
            frame1 = sub_40c->msgMode;
            sp_handle = sub_40c->msgStack;
            frame0 = sub_40c->msgCode;
            frame[0] = frame0;
            frame[1] = frame1;
            frame[2] = frame2;
            if (Stack_IsFull(sp_handle) == 0)
            {
                Stack_Push(sp_handle, frame);
            }
        }
        sub_40c->savedTargetObj = 0;
    }
    *(s8*)&bs->stateTag = 16;
    bs->moveSpeed = 0.015f;
    bs->animSpeedA = lbl_803E62A8;
    if (*(s8*)&bs->moveDone != 0)
    {
        sub_40c->msgAdvance = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA04(GameObject* obj, int baddie)
{
    GroundBaddieState* state = (obj)->extra;
    BaddieState* bs = (BaddieState*)baddie;
    u32 eventFlags;
    DbStealerwormControl* sub;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    bs->moveSpeed = 0.01f;
    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xa, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->stateTag = 1;
    sub = (DbStealerwormControl*)state->control;
    sub->flags14 = sub->flags14 | DBWORM_FLAG14_FX_DUST;
    eventFlags = bs->eventFlags;
    if (eventFlags & 1)
    {
        bs->eventFlags = eventFlags & ~BADDIE_EVENT_FOOTSTEP;
        sub->flags14 = sub->flags14 | DBWORM_FLAG14_ATTACK;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        sub->msgAdvance = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA03(int obj, int baddie)
{


    if (*(char*)&((BaddieState*)baddie)->moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    ((BaddieState*)baddie)->moveSpeed = 0.01f;
    if (*(char*)&((BaddieState*)baddie)->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E62A8, 0);
        *(s8*)&((BaddieState*)baddie)->moveDone = 0;
    }
    *(s8*)&((BaddieState*)baddie)->stateTag = 1;
    return 0;
}


int dbstealerworm_stateHandlerA02(GameObject* obj, int baddie)
{

    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    BaddieState* bs = (BaddieState*)baddie;

    if (*(s8*)&bs->moveJustStartedA != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
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
        bs->stateTag = 1;
        bs->moveSpeed = 0.005f + state->aggression / 20000.0f;
    }
    bs->animSpeedA = lbl_803E62A8;
    if (*(s8*)&bs->moveDone != 0)
    {
        sub->msgAdvance = 1;
    }
    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    return 0;
}

int dbstealerworm_stateHandlerA01(GameObject* obj, int baddie)
{
    BaddieState* bs = (BaddieState*)baddie;
    GroundBaddieState* sub;
    DbStealerwormControl* sub_40c;
    int placementData;

    sub = (obj)->extra;
    placementData = *(int*)&(obj)->anim.placementData;
    sub_40c = (DbStealerwormControl*)sub->control;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if ((obj)->anim.currentMoveProgress > 0.25f)
    {
        sub_40c->flags14 |= DBWORM_FLAG14_FX_DUST;
        ObjHits_DisableObject((int)obj);
    }
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        bs->moveSpeed = 0.01f;
        bs->animSpeedA = lbl_803E62A8;
    }
    if (*(s8*)&bs->moveDone != 0)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_mn_eggylaugh116);
        sub_40c->unk04 = 1.0f;
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
        *(u32*)&bs->targetObj = 0;
        bs->physicsActive = 0;
        bs->hasTarget = 0;
        sub->targetState = 0;
        sub->configFlags |= ((DbstealerwormPlacement*)placementData)->configFlags;
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 19);
            sub_40c->linkedObj = 0;
            sub_40c->msgSlotIndex = -1;
        }
        if ((sub_40c->flags15 & 0x2) == 0)
        {
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        sub_40c->msgAdvance = 1;
    }
    (**(int (**)(int, int, int, int, int*))((char*)*gPlayerInterface + 0x34))((int)obj, baddie, 7, 0, lbl_80329640);
    return 0;
}

int dbstealerworm_stateHandlerA00(GameObject* obj, int baddie)
{

    GroundBaddieState* sub = (obj)->extra;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)baddie;

    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        bs->physicsActive = 1;
        *(u8*)&(obj)->anim.resetHitboxMode = (u8)(*(u8*)&(obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        (obj)->anim.alpha = 255;
        bs->stateTag = 1;
        bs->moveSpeed = 0.012f + (f32)(u32)sub->aggression / 10000.0f;
        ObjHits_EnableObject((int)obj);
        sub_40c->linkedObj = 0;
        sub_40c->msgSlotIndex = -1;
    }
    else
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    }

    if ((s32)(s8)bs->moveDone != 0)
    {
        sub->targetState = 1;
        sub_40c->msgAdvance = 1;
    }

    if ((*(int*)&bs->eventFlags & BADDIE_EVENT_LANDING) != 0)
    {
        *(int*)&bs->eventFlags = *(int*)&bs->eventFlags & ~BADDIE_EVENT_LANDING;
        sub_40c->flags14 = (u8)(sub_40c->flags14 | DBWORM_FLAG14_FX_SPRAY);
    }

    if ((obj)->anim.currentMoveProgress < 0.7f)
    {
        sub_40c->flags14 = (u8)(sub_40c->flags14 | DBWORM_FLAG14_FX_DUST);
    }

    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))((int)obj, baddie, 7, 0, lbl_80329640);
    return 0;
}

int fn_80202A2C(GameObject* obj, int* objs, f32* weights, int n, f32 limit)
{

    int* objCursor;
    f32* weightCursor;
    BaddieState* state = (obj)->extra;
    int i;
    f32 rangeInit;
    f32 accX;
    f32 accZ;
    u32 nearest;
    f32 k;
    f32 scale;
    f32 cosv;
    f32 sinv;
    f32 v;
    f32 w;
    struct
    {
        f32 range;
        f32 d[3];
    } stk;

    accX = lbl_803E62A8;
    accZ = *(f32*)&lbl_803E62A8;
    i = 0;
    objCursor = objs;
    weightCursor = weights;
    rangeInit = 260.0f;
    for (; i < n; i++)
    {
        stk.range = rangeInit;
        nearest = ObjGroup_FindNearestObjectForObjectLegacy(*objCursor, obj, &stk.range);
        if (nearest != 0)
        {
            if (stk.range == lbl_803E62A8)
            {
                return 0;
            }
            scale = 1.0f;
            k = scale - stk.range / 260.0f;
            k = k * k;
            k = k * k;
            stk.d[0] = ((GameObject*)nearest)->anim.localPosX - (obj)->anim.localPosX;
            stk.d[1] = ((GameObject*)nearest)->anim.localPosY - (obj)->anim.localPosY;
            stk.d[2] = ((GameObject*)nearest)->anim.localPosZ - (obj)->anim.localPosZ;
            stk.d[0] = stk.d[0] * (scale / stk.range);
            stk.d[1] = stk.d[1] * (scale / stk.range);
            stk.d[2] = stk.d[2] * (scale / stk.range);
            accX = accX - limit * (stk.d[0] * k * (w = *weightCursor));
            accZ = accZ - limit * (stk.d[2] * k * (v = w));
        }
        objCursor++;
        weightCursor++;
    }
    cosv = mathSinf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
    sinv = mathCosf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
    state->animSpeedB = state->animSpeedB + (accX * sinv - accZ * cosv);
    state->animSpeedA = state->animSpeedA + (-accZ * sinv - accX * cosv);
    v = state->animSpeedA;
    if (v < -limit)
    {
        v = -limit;
    }
    else if (v > limit)
    {
        v = limit;
    }
    state->animSpeedA = v;
    v = state->animSpeedB;
    state->animSpeedB = (v < -limit) ? -limit : (v > limit) ? limit : v;
    return 0;
}

#pragma dont_inline on
#pragma opt_common_subs off
int fn_80202C78(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused, f32 range)
{
    BaddieState* state = (obj)->extra;
    f32 yawF;
    int yaw;
    f32 zero;
    f32 a;
    f32 ratio;
    f32 k;
    f32 cur;
    f32 prod;

    yaw = Obj_GetYawDeltaToObject(obj, otherObj, &yawF);
    zero = lbl_803E62A8;
    if (zero == range)
    {
        return 0;
    }
    yawF -= yawOffset;
    ratio = yawF / range;
    yawF = ratio;
    if (ratio >= zero)
    {
        a = ratio;
    }
    else
    {
        a = -ratio;
    }
    if (a < 10.0f)
    {
        return 1;
    }
    if (ratio < lbl_803E62A8)
    {
        speed = -speed;
    }
    cur = state->animSpeedA;
    k = timeDelta * 0.25f;
    prod = speed * (1.0f - (f32)(s16)yaw / 65536.0f);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}

#pragma opt_common_subs reset
int fn_80202DA4(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused, f32 range)
{
    BaddieState* state = obj->extra;
    f32 yawF;
    int yaw;
    f32 dy;
    f32 zero;
    f32 k;
    f32 cur;
    f32 prod;

    if (obj == NULL || otherObj == NULL)
    {
        return 0;
    }
    yaw = Obj_GetYawDeltaToObject(obj, otherObj, &yawF);
    zero = lbl_803E62A8;
    if (zero == range)
    {
        return 0;
    }
    if (yawF < yawOffset)
    {
        dy = (obj->anim.localPosY - otherObj->anim.localPosY >= zero)
                 ? obj->anim.localPosY - otherObj->anim.localPosY
                 : -(obj->anim.localPosY - otherObj->anim.localPosY);
        if (dy < 8.0f)
        {
            return 1;
        }
    }
    cur = state->animSpeedA;
    k = timeDelta * 0.25f;
    prod = speed * (1.0f - (f32)(s16)yaw / 65536.0f);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}

#pragma dont_inline reset

void fn_80202EF0(GameObject* obj, int baddie)
{

    ObjPlacement* setup;
    GameObject* newObj;
    f32 dur;
    f32 t;

    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x24, DBSTEALERWORM_CHILD_OBJ_PROJECTILE);
        setup->posX = (obj)->anim.localPosX;
        setup->posY = 15.0f + (obj)->anim.localPosY;
        setup->posZ = (obj)->anim.localPosZ;
        setup->color[0] = 1;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        newObj = Obj_SetupObject(setup, 5, (obj)->anim.mapEventSlot, -1, NULL);
        if (newObj != NULL)
        {
            t = ((BaddieState*)baddie)->targetDistance / 200.0f;
            dur = 50.0f * t;
            ((GameObject*)newObj)->anim.velocityX =
                (((GameObject*)((BaddieState*)baddie)->targetObj)->anim.localPosX - (obj)->anim.localPosX) / dur;
            ((GameObject*)newObj)->anim.velocityY =
                ((90.0f * t + ((GameObject*)((BaddieState*)baddie)->targetObj)->anim.localPosY) -
                 (obj)->anim.localPosY) /
                dur;
            ((GameObject*)newObj)->anim.velocityZ =
                (((GameObject*)((BaddieState*)baddie)->targetObj)->anim.localPosZ - (obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)newObj)->ownerObj = (int)obj;
        }
    }
}
#pragma dont_inline on
void fn_80203000(GameObject* obj, int baddie)
{
    int i;
    DbStealerwormControl* state = (DbStealerwormControl*)*(int*)&((GroundBaddieState*)baddie)->control;
    if ((state->flags14 & DBWORM_FLAG14_ATTACK) && *(void**)&((GroundBaddieState*)baddie)->baddie.targetObj != 0)
    {
        fn_80202EF0(obj, baddie);
    }
    if (state->flags14 & DBWORM_FLAG14_FX_DUST)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
    }
    if (state->flags14 & DBWORM_FLAG14_FX_SPRAY)
    {
        for (i = 0; i < 0xa; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_SPRAY, NULL, 1, -1, NULL);
        }
    }
    state->flags14 = 0;
}

#pragma dont_inline reset
#pragma fp_contract off
#pragma opt_common_subs off
void fn_80203144(GameObject* obj, int groundState, int baddie)
{

    GroundBaddieState* st = (GroundBaddieState*)groundState;
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

    stk.range = 100.0f;
    data = *(int*)&obj->anim.placementData;
    near = (**(u32(**)(int, int, f32, int))((char*)*gBaddieControlInterface + 0x48))((int)obj, baddie, st->aggroRange,
                                                                                     0x8000);
    if (near == 0 && (st->configFlags & 0x10) != 0)
    {
        near = ObjGroup_FindNearestObject(DBEGG_OBJGROUP, (int)obj, &stk.range);
    }
    if (near == 0 && (st->configFlags & 0x10) != 0 && (st->configFlags & 2) == 0 &&
        (((DbstealerwormPlacement*)data)->configFlags & 2) != 0)
    {
        near = ObjGroup_FindNearestObject(DBEGG_OBJGROUP, (int)obj, 0);
    }
    if (near != 0 && (st->configFlags & 2) == 0)
    {
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)*gBaddieControlInterface + 0x28))(
            (int)obj, baddie, groundState + 0x35c, st->gameBitB, 0, 0, 0, 8, -1);
        *(int*)&((BaddieState*)baddie)->targetObj = near;
        ((BaddieState*)baddie)->hasTarget = 0;
        ObjGroup_AddObject((int)obj, DBSTEALERWORM_OBJGROUP);
        *(u16*)&st->targetState = 1;
    }
    else
    {
        player = (char*)Obj_GetPlayerObject();
        if (player != NULL)
        {
            stk.d[0] = ((GameObject*)player)->anim.worldPosX - obj->anim.worldPosX;
            stk.d[1] = ((GameObject*)player)->anim.worldPosY - obj->anim.worldPosY;
            stk.d[2] = ((GameObject*)player)->anim.worldPosZ - obj->anim.worldPosZ;
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        }
        else
        {
            dist = 10000.0f;
        }
        if (sub->countdown > sub->nextSfxTime && dist < 400.0f)
        {
            Sfx_PlayFromObject((int)obj, lbl_80329640[1]);
            sub->nextSfxTime = sub->nextSfxTime + (f32)(int)randomGetRange(0x32, 0xfa);
        }
        sub->countdown += timeDelta;
    }
}
#pragma fp_contract reset
#pragma opt_common_subs reset

int dbstealerworm_func0B(GameObject* obj, u8 msg, int* out)
{
    GroundBaddieState* state = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    int result = 0;
    u8 configFlags;
    switch (msg)
    {
    case 0x80:
        break;
    case 0x81:
        configFlags = state->configFlags;
        if ((configFlags & 2) == 0)
        {
            break;
        }
        state->configFlags = configFlags & ~2;
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
        sub->savedTargetObj = (int)out;
        result = 1;
        break;
    case 0x83:
        result = sub->savedTargetObj;
        break;
    }
    return result;
}


s16 dbstealerworm_setScale(int* obj)
{
    return ((BaddieState*)((int**)obj)[0xb8 / 4])->controlMode;
}

int dbstealerworm_getExtraSize(void)
{
    return 0x460;
}
int dbstealerworm_getObjectTypeId(void)
{
    return 0x49;
}


void dbstealerworm_free(int* obj)
{
    u8* sub = ((GameObject*)obj)->extra;
    int* p40c = *(int**)&((GroundBaddieState*)sub)->control;
    ObjGroup_RemoveObject((int)obj, DBSTEALERWORM_OBJGROUP);
    Stack_Free(((DbStealerwormControl*)p40c)->msgStack);
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
        *(int*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    ((void (*)(int*, u8*, int))((void**)*gBaddieControlInterface)[16])(obj, sub, 3);
}

void dbstealerworm_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    GroundBaddieState* state;
    char* path;
    DbStealerwormControl* sub;

    state = (obj)->extra;
    sub = (DbStealerwormControl*)state->control;
    if (*(void**)&sub->linkedObj != NULL)
    {
        ((GameObject*)sub->linkedObj)->anim.localPosX = (obj)->anim.localPosX;
        ((GameObject*)sub->linkedObj)->anim.localPosY = (obj)->anim.localPosY;
        ((GameObject*)sub->linkedObj)->anim.localPosZ = (obj)->anim.localPosZ;
        ((GameObject*)sub->linkedObj)->anim.localPosY += 30.0f;
    }
    if (visible == 0 || (obj)->unkF4 != 0 || state->targetState == 0)
    {
        return;
    }
    {
        {
            if (state->glowAlpha != lbl_803E62A8)
            {
                fn_8003B5E0(0xc8, 0, 0, state->glowAlpha);
            }
            ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)((int)obj, p2, p3, p4, p5,
                                                                                  1.0f);
            if ((state->flags400 & 0x60) != 0)
            {
                objParticleFn_80099d84((GameObject*)obj, 1.0f, 3, state->glowAlpha, 0);
            }
            path = *(char**)&sub->linkedObj;
            if (path != NULL && *(void**)(path + 0x50) != NULL)
            {
                ObjPath_GetPointWorldPosition(obj, 3, (f32*)(path + 0xc), (f32*)(path + 0x10), (f32*)(path + 0x14), 0);
                ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(sub->linkedObj, p2, p3, p4, p5,
                                                                                      1.0f);
            }
        }
    }
}


void dbstealerworm_hitDetect(GameObject* obj)
{
    int* inner = obj->extra;
    (*(void (*)(int, int*, int*))(*(int*)((char*)*gPlayerInterface + 0xc)))((int)obj, inner, gDBStealerWormStateHandlersA);
}

__declspec(section ".sdata2") f32 lbl_803E6388 = 0.17f;
#pragma opt_loop_invariants off
#pragma opt_propagation off
void dbstealerworm_update(u8* objp)
{
    char* st;
    char* tbl;
    int blob;
    int data;
    int sub;
    int obj;
    int off;
    char* entry;
    int sub3;
    int n;
    int sub2;
    int t;
    struct
    {
        u32 msg;
        int argA;
        int argB;
        f32 v[3];
    } stk;

    obj = (int)objp;
    st = (char*)(int)lbl_803AD0C0;
    tbl = (char*)lbl_803293B8;
    blob = *(int*)&((GameObject*)obj)->extra;
    data = (int)((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GroundBaddieState*)blob)->control;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if ((u32)((DbStealerwormControl*)sub)->flags44 >> 4 & 1)
    {
        entry = tbl + ((DbstealerwormPlacement*)data)->cfgTableIndex * 8;
        entry = entry + 0x15c;
        ((DbStealerwormControl*)sub)->msgStack = allocModelStruct_800139e8(0x14, 0xc);
        n = *(s16*)(entry + 4);
        off = n * 0xc;
        while (n != 0)
        {
            RingBufferQueue* stk = ((DbStealerwormControl*)sub)->msgStack;
            int base = *(int*)entry;
            n--;
            Stack_Push(stk, (int*)(base + (off -= 12)));
        }
        ((DbStealerwormControl*)sub)->msgAdvance = 1;
        ((DbStealerwormFlags44*)&((DbStealerwormControl*)sub)->flags44)->flag10 = 0;
    }
    if (mainGetBit(((GroundBaddieState*)blob)->gameBitC) != 0)
    {
        if (((GameObject*)obj)->unkF4 != 0)
        {
            if ((((GroundBaddieState*)blob)->configFlags & 4) == 0 &&
                (*gMapEventInterface)->shouldNotSaveTime(*(int*)&((DbstealerwormPlacement*)data)->eventConfigId) != 0)
            {
                ((void (*)(int, int, int, int, int, int, int, f32))((void**)*gBaddieControlInterface)[22])(
                    obj, data, blob, 0x10, 7, 0x10a, 0x26, lbl_803E62FC);
                ObjGroup_AddObject((int)obj, DBSTEALERWORM_OBJGROUP);
                ((GroundBaddieState*)blob)->targetState = 0;
                ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
                ((GroundBaddieState*)blob)->baddie.moveDone = 0;
                ((GameObject*)obj)->anim.alpha = 0xff;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->homePosX;
            ((GameObject*)obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->homePosY;
            ((GameObject*)obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->homePosZ;
            (*gObjectTriggerInterface)->runSequence(((DbstealerwormPlacement*)data)->seqId, (void*)obj, -1);
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
                    stk.v[0] = ((GameObject*)t)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
                    stk.v[1] = ((GameObject*)t)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
                    stk.v[2] = ((GameObject*)t)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
                    ((GroundBaddieState*)blob)->baddie.targetDistance =
                        sqrtf(stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = *(int*)&((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
                while (ObjMsg_Pop((void*)obj, &stk.msg, (u32*)&stk.argB, &stk.msg + 1) != 0)
                {
                    if (stk.msg == 0x11 && ((DbStealerwormControl*)sub2)->msgSlotIndex != -1)
                    {
                        ObjMsg_SendToObject((void*)((DbStealerwormControl*)sub2)->linkedObj, 0x11, (void*)obj, 0x14);
                        ((DbStealerwormControl*)sub2)->linkedObj = 0;
                        ((DbStealerwormControl*)sub2)->msgSlotIndex = -1;
                        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
                    }
                }
                if (((int (*)(int, int, int, int, char*, char*, int, char*))((void**)*gBaddieControlInterface)[20])(
                        obj, blob, blob + 0x35c, ((GroundBaddieState*)blob)->gameBitB, tbl + 0x2ac, tbl + 0x324, 1,
                        (char*)(int)lbl_803AD0C0) != 0)
                {
                    *(f32*)(st + 0xc) = ((GameObject*)obj)->anim.localPosX;
                    *(f32*)(st + 0x10) = ((GameObject*)obj)->anim.localPosY;
                    ((GroundBaddieState*)st)->baddie.posX = ((GameObject*)obj)->anim.localPosZ;
                    objLightFn_8009a1dc((void*)obj, 0.014f, (char*)(int)lbl_803AD0C0, 1, 0);
                }
                if (((GroundBaddieState*)blob)->targetState == 0)
                {
                    fn_80203144((GameObject*)obj, blob, blob);
                }
                else
                {
                    sub3 = *(int*)&((GroundBaddieState*)blob)->control;
                    fn_80203000((GameObject*)(obj), blob);
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
#pragma opt_propagation reset

void dbstealerworm_init(int* obj, u8* def, int flag)
{
    u8* sub;
    int* p40c;
    u8 mode;
    int randomValue;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (flag != 0)
    {
        mode |= 1;
    }
    ((void (*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*gBaddieControlInterface)[22])(
        obj, def, sub, 0x10, 7, 0x10a, mode, lbl_803E62FC);
    ObjGroup_AddObject((int)obj, DBSTEALERWORM_OBJGROUP);
    ((GameObject*)obj)->animEventCallback = NULL;
    p40c = *(int**)&((GroundBaddieState*)sub)->control;
    memset(p40c, 0, sizeof(DbStealerwormControl));
    ((DbStealerwormControl*)p40c)->unk08 = lbl_803E62FC;
    ((DbStealerwormControl*)p40c)->cfg = (int)&lbl_80329514[((s16) * (s16*)(def + 0x24)) * 2];
    randomValue = randomGetRange(0xa, 0x12c);
    ((DbStealerwormControl*)p40c)->countdown = (f32)(s32)randomValue;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->flag20 = def[0x2b] & 1;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->flag10 = 1;
    ((DbStealerwormControl*)p40c)->linkedObj = 0;
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    ((void (*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, sub, 3);
    ((GroundBaddieState*)sub)->baddie.substate = 0;
    ((GroundBaddieState*)sub)->baddie.physicsActive = 1;
    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4008;
    }
}


void dbstealerworm_release(void)
{
}

void dbstealerworm_initialise(void)
{
    DBstealerwo_setFuncPtrs_80203c78();
}

/* Trivial 0-returner. */

/* Trivial 0-returner. */

/* if (p6) objRenderModelAndHitVolumes(lbl_803E6408). */

/* if (b->_8 && (b->_8->_6 & 0x40)) clear. */

u32 lbl_803293B8[18] = {0x00000000, 0x00000000, 0x00000000, 0x00000007, 0x00000000, 0x00000024,
                        0x00000009, 0x00000000, 0x00000024, 0x00000008, 0x00000000, 0x00000003,
                        0x0000000a, 0x00000000, 0x00000003, 0x00000001, 0x00000000, 0x00000000};
u32 lbl_80329400[18] = {0x00000000, 0x00000000, 0x00000000, 0x00000007, 0x00000000, 0x00000024,
                        0x00000009, 0x00000000, 0x00000024, 0x00000008, 0x00000000, 0x0000001e,
                        0x0000000a, 0x00000000, 0x0000001e, 0x00000001, 0x00000000, 0x00000000};
u32 lbl_80329448[15] = {0x00000000, 0x00000000, 0x00000000, 0x00000007, 0x00000000, 0x00000024,
                        0x00000009, 0x00000000, 0x00000024, 0x00000007, 0x00000000, 0x0000001e,
                        0x00000001, 0x00000000, 0x00000000};
u32 lbl_80329484[18] = {0x00000000, 0x00000000, 0x00000000, 0x00000007, 0x00000000, 0x00000024,
                        0x00000009, 0x00000000, 0x00000024, 0x00000008, 0x00000000, 0x00000000,
                        0x0000000a, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000000};
u32 lbl_803294CC[9] = {0x00000000, 0x00000000, 0x00000000, 0x0000000b, 0x00000000, 0x00000024,
                       0x00000001, 0x00000000, 0x00000000};
u32 lbl_803294F0[9] = {0x00000000, 0x00000000, 0x00000000, 0x0000000f, 0x00000000, 0x00000000,
                       0x00000001, 0x00000000, 0x00000000};
u32 lbl_80329514[72] = {(u32)lbl_803293B8, 0x00060000, (u32)lbl_80329400, 0x00060000,
                        (u32)lbl_80329448, 0x00050000, (u32)lbl_80329484, 0x00060000,
                        (u32)lbl_803294CC, 0x00030000, (u32)lbl_803294F0, 0x00030000,
                        0x706f704f, 0x75744f66, 0x47726f75, 0x6e640062,
                        0x75727374, 0x496e746f, 0x47726f75, 0x6e006269,
                        0x74654174, 0x7461636b, 0x20202020, 0x00737461,
                        0x6e645374, 0x696c6c20, 0x20202000, 0x7374616e,
                        0x64416e64, 0x53706974, 0x20200068, 0x69744669,
                        0x6768744d, 0x61696e20, 0x20006669, 0x6768745f,
                        0x64696520, 0x20202020, 0x0072756e, 0x746f5f4f,
                        0x626a6563, 0x74202000, 0x72756e74, 0x6f5f5468,
                        0x726f774f, 0x626a0070, 0x69636b75, 0x705f4f62,
                        0x6a656374, 0x20007468, 0x726f775f, 0x41744f62,
                        0x6a656374, 0x00776169, 0x745f666f, 0x724f626a,
                        0x65637400, 0x57616974, 0x5f666f72, 0x5f746872,
                        0x6f770074, 0x72795f74, 0x6f5f6361, 0x74636820,
                        0x20006361, 0x7463685f, 0x4f626a65, 0x63742020,
                        0x004b696c, 0x6c5f4f62, 0x6a656374, 0x20202000};
int lbl_80329634[3] = {0x000001ed, 0x000001ed, 0x000001ec};
int lbl_80329640[4] = {0x00000000, 0x000001f0, 0x000001f1, 0x000001f1};

int gDbStealerwormSfxIds[] = {
    498, 498, 498, 149, 149, 5, 5, 5, 5, 5, 5, 5, 5, 5,  5,  5,  5,  5,  5,  2,  5,      5,
    5,   5,   5,   5,   5,   5, 5, 5, 5, 5, 5, 5, 5, -1, -1, -1, -1, -1, -1, -1, -65536,
};

u32 lbl_803296FC[4] = {0x00000000, 0x00000001, 0x00000003, 0x0000000a};
u32 lbl_8032970C[4] = {0x40000000, 0x40800000, 0x3fc00000, 0x40400000};
u32 lbl_8032971C[4] = {0x00000003, 0x00000000, 0x00000001, 0x0000000a};
u32 lbl_8032972C[4] = {0x41000000, 0x40400000, 0x40000000, 0x40800000};
u32 lbl_8032973C[4] = {0x00000003, 0x00000001, 0x00000000, 0x0000000a};
u32 lbl_8032974C[10] = {0x40000000, 0x3f4ccccd, 0x3ecccccd, 0x40000000, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
u32 gDBstealerwormObjDescriptor[39] = {0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       0x000b0000,
                                       (u32)dbstealerworm_initialise,
                                       (u32)dbstealerworm_release,
                                       0x00000000,
                                       (u32)dbstealerworm_init,
                                       (u32)dbstealerworm_update,
                                       (u32)dbstealerworm_hitDetect,
                                       (u32)dbstealerworm_render,
                                       (u32)dbstealerworm_free,
                                       (u32)dbstealerworm_getObjectTypeId,
                                       (u32)dbstealerworm_getExtraSize,
                                       (u32)dbstealerworm_setScale,
                                       (u32)dbstealerworm_func0B,
                                       0x20537461,
                                       0x636b202d,
                                       0x2d2d2d2d,
                                       0x2d2d2d2d,
                                       0x2d2d2d2d,
                                       0x2d2d2d2d,
                                       0x2d2d0a00,
                                       0x2569203a,
                                       0x20257320,
                                       0x3a204f70,
                                       0x616e6420,
                                       0x2569200a,
                                       0x00000000,
                                       0x20484153,
                                       0x2042414c,
                                       0x4c203a20,
                                       0x25783d20,
                                       0x25780a00,
                                       0x20544852,
                                       0x4f572043,
                                       0x48414e43,
                                       0x45202569,
                                       0x200a0000};
u32 gDBHoleControl1ObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        (u32)dbholecontrol1_initialise,
                                        (u32)dbholecontrol1_release,
                                        0x00000000,
                                        (u32)dbholecontrol1_init,
                                        (u32)dbholecontrol1_update,
                                        (u32)dbholecontrol1_hitDetect,
                                        (u32)dbholecontrol1_render,
                                        (u32)dbholecontrol1_free,
                                        (u32)dbholecontrol1_getObjectTypeId,
                                        (u32)dbholecontrol1_getExtraSize};
u32 lbl_80329848[5] = {0x00010002, 0x00030000, 0x00000000, 0x00000000, 0x00000000};
u32 gDFP_LevelControlObjDescriptor[15] = {0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          0x000a0000,
                                          (u32)DFP_LevelControl_initialise,
                                          (u32)DFP_LevelControl_release,
                                          0x00000000,
                                          (u32)DFP_LevelControl_init,
                                          (u32)DFP_LevelControl_update,
                                          (u32)DFP_LevelControl_hitDetect,
                                          (u32)DFP_LevelControl_render,
                                          (u32)DFP_LevelControl_free,
                                          (u32)DFP_LevelControl_getObjectTypeId,
                                          (u32)DFP_LevelControl_getExtraSize,
                                          (u32)DFP_LevelControl_setScale};
u32 gDFP_ObjCreatorObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        (u32)DFP_ObjCreator_initialise,
                                        (u32)DFP_ObjCreator_release,
                                        0x00000000,
                                        (u32)DFP_ObjCreator_init,
                                        (u32)DFP_ObjCreator_update,
                                        (u32)DFP_ObjCreator_hitDetect,
                                        (u32)DFP_ObjCreator_render,
                                        (u32)DFP_ObjCreator_free,
                                        (u32)DFP_ObjCreator_getObjectTypeId,
                                        (u32)DFP_ObjCreator_getExtraSize};
u32 lbl_803298D0[14] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00090000,
                        (u32)dll_22C_initialise_nop,
                        (u32)dll_22C_release_nop,
                        0x00000000,
                        (u32)dll_22C_init,
                        (u32)dll_22C_update,
                        (u32)dll_22C_hitDetect_nop,
                        (u32)dll_22C_render,
                        (u32)dll_22C_free,
                        (u32)dll_22C_getObjectTypeId,
                        (u32)dll_22C_getExtraSize_ret_16};
u32 gDoorswitchObjDescriptor[14] = {0x00000000,
                                    0x00000000,
                                    0x00000000,
                                    0x00090000,
                                    (u32)doorswitch_initialise,
                                    (u32)doorswitch_release,
                                    0x00000000,
                                    (u32)doorswitch_init,
                                    (u32)doorswitch_update,
                                    (u32)doorswitch_hitDetect,
                                    (u32)doorswitch_render,
                                    (u32)doorswitch_free,
                                    (u32)doorswitch_getObjectTypeId,
                                    (u32)doorswitch_getExtraSize};
