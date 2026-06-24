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
 *   EN v1.0 0x80206474  8b   trivial 0-returner.
 *   EN v1.0 0x80206484  8b   trivial 0-returner.
 *   EN v1.0 0x802064D0  48b  if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 *   EN v1.0 0x80206500  44b  if (b->_8 && (b->_8->_6 & 0x40)) clear.
 */
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/dfp_types.h"
#include "main/main.h"
extern void objRenderFn_8003b8f4(int* obj);
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/objlib.h"

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

typedef struct DbstealerwormPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;             /* 0x04 */
    u8 unk5;             /* 0x05 */
    u8 unk6;             /* 0x06 */
    u8 unk7;             /* 0x07 */
    f32 homePosX;        /* 0x08: worm home/spawn position */
    f32 homePosY;        /* 0x0C */
    f32 homePosZ;        /* 0x10 */
    u32 eventConfigId;   /* 0x14: 0xFFFFFFFF = no map-event config */
    s16 incrementGameBit;/* 0x18: game bit bumped on a successful steal */
    s16 unk1A;           /* 0x1A */
    s16 unk1C;           /* 0x1C */
    s16 unk1E;           /* 0x1E */
    s16 unk20;           /* 0x20 */
    u8 pad22[0x24 - 0x22];
    s16 cfgTableIndex;   /* 0x24: index into the per-worm config table (entry stride 8) */
    u8 pad26[0x2B - 0x26];
    u8 configFlags;      /* 0x2B: config flag bits OR'd into the state's configFlags */
    s16 unk2C;           /* 0x2C */
    s8 seqId;            /* 0x2E: sequence run when activated */
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

extern u32 ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObjectForObject();

extern u32 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern void Stack_Free(int* stack);
extern void** gBaddieControlInterface;
extern int* gPlayerInterface;
extern f32 lbl_803E62A8;
extern f32 lbl_803E62FC;
extern u8 lbl_80329514[];

extern int gDBStealerWormStateHandlersA[];
extern f32 lbl_803E62BC;
extern int dbstealerworm_stateHandlerB06();
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA02();
extern f32 lbl_803E62F4;
extern f32 lbl_803E62E8;
extern f32 lbl_803E62EC;

int dbstealerworm_stateHandlerB04(int obj, int p)
{
    float fz;
    int b8;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)p)->moveJustStartedB != '\0')
    {
        (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 1);
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->nextSfxTime = fz;
        ((DbStealerwormControl*)b8)->unk04 = fz;
    }
    return 0;
}

int dbstealerworm_stateHandlerB02(int obj, int p)
{
    int b8;
    float fz;
    s8 flag2;

    b8 = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)&((BaddieState*)p)->moveJustStartedB != '\0')
    {
        b8 = *(int*)&((GroundBaddieState*)b8)->control;
        fz = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->countdown = lbl_803E62A8;
        ((DbStealerwormControl*)b8)->nextSfxTime = fz;
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

int dbstealerworm_stateHandlerA09(int obj, int p)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    BaddieState* bs = (BaddieState*)p;
    DbStealerwormControl* sub_40c;
    int slotIndex;
    int frame[3];
    int frame2[3];
    f32 resetValue;

    sub_40c = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    slotIndex = sub_40c->unk30;
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
        sub_40c->unk1C = slotIndex;
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

int dbstealerworm_stateHandlerA06(int obj, int p2)
{

    extern void ObjGroup_RemoveObject(int, int);
    extern int gameBitIncrement(int bit);

    extern void Stack_Pop(int, int*);
    extern int Stack_IsEmpty(int);
    extern int lbl_80329634[];
    extern int lbl_80329640[];
    extern f32 lbl_803E6334;
    extern f32 lbl_803E6338;
    extern f32 lbl_803E633C;

    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)p2;

    *(s8*)&bs->unk34D = 0x11;

    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        f32 fz = lbl_803E62A8;
        bs->animSpeedB = fz;
        bs->animSpeedA = fz;
        *(int*)&bs->targetObj = 0;
        bs->physicsActive = 1;
        bs->hasTarget = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        ObjHits_DisableObject(obj);
        ObjGroup_RemoveObject(obj, 3);
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject((void*)sub_40c->linkedObj, 17, obj, 16);
            sub_40c->unk1C = -1;
            sub_40c->linkedObj = 0;
        }
    }
    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->moveSpeed = lbl_803E6334;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E6338)
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
        if (((DbstealerwormPlacement*)data)->unk2C == 0)
        {
            (*gMapEventInterface)->
                addTime(*(int*)&((DbstealerwormPlacement*)data)->eventConfigId, lbl_803E633C);
        }
        sub->configFlags |= ((DbstealerwormPlacement*)data)->configFlags;
    }
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))(obj, p2, 0, 2, lbl_80329634);
    (**(void (**)(int, int, int, int, int*))((char*)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
    return 0;
}

int dbstealerworm_stateHandlerA05(int obj, int p)
{

    extern int gDbStealerwormSfxIds[];
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
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
            Sfx_PlayFromObject(obj, gDbStealerwormSfxIds[randomGetRange(3, 4)]);
        }
        else
        {
            Sfx_PlayFromObject(obj, gDbStealerwormSfxIds[randomGetRange(0, 2)]);
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
    extern int lbl_80329640[];
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E634C;
    BaddieState* bs = (BaddieState*)p;
    GroundBaddieState* sub;
    DbStealerwormControl* sub_40c;
    int placementData;

    sub = ((GameObject*)obj)->extra;
    placementData = *(int*)&((GameObject*)obj)->anim.placementData;
    sub_40c = (DbStealerwormControl*)sub->control;
    if (*(char*)&bs->moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E62A8, 0);
        *(s8*)&bs->moveDone = 0;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
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
        sub->configFlags |= ((DbstealerwormPlacement*)placementData)->configFlags;
        if (*(void**)&sub_40c->linkedObj != NULL)
        {
            ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 19);
            sub_40c->linkedObj = 0;
            sub_40c->unk1C = -1;
        }
        if ((sub_40c->flags15 & 0x2) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        sub_40c->unk34 = 1;
    }
    (**(int (**)(int, int, int, int, int*))(*gPlayerInterface + 0x34))(obj, p, 7, 0, lbl_80329640);
    return 0;
}

void dbstealerworm_release(void)
{
}

void dbstealerworm_init(int* obj, u8* def, int param3)
{
    extern u32 ObjGroup_AddObject();
    extern u32 ObjHits_EnableObject();
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
    memset(p40c, 0, sizeof(DbStealerwormControl));
    ((DbStealerwormControl*)p40c)->unk08 = lbl_803E62FC;
    ((DbStealerwormControl*)p40c)->cfg = (int)&lbl_80329514[((s16) * (s16*)(def + 0x24)) * 8];
    r = randomGetRange(0xa, 0x12c);
    ((DbStealerwormControl*)p40c)->countdown = (f32)(s32)r;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->flag20 = def[0x2b] & 1;
    ((DbStealerwormFlags44*)&((DbStealerwormControl*)p40c)->flags44)->flag10 = 1;
    ((DbStealerwormControl*)p40c)->linkedObj = 0;
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
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
    extern u64 ObjGroup_RemoveObject();
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
        ((DbStealerwormControl*)state->control)->spawnAccumulator += lbl_803E62BC;
        return 7;
    }
    return 0;
}

int dbstealerworm_stateHandlerA00(int obj, int p2)
{

    extern int lbl_80329640[];
    extern f32 lbl_803E6350;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6358;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    DbStealerwormControl* sub_40c = (DbStealerwormControl*)sub->control;
    BaddieState* bs = (BaddieState*)p2;

    if ((s32)(s8)bs->moveJustStartedA != 0)
    {
        bs->physicsActive = 1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        ((GameObject*)obj)->anim.alpha = 255;
        bs->unk34D = 1;
        bs->moveSpeed = lbl_803E6350 + (f32)(u32)sub->aggression / lbl_803E6354;
        ObjHits_EnableObject(obj);
        sub_40c->linkedObj = 0;
        sub_40c->unk1C = -1;
    }
    else
    {
        ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    }

    if ((s32)(s8)bs->moveDone != 0)
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

#pragma dont_inline on
void fn_80203000(int obj, int param2)
{
    int i;
    int state = *(int*)&((GroundBaddieState*)param2)->control;
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
            ((GameObject*)newObj)->anim.velocityX = (((GameObject*)((BaddieState*)p2)->targetObj)->anim.localPosX - ((GameObject
                *)obj)->anim.localPosX) / dur;
            ((GameObject*)newObj)->anim.velocityY = ((lbl_803E6380 * t + *(f32*)(*(int*)&((BaddieState*)p2)->targetObj +
                0x10)) - ((GameObject*)obj)->anim.localPosY) / dur;
            ((GameObject*)newObj)->anim.velocityZ = (((GameObject*)((BaddieState*)p2)->targetObj)->anim.localPosZ - ((
                GameObject*)obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)newObj)->ownerObj = obj;
        }
    }
}

#pragma opt_common_subs off
#pragma dont_inline on
int fn_80202C78(int obj, int p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern f32 lbl_803E6370;
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
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}
#pragma dont_inline reset
#pragma opt_common_subs reset

#pragma dont_inline on
int fn_80202DA4(u8* obj, u8* p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern f32 lbl_803E6378;
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
        dy = (((GameObject*)obj)->anim.localPosY - *(f32*)(p6 + 0x10) >= zero)
                 ? ((GameObject*)obj)->anim.localPosY - *(f32*)(p6 + 0x10)
                 : -(((GameObject*)obj)->anim.localPosY - *(f32*)(p6 + 0x10));
        if (dy < lbl_803E6378)
        {
            return 1;
        }
    }
    cur = state->animSpeedA;
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}

#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2)
{

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
        bs->moveSpeed = lbl_803E6344 + state->aggression / lbl_803E6348;
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
    extern void fn_8003B5E0(int a, int b, int c, u8 d);
    extern void objParticleFn_80099d84(int, f32, int, f32, int);
    extern void ObjPath_GetPointWorldPosition(int, int, char*, char*, char*, int);
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62C8;
    GroundBaddieState* state;
    char* path;
    DbStealerwormControl* sub;

    state = ((GameObject*)obj)->extra;
    sub = (DbStealerwormControl*)state->control;
    if (*(void**)&sub->linkedObj != NULL)
    {
        *(f32*)(sub->linkedObj + 0xc) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(sub->linkedObj + 0x10) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(sub->linkedObj + 0x14) = ((GameObject*)obj)->anim.localPosZ;
        *(f32*)(sub->linkedObj + 0x10) += lbl_803E62D0;
    }
    if (visible == 0 || ((GameObject*)obj)->unkF4 != 0 || state->targetState == 0) { return; }
    {
        {
            if (state->glowAlpha != lbl_803E62A8)
            {
                fn_8003B5E0(0xc8, 0, 0, state->glowAlpha);
            }
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E62C8);
            if ((state->flags400 & 0x60) != 0)
            {
                objParticleFn_80099d84(obj, lbl_803E62C8, 3, state->glowAlpha, 0);
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

#pragma opt_propagation off
#pragma opt_common_subs off
#pragma fp_contract off
int dbstealerworm_stateHandlerA0D(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 lbl_803E62F0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E62EC;
    extern f32 lbl_803E62F8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E62B8;
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&((GameObject*)obj)->extra)->control;
    BaddieState* bs = (BaddieState*)p2;
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
        && ((GameObject*)bs->targetObj)->anim.localPosY - lbl_803E62F8 <= ((GameObject*)obj)->anim.localPosY)
    {
        obj = sub->msgStack;
        stk.msg9[0] = 9;
        stk.msg9[1] = 0;
        stk.msg9[2] = 0x24;
        if (Stack_IsFull(obj) == 0)
        {
            Stack_Push(obj, stk.msg9);
        }
        sub->unk34 = 1;
        tmp = *(int*)&bs->targetObj;
        obj = sub->msgStack;
        stk.msg7[0] = 7;
        stk.msg7[1] = 1;
        stk.msg7[2] = tmp;
        if (Stack_IsFull(obj) == 0)
        {
            Stack_Push(obj, stk.msg7);
        }
        sub->unk34 = 1;
        return 0;
    }
    else
    {
        stk.pos[0] = ((GameObject*)obj)->anim.localPosX;
        stk.pos[1] = ((GameObject*)obj)->anim.localPosY;
        stk.pos[2] = ((GameObject*)obj)->anim.localPosZ;
        stk.pos[1] = stk.pos[1] + lbl_803E62FC;
        stk.pos[0] = ((GameObject*)bs->targetObj)->anim.localPosX - stk.pos[0];
        stk.pos[1] = ((GameObject*)bs->targetObj)->anim.localPosY - stk.pos[1];
        stk.pos[2] = ((GameObject*)bs->targetObj)->anim.localPosZ - stk.pos[2];
        if (sqrtf(stk.pos[2] * stk.pos[2] + (stk.pos[0] * stk.pos[0] + stk.pos[1] * stk.pos[1])) < lbl_803E62B8)
        {
            tmp = *(int*)&bs->targetObj;
            obj = sub->msgStack;
            stk.msgE[0] = 0xe;
            stk.msgE[1] = 1;
            stk.msgE[2] = tmp;
            if (Stack_IsFull(obj) == 0)
            {
                Stack_Push(obj, stk.msgE);
            }
            sub->unk34 = 1;
        }
    }
    return 0;
}
#pragma fp_contract reset
#pragma opt_common_subs reset
#pragma opt_propagation reset

int dbstealerworm_stateHandlerB05(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int*);
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
        ((DbStealerwormFlags44*)&sub->flags44)->flag40 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, buf);
        }
        base = sub->cfg;
        n = (sub->routeCursor - *(int*)base) / 12;
        if (n >= *(s16*)(base + 4))
        {
            sub->routeCursor = 0;
        }
        if (*(void**)&sub->routeCursor == NULL)
        {
            sub->routeCursor = *(int*)sub->cfg;
            ((GameObject*)obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->homePosX;
            ((GameObject*)obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->homePosY;
            ((GameObject*)obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->homePosZ;
        }
        if (*(int*)(sub->routeCursor + 4) != 0)
        {
            *(int*)&((BaddieState*)p2)->targetObj = ObjGroup_FindNearestObjectForObject(
                *(int*)(sub->routeCursor + 4), obj, &range);
        }
        if (*(void**)&((BaddieState*)p2)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, p2, *(int*)sub->routeCursor);
        }
        return 0;
    }
    else
    {
        f32 t;
        if (*(void**)&sub->linkedObj == NULL && (t = sub->spawnAccumulator) > lbl_803E62B0)
        {
            sub->spawnAccumulator = t - lbl_803E62B0;
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

    extern void* Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern int lbl_80329640[];
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6384;
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
        obj, p3, st->aggroRange, 0x8000);
    if (near == 0 && (st->configFlags & 0x10) != 0)
    {
        near = ObjGroup_FindNearestObject(0x24, obj, &stk.range);
    }
    if (near == 0 && (st->configFlags & 0x10) != 0 && (st->configFlags & 2) == 0 && (((DbstealerwormPlacement*)data)->configFlags & 2) != 0)
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
            stk.d[0] = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            stk.d[1] = ((GameObject*)player)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
            stk.d[2] = ((GameObject*)player)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        }
        else
        {
            dist = lbl_803E6354;
        }
        if (sub->countdown > sub->nextSfxTime && dist < lbl_803E6384)
        {
            Sfx_PlayFromObject(obj, lbl_80329640[1]);
            sub->nextSfxTime = sub->nextSfxTime + (f32)(int)randomGetRange(0x32, 0xfa);
        }
        sub->countdown += timeDelta;
    }
}

int fn_80202A2C(int obj, int* objs, f32* weights, int n, f32 limit)
{


    extern f32 lbl_803E635C;
    extern f32 lbl_803E62C8;
    extern f32 gDbStealerwormPi;
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
    cosv = mathSinf(gDbStealerwormPi * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6364);
    sinv = mathCosf(gDbStealerwormPi * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6364);
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

int dbstealerworm_stateHandlerB06(int obj, int baddie)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int*);
    extern void Stack_Push(int, int*);

    extern int ObjGroup_ContainsObject(int, int);
    extern u8 lbl_80329514[];
    extern f32 lbl_803E62AC;
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
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedB != 0 || sub->unk34 != 0)
    {
        sub->flags15 &= ~4;
        sub->unk34 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0)
        {
            Stack_Pop(sub->msgStack, &sub->unk28);
        }
        else
        {
            if (((DbstealerwormPlacement*)data)->eventConfigId == 0xFFFFFFFF)
            {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = (char*)&lbl_80329514[((DbstealerwormPlacement*)data)->cfgTableIndex * 8];
            n = *(s16*)(entry + 4);
            off = n * 12;
            for (; n != 0;)
            {
                n--;
                Stack_Push(sub->msgStack, (int*)(*(int*)entry + (off -= 12)));
            }
            sub->unk34 = 1;
            ((GameObject*)obj)->anim.localPosX = ((DbstealerwormPlacement*)data)->homePosX;
            ((GameObject*)obj)->anim.localPosY = ((DbstealerwormPlacement*)data)->homePosY;
            ((GameObject*)obj)->anim.localPosZ = ((DbstealerwormPlacement*)data)->homePosZ;
        }
        switch (sub->unk2C)
        {
        case 0:
            if (sub->unk30 != 0)
            {
                *(int*)&((BaddieState*)baddie)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, &range);
            }
            break;
        case 1:
            *(int*)&((BaddieState*)baddie)->targetObj = sub->unk30;
            break;
        }
        if (*(void**)&((BaddieState*)baddie)->targetObj != NULL)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, baddie, *(int*)&sub->unk28);
        }
        return 0;
    }
    else
    {
        switch (sub->unk2C)
        {
        case 0:
            if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
            {
                sub->unk34 = 1;
            }
            else if (sub->unk30 != 0)
            {
                if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, sub->unk30) == 0)
                {
                    *(int*)&((BaddieState*)baddie)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, 0);
                    if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
                    {
                        sub->unk34 = 1;
                    }
                    ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
                }
            }
            break;
        case 1:
            if (*(void**)&((BaddieState*)baddie)->targetObj == NULL)
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

#pragma opt_common_subs off
int dbstealerworm_stateHandlerA0A(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern s16 Obj_GetYawDeltaToObject(int, int, f32*);
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
        if (*(void**)&sub->linkedObj != NULL && (s32)(((BaddieState*)p2)->eventFlags & 0x200) != 0)
        {
            t = *(int*)&((BaddieState*)p2)->targetObj;
            stk.v[0] = *(f32*)(t + 0xc) - ((GameObject*)obj)->anim.localPosX;
            stk.v[1] = *(f32*)(t + 0x10) - ((GameObject*)obj)->anim.localPosY;
            stk.v[2] = *(f32*)(t + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            {
                f32 sqx = stk.v[0] * stk.v[0];
                f32 sqz = stk.v[2] * stk.v[2];
                dist = sqrtf(sqx + sqz);
            }
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
#pragma opt_common_subs reset

int dbstealerworm_stateHandlerA0B(int obj, int baddie, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern int ObjGroup_ContainsObject(int, int);
    extern int* ObjGroup_GetObjects(int, int*);

    extern int Obj_GetPlayerObject(void);
    extern int* seqFn_800394a0(void);
    extern s16* objModelGetVecFn_800395d8(int, int);
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
    if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, c30) == 0)
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
    q = *(int*)&((BaddieState*)baddie)->targetObj;
    found = 0;
    objs = ObjGroup_GetObjects(3, &cnt2);
    for (i = 0; i < cnt2; i++)
    {
        if (*(s16*)(*objs + 0x46) == 0x539)
        {
            if ((u32)(**(int (**)(int, int, int))(*(int*)(*(int*)(*objs + 0x68)) + 0x24))(*objs, 0x83, 0) == q)
            {
                found = 1;
            }
        }
        objs++;
    }
    if (found == 0)
    {
        if ((u32)obj == ObjGroup_FindNearestObject(3, *(int*)&((BaddieState*)baddie)->targetObj, 0))
        {
            sub->unk3C = *(int*)&((BaddieState*)baddie)->targetObj;
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
    ((BaddieState*)baddie)->unk34D = 0x1f;
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
        ((BaddieState*)baddie)->moveDone = 0;
    }
    if (*(void**)&sub->unk3C != NULL)
    {
        if (ObjGroup_ContainsObject(*(int*)&((BaddieState*)baddie)->targetObj, c30) != 0)
        {
            tmpB = sub->unk2C;
            tmpA = sub->unk30;
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
    frac = blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int*)&((BaddieState*)baddie)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032971C, lbl_8032972C, 4, frac);
    }
    player = Obj_GetPlayerObject();
    d = Obj_GetYawDeltaToObject(obj, player, &yawf);
    flag = 0;
    if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < lbl_803E62D0)
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
        *(int*)&((BaddieState*)baddie)->targetObj = player;
        tmpB = sub->unk2C;
        tmpA = sub->unk30;
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

int dbstealerworm_stateHandlerA07(int obj, int baddie, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern int Obj_GetPlayerObject(void);
    extern int* seqFn_800394a0(void);
    extern s16* objModelGetVecFn_800395d8(int, int);
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
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_ClearHitVolumes(obj);
    ((BaddieState*)baddie)->moveSpeed = lbl_803E62F4;
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
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        frac = blob->aggression / lbl_803E62C4;
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
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        ((BaddieState*)baddie)->moveSpeed = lbl_803E6300;
        frac = blob->aggression / lbl_803E6324;
    }
    ((BaddieState*)baddie)->unk34D = 0x1f;
    if (fn_80202DA4((u8*)obj, *(u8**)&((BaddieState*)baddie)->targetObj, lbl_803E6330, frac, lbl_803E62CC, t) != 0)
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
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < lbl_803E62D0)
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
            *(int*)&((BaddieState*)baddie)->targetObj = player;
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
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = -(lbl_803E6328 * ((BaddieState*)baddie)->animSpeedA);
        flag = -(lbl_803E6328 * ((BaddieState*)baddie)->animSpeedB);
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
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}

#pragma opt_loop_invariants off
#pragma opt_propagation off
void dbstealerworm_update(u8* objp)
{
    extern void Stack_Push(int sp, int* args);
    extern int allocModelStruct_800139e8(int, int);
    extern int ObjMsg_Pop(int, u32*, int*, int*);
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E6388;
    extern f32 lbl_803E638C;
    extern u8 lbl_803AD0C0[];
    extern u8 lbl_803293B8[];
    char* st;
    char* tbl;
    int blob;
    int data;
    int sub;
    int obj;
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

    obj = (int)objp;
    st = (char*)(int)lbl_803AD0C0;
    tbl = (char*)lbl_803293B8;
    blob = *(int*)(obj + 0xb8);
    data = *(int*)(obj + 0x4c);
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
            int stk = ((DbStealerwormControl*)sub)->msgStack;
            int base = *(int*)entry;
            n--;
            Stack_Push(stk, (int*)(base + (off -= 12)));
        }
        ((DbStealerwormControl*)sub)->unk34 = 1;
        ((DbStealerwormFlags44*)&((DbStealerwormControl*)sub)->flags44)->flag10 = 0;
    }
    if (GameBit_Get(((GroundBaddieState*)blob)->gameBitC) != 0)
    {
        if (((GameObject*)obj)->unkF4 != 0)
        {
            if ((((GroundBaddieState*)blob)->configFlags & 4) == 0 &&
                (*gMapEventInterface)->shouldNotSaveTime(*(int*)&((DbstealerwormPlacement*)data)->eventConfigId) != 0)
            {
                ((void (*)(int, int, int, int, int, int, int, f32))((void**)*gBaddieControlInterface)[22])(
                    obj, data, blob, 0x10, 7, 0x10a, 0x26, lbl_803E62FC);
                ObjGroup_AddObject(obj, 3);
                ((GroundBaddieState*)blob)->targetState = 0;
                ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0x10);
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
                    stk.v[0] = *(f32*)(t + 0x18) - ((GameObject*)obj)->anim.worldPosX;
                    stk.v[1] = *(f32*)(t + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
                    stk.v[2] = *(f32*)(t + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
                    ((GroundBaddieState*)blob)->baddie.targetDistance = sqrtf(
                        stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
                while (ObjMsg_Pop(obj, &stk.msg, &stk.argB, (int*)(&stk.msg + 1)) != 0)
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
                    (char*)(int)lbl_803AD0C0) != 0)
                {
                    *(f32*)(st + 0xc) = ((GameObject*)obj)->anim.localPosX;
                    *(f32*)(st + 0x10) = ((GameObject*)obj)->anim.localPosY;
                    ((GroundBaddieState*)st)->baddie.posX = ((GameObject*)obj)->anim.localPosZ;
                    objLightFn_8009a1dc((void*)obj, lbl_803E638C, (char*)(int)lbl_803AD0C0, 1, 0);
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
#pragma opt_propagation reset

int dbstealerworm_stateHandlerA08(int obj, int baddie, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern int Obj_GetPlayerObject(void);
    extern int* seqFn_800394a0(void);
    extern s16* objModelGetVecFn_800395d8(int, int);
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
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
        ObjHits_ClearHitVolumes(obj);
    }
    ((BaddieState*)baddie)->moveSpeed = lbl_803E62F4;
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
        if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState*)baddie)->moveDone = 0;
        }
        ((BaddieState*)baddie)->moveSpeed = lbl_803E6300;
        frac = blob->aggression / lbl_803E6324;
    }
    ((BaddieState*)baddie)->unk34D = 0x1f;
    if (fn_80202C78(obj, *(int*)&((BaddieState*)baddie)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t) != 0)
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
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (((s16)d >= 0 ? (s16)d : -(s16)d) < 0x1c71 && yawf < lbl_803E62D0)
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
            *(int*)&((BaddieState*)baddie)->targetObj = player;
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
    }
    else if (*(void**)&sub->linkedObj == NULL)
    {
        d = (s16)-(lbl_803E6328 * ((BaddieState*)baddie)->animSpeedA);
        flag = (s16)-(lbl_803E6328 * ((BaddieState*)baddie)->animSpeedB);
        if (d < -0x500)
        {
            d = -0x500;
        }
        else if (d > 0x500)
        {
            d = 0x500;
        }
        sa = d;
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
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}

int dbstealerworm_stateHandlerA0C(int obj, int baddie, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern void fn_80137948(char* fmt, ...);
    extern int Obj_GetPlayerObject(void);
    extern int* ObjGroup_GetObjects(int, int*);
    extern f32 Vec_xzDistance(int, int);
    extern f32 vec3f_distanceSquared(int, int);

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
    if (*(s8*)&((BaddieState*)baddie)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        ((BaddieState*)baddie)->moveDone = 0;
    }
    ((BaddieState*)baddie)->moveSpeed = lbl_803E6300;
    frac = blob->aggression / lbl_803E62B8;
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
    ratio = (Vec_xzDistance(obj + 0x18, player + 0x18) - lbl_803E6304) / (lbl_803E6308 * blob->aggression);
    n = (int)(ratio < lbl_803E62A8 ? lbl_803E62A8 : (ratio > lbl_803E62B0 ? lbl_803E62B0 : ratio));
    fn_80137948(tbl + 0x444, n);
    player = Obj_GetPlayerObject();
    best = 0;
    bestD = lbl_803E62A8;
    objs = ObjGroup_GetObjects(c30, &cnt);
    for (i = 0; i < cnt; i++)
    {
        o = *objs;
        if ((u32)o != player)
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
        if ((u32)best != obj)
        {
            if (*(s16*)(best + 0x46) == 0x539)
            {
                *(int*)&((BaddieState*)baddie)->targetObj = best;
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

int dbstealerworm_stateHandlerA0F(int obj, int baddie, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int* args);
    extern f32 Vec_xzDistance(int, int);

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
    int tmpB;
    int tmpA;
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
    if (((GameObject*)((BaddieState*)baddie)->targetObj)->objectFlags & 0x1000)
    {
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
        ((BaddieState*)baddie)->moveSpeed = lbl_803E62C0;
        return 0;
    }
    frac = blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int*)&((BaddieState*)baddie)->targetObj, lbl_803E62C8, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0)
    {
        fn_80202A2C(obj, lbl_8032973C, lbl_8032974C, 4, frac);
    }
    d = Vec_xzDistance(obj + 0x18, (int)&((GameObject*)((BaddieState*)baddie)->targetObj)->anim.worldPosX);
    ((BaddieState*)baddie)->unk34D = 1;
    if (d < lbl_803E62D0)
    {
        {
            f32 k = lbl_803E62D4;
            ((BaddieState*)baddie)->animSpeedA *= k;
            ((BaddieState*)baddie)->animSpeedB *= k;
        }
        target = *(int*)&((BaddieState*)baddie)->targetObj;
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
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = lbl_803E62A8;
        target = *(int*)&((BaddieState*)baddie)->targetObj;
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
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState*)baddie)->animSpeedA,
                                                                        (float*)(baddie + 0x2a0));
    return 0;
}

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408). */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
