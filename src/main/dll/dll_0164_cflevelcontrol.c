/* DLL 0x0164 — cflevelcontrol (CloudRunner Fortress level controller). TU: 0x801A4524–0x801A4DB8. */
#include "main/dll/DR/dll_015A_explodable.h"
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct CflevelcontrolState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xD - 0xC];
    s8 unkD;
    u8 padE[0x10 - 0xE];
} CflevelcontrolState;

extern undefined8 FUN_80017698();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void s16toFloat(void* p, int duration);
extern void Sfx_PlayFromObject(int obj, int sfxId);

void FUN_801a4520(int param_1)
{
    int iVar1;

    if (((GameObject*)param_1)->unkF4 == 0)
    {
        iVar1 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if ((*(short*)(iVar1 + 0x1c) != 0) && (**(byte**)&((GameObject*)param_1)->extra >> 5 != 0))
        {
            (*gObjectTriggerInterface)->preempt(param_1, *(s16*)(iVar1 + 0x1c));
        }
        iVar1 = (int)*(char*)(iVar1 + 0x1e);
        if (iVar1 != -1)
        {
            (*gObjectTriggerInterface)->runSequence(iVar1, (void*)param_1, -1);
        }
        ((GameObject*)param_1)->unkF4 = 1;
    }
    return;
}

void FUN_801a45cc(short* param_1, int param_2)
{
}

void cflevelcontrol_free(int param_1)
{
}

undefined4
FUN_801a4810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, undefined4 param_10, int param_11)
{
    undefined4 uVar1;
    int iVar2;
    undefined8 uVar3;

    for (iVar2 = 0; iVar2 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar2 = iVar2 + 1)
    {
        if (*(char*)(param_11 + iVar2 + 0x81) == '\x01')
        {
            FUN_80017698(0xdcb, 1);
            uVar3 = FUN_80017698(0x4a3, 0);
            FUN_80041ff8(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x2b);
            FUN_80042b9c(0, 0, 1);
            uVar1 = FUN_80044404(0x2b);
            FUN_80042bec(uVar1, 0);
        }
    }
    return 0;
}

void cfforcefield_release(void);

void cflevelcontrol_hitDetect(void)
{
}

void cflevelcontrol_release(void)
{
}

void cflevelcontrol_initialise(void)
{
}

extern void storeZeroToFloatParam(void* p);
extern s16 lbl_80323008[];

void cflevelcontrol_init(u8* obj, u8* params)
{
    extern void objSetSlot(void* obj, int resourceId); /* #57 */
    typedef struct LevelControlFlags
    {
        u8 b7 : 1;
        u8 b6 : 1;
        u8 b5 : 1;
        u8 b4 : 1;
        u8 b3 : 1;
        u8 rest : 3;
    } LevelControlFlags;
    u8* sub;
    int i;

    sub = ((GameObject*)obj)->extra;
    ((CflevelcontrolState*)sub)->unk8 = 0;
    ((CflevelcontrolState*)sub)->unkD = -1;
    storeZeroToFloatParam(sub);
    s16toFloat(sub, 0x1e0);
    ((LevelControlFlags*)(sub + 0xc))->b6 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)CFLevelControl_SeqFn;
    GameBit_Set(0x983, *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) != 0x2cef);
    if (GameBit_Get(0x2fe) == 0)
    {
        for (i = 0; i < 0x17; i++)
        {
            GameBit_Set(lbl_80323008[i], 0);
        }
    }
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x11, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x15, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x16, 0);
    ((LevelControlFlags*)(sub + 0xc))->b5 = (u8)GameBit_Get(0x974);
    ((LevelControlFlags*)(sub + 0xc))->b4 = (u8)GameBit_Get(0x975);
    objSetSlot(obj, 0x51);
    ((LevelControlFlags*)(sub + 0xc))->b3 = 1;
}

void exploded_free(void);

int cflevelcontrol_getExtraSize(void) { return 0x10; }
int cflevelcontrol_getObjectTypeId(void) { return 0x0; }
int exploded_getExtraSize(void);

extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E43E8;

void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43E8);
}

void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern int ObjList_FindObjectById(int objectId);
extern void fn_8017C294(int obj);
extern void getEnvfxActImmediately(void* obj, void* target, int animId, int flags);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void unlockLevel(int a, int b, int c);
extern int playerIsDisguised(int player);
extern void fn_80295CF4(int player, int mode);
extern int getCurMapLayer(void);
extern int lbl_802C22E8[];
extern f32 lbl_803E43EC;
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void SCGameBitLatch_UpdateInverted(void* latch, int mask, int clearIfSetBit,
                                          int clearIfClearBit, int latchBit, int musicId);

void cflevelcontrol_update(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    int player = (int)Obj_GetPlayerObject();
    int triggerPos[3];
    u32 bit974;
    u32 bit975;
    u32 old974;
    u32 bit94e;
    int cameraMode;

    triggerPos[0] = lbl_802C22E8[0];
    triggerPos[1] = lbl_802C22E8[1];
    triggerPos[2] = lbl_802C22E8[2];

    if (((u32)state[0xc] >> 3 & 1) != 0)
    {
        fn_8017C294(ObjList_FindObjectById(0x47fae));
        fn_8017C294(ObjList_FindObjectById(0x47f83));
        fn_8017C294(ObjList_FindObjectById(0x47f8f));
        fn_8017C294(ObjList_FindObjectById(0x47fa2));
        fn_8017C294(ObjList_FindObjectById(0x29f2));
        fn_8017C294(ObjList_FindObjectById(0x29f3));
        fn_8017C294(ObjList_FindObjectById(0x29ef));
        fn_8017C294(ObjList_FindObjectById(0x29ee));
        state[0xc] = (u8)(state[0xc] & ~0x08);
    }

    if ((*gMapEventInterface)->getMode(0x1d) == 1 &&
        GameBit_Get(0x40) != 0)
    {
        (*gMapEventInterface)->setMode(0x1d, 2);
    }

    bit974 = (u8)GameBit_Get(0x974);
    bit975 = (u8)GameBit_Get(0x975);
    old974 = ((u32)state[0xc] >> 5) & 1;

    if (old974 == 0 || (((u32)state[0xc] >> 4) & 1) == 0)
    {
        if (old974 == 0 && (((u32)state[0xc] >> 4) & 1) == 0)
        {
            if (bit974 != 0 || bit975 != 0)
            {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
        }
        else if (bit974 != 0 && bit975 != 0)
        {
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        }
    }

    state[0xc] = (u8)((state[0xc] & ~0x20) | ((bit974 & 1) << 5));
    state[0xc] = (u8)((state[0xc] & ~0x10) | ((bit975 & 1) << 4));

    if (((GameObject*)obj)->unkF4 == 0)
    {
        getEnvfxActImmediately((void*)obj, (void*)obj, 0x56, 0);
        if (GameBit_Get(0xd73) == 0)
        {
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x11, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xe, 0);
            skyFn_80088e54(0, lbl_803E43EC);
            GameBit_Set(0xd73, 1);
        }

        if (GameBit_Get(0xdca) != 0)
        {
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x7e, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x7d, 0);
            skyFn_80088e54(1, lbl_803E43EC);
            GameBit_Set(0xdca, 0);
            unlockLevel(0, 0, 1);
        }

        ((GameObject*)obj)->unkF4 = 1;
    }

    if (GameBit_Get(0x94f) != 0 && (((GameObject*)player)->objectFlags & 0x1000) == 0)
    {
        GameBit_Set(0x94e, 0);
    }

    bit94e = GameBit_Get(0x94e);
    if (bit94e != 0)
    {
        if (playerIsDisguised(player) == 0)
        {
            fn_80295CF4((int)Obj_GetPlayerObject(), 0);
        }
    }
    else if (playerIsDisguised(player) == 0)
    {
        fn_80295CF4((int)Obj_GetPlayerObject(), 1);
    }

    if (GameBit_Get(0xd3d) != 0)
    {
        ((void (*)(int*, int, int, int))(*(int*)((u8*)*gMapEventInterface + 0x24)))(
            triggerPos, 0, getCurMapLayer(), 1);
        GameBit_Set(0xd3d, 0);
        getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
        getEnvfxActImmediately((void*)obj, (void*)obj, 0x11, 0);
        skyFn_80088e54(1, lbl_803E43E8);
    }

    cameraMode = (*gCameraInterface)->getMode();
    if (cameraMode == 0x47)
    {
        if ((s8)state[0xd] != 0x47)
        {
            GameBit_Set(0xc0, 1);
        }
    }
    else if ((s8)state[0xd] == 0x47)
    {
        GameBit_Set(0x1a8, 1);
    }
    state[0xd] = (s8)(*gCameraInterface)->getMode();

    SCGameBitLatch_Update(state + 8, 4, -1, -1, 0x983, 0xb0);
    SCGameBitLatch_Update(state + 8, 8, -1, -1, 0x983, 0x38);
    SCGameBitLatch_UpdateInverted(state + 8, 0x100, -1, -1, 0x983, 0x16);
    SCGameBitLatch_UpdateInverted(state + 8, 0x80, -1, -1, 0x983, 0x39);

    if (GameBit_Get(0x983) == 0)
    {
        if (GameBit_Get(0xe23) == 0)
        {
            SCGameBitLatch_UpdateInverted(state + 8, 0x200, -1, -1, 0x984, 0xad);
            SCGameBitLatch_Update(state + 8, 0x40, -1, -1, 0x984, 0x16);
        }
        if (GameBit_Get(0x984) != 0)
        {
            SCGameBitLatch_Update(state + 8, 0x20, -1, -1, 0xe23, 0x17);
            SCGameBitLatch_UpdateInverted(state + 8, 0x400, -1, -1, 0xe23, 0x16);
        }
    }

    SCGameBitLatch_Update(state + 8, 1, 0x1a8, 0xc0, 0xdb8, 0xae);
    SCGameBitLatch_Update(state + 8, 0x10, -1, -1, 0xe1d, 0x36);
    SCGameBitLatch_Update(state + 8, 0x1000, -1, -1, 0xe1d, 0xf1);
    SCGameBitLatch_Update(state + 8, 2, -1, -1, 0xb46, 0xaf);
    SCGameBitLatch_Update(state + 8, 0x800, -1, -1, 0xcbb, 0xc4);
}

void attractor_free(int x);

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */

extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int b);

int CFLevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            GameBit_Set(0xdcb, 1);
            GameBit_Set(0x4a3, 0);
            loadMapAndParent(0x2b);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x2b), 0);
            break;
        }
    }
    return 0;
}

void cfforcefield_init(s16* obj, void* data);

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
