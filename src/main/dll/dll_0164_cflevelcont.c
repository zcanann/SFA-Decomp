/* === moved from main/dll/DR/gasventControl.c [801A39B4-801A39D0) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/DR/dll_015A_explodable.h"
#include "main/obj_placement.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjGroup_AddObject();


/*
 * --INFO--
 *
 * Function: blasted_init
 * EN v1.0 Address: 0x801A2AF8
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801A2B9C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801a2cb8
 * EN v1.0 Address: 0x801A2CB8
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801A2D6C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801a32d4
 * EN v1.0 Address: 0x801A32D4
 * EN v1.0 Size: 800b
 * EN v1.1 Address: 0x801A3190
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */



void cfforcefield_free(void);

void cfforcefield_render(void);

void cfforcefield_hitDetect(void);

/* 8b "li r3, N; blr" returners. */







/* explodable_getExtraSize == 0x6e8 (gas-vent explodable). */
/* Per-fragment record inside DrExplodableState (stride 0x70). */
typedef struct DrExplodableChunk
{
    u8 pad00[4];
    f32 centroidX; /* 0x04: model vertex average */
    f32 centroidY; /* 0x08 */
    f32 centroidZ; /* 0x0c */
    f32 offX; /* 0x10: rotated launch offset */
    f32 offY; /* 0x14 */
    f32 offZ; /* 0x18 */
    f32 spinX; /* 0x1c */
    f32 spinY; /* 0x20 */
    f32 spinZ; /* 0x24 */
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    f32 unk38;
    f32 unk3C;
    f32 velX; /* 0x40 */
    f32 velY; /* 0x44 */
    f32 velZ; /* 0x48 */
    f32 posX; /* 0x4c */
    f32 posY; /* 0x50 */
    f32 posZ; /* 0x54 */
    f32 height;
    int unk5C;
    int launchDelay; /* 0x60: per-fragment delay roll, -1 = none */
    s16 unk64; /* 0x64: from def+0x1e */
    s16 unk66; /* 0x66: from def+0x1c */
    s16 unk68; /* 0x68: from def+0x1a */
    u8 gameBitMode; /* 0x6a: gamebit-gated mode */
    u8 unk6B; /* 0x6b: init 0xff */
    u8 launchFlags; /* 0x6c: axis sign bits */
    u8 spinScale; /* 0x6d */
    u8 pad6E[2];
} DrExplodableChunk;

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

typedef struct DrExplodableState
{
    DrExplodableChunk chunks[15]; /* 0x000 */
    int children[15]; /* 0x690: spawned fragment objects */
    u32 flags6CC;
    int unk6D0;
    u8 count6D4;
    u8 spawnedFlags[15]; /* 0x6d5 */
    u8 phase6E4;
    u8 unk6E5;
    u8 pad6E6[2];
} DrExplodableState;

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

int cfforcefield_getExtraSize(void);
int cfforcefield_getObjectTypeId(void);

extern void Obj_FreeObject(int obj);
#pragma scheduling off
#pragma peephole off










extern void Model_GetVertexPosition(int model, int i, f32* out);



#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct CfmagicwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfmagicwallPlacement;


typedef struct CfforcefieldPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfforcefieldPlacement;


typedef struct CflevelcontrolState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xD - 0xC];
    s8 unkD;
    u8 padE[0x10 - 0xE];
} CflevelcontrolState;


typedef struct SlidingdoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} SlidingdoorPlacement;


extern undefined8 FUN_80017698();
extern undefined8 ObjGroup_RemoveObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void Obj_BuildWorldTransformMatrix(void* obj, f32* mtx, int flags);
extern void PSMTXMultVecSR(f32 * mtx, f32 * src, f32 * dst);
extern f32 mathCosf(f32 angle);
extern f32 mathSinf(f32 angle);
extern int fn_80080150(void* timer);
extern void s16toFloat(void* p, int duration);
extern int timerCountDown(void* timer);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern EffectInterface** gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803DBE90;
extern int lbl_803DBE94;
extern int lbl_803DBE98;
extern int lbl_80322ED8[];
extern f32 lbl_803E4390;
extern f32 lbl_803E4394;
extern f32 lbl_803E4398;
extern f32 lbl_803E439C;
extern f32 lbl_803E43A0;
extern f32 lbl_803E43A4;
extern f32 lbl_803E43A8;
extern f32 lbl_803E43AC;

/*
 * --INFO--
 *
 * Function: cfforcefield_update
 * EN v1.0 Address: 0x801A39D0
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801A3B20
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfforcefield_update(u8* obj);


/*
 * --INFO--
 *
 * Function: FUN_801a4520
 * EN v1.0 Address: 0x801A4520
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A4660
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_801a45cc
 * EN v1.0 Address: 0x801A45CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A4708
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45cc(short* param_1, int param_2)
{
}


/*
 * --INFO--
 *
 * Function: cflevelcontrol_free
 * EN v1.0 Address: 0x801A45D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A4880
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cflevelcontrol_free(int param_1)
{
}


/*
 * --INFO--
 *
 * Function: FUN_801a4810
 * EN v1.0 Address: 0x801A4810
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A4AD8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/* Trivial 4b 0-arg blr leaves. */
void cfforcefield_release(void);

void cfforcefield_initialise(void);

void slidingdoor_free(void);

void slidingdoor_hitDetect(void);

void slidingdoor_release(void);

void slidingdoor_initialise(void);

void attractor_hitDetect(void);

void attractor_update(void);

void attractor_release(void);

void attractor_initialise(void);

void cfmagicwall_free(void);

void cfmagicwall_hitDetect(void);

void cfmagicwall_release(void);

void cfmagicwall_initialise(void);

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

void exploded_hitDetect(void);

void exploded_release(void);

void exploded_initialise(void);

/* 8b "li r3, N; blr" returners. */
int slidingdoor_getExtraSize(void);
int slidingdoor_getObjectTypeId(void);
int attractor_getExtraSize(void);
int attractor_getObjectTypeId(void);
int cfmagicwall_getExtraSize(void);
int cfmagicwall_getObjectTypeId(void);
int cflevelcontrol_getExtraSize(void) { return 0x10; }
int cflevelcontrol_getObjectTypeId(void) { return 0x0; }
int exploded_getExtraSize(void);

/* Pattern wrappers. */
u8 exploded_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E43BC;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43D0;
extern f32 lbl_803E43D8;
extern f32 lbl_803E43DC;
extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(void* a, void* b);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803E43E8;
extern f32 lbl_803E43F4;

void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43E8);
}

void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cfmagicwall_update(int obj);

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

/* ObjGroup_RemoveObject(x, N) wrappers. */
void attractor_free(int x);

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 exploded_getObjectTypeId(ExplodedObject* obj);

/* byte-to-short shift8 pattern. */
void cfmagicwall_init(s16* dst, void* src);

/* attractor_setScale: branch on s8 flag at +0x19 of obj->_4C; if set return s16 at +0x1a, else 0. */
int attractor_setScale(int* obj);

/* attractor_init: ObjGroup_AddObject(obj, 0x1e); byte<<8 -> sth at obj. */
void attractor_init(s16* obj, void* data);

extern u8 framesThisStep;

void exploded_update(int* obj);

extern f32 lbl_803E43B8;
extern f32 lbl_803E43C0;
extern f32 lbl_803E4428;
extern void* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern int atan2i(int y, int x);

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */
int slidingdoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate);

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */
void slidingdoor_update(u8* obj);

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */
void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra);

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */
void attractor_func0B(u8* obj, void** out);

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */
void slidingdoor_init(u8* obj, u8* data);

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

/* cfforcefield_init: byte<<8 sth; insert GameBit_Get bit into bit-7 of *(u8*)obj->_B8; storeZeroToFloatParam. */
void cfforcefield_init(s16* obj, void* data);

extern void Obj_TransformLocalPointByWorldMatrix(void* obj, void* state, f32* out, int flags);
extern void fn_80065684(double x, double y, double z, void* obj, f32* out, int flags);
extern f32 lbl_803E43F0;
extern f32 lbl_803E4400;
extern f32 lbl_803E4404;
extern f32 lbl_803E4408;
extern f32 lbl_803E4418;
extern f32 lbl_803E441C;
extern f32 lbl_803E4420;
extern f32 lbl_803E4424;


void exploded_initDebrisState(ExplodedObject* obj, ExplodedObjectMapData* data, int computeModelCenter, ExplodedObjectState* state);


/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */
void exploded_seedDebrisMotion(ExplodedObject* obj, ExplodedObjectState* state, ExplodedObjectMapData* data);

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
int exploded_stepDebrisPhysics(ExplodedObject* obj, ExplodedObjectState* state);
