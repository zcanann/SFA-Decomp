/* === moved from main/dll/dim_bossgut.c [801D286C-801D2C54) (TU re-split, docs/boundary_audit.md) === */
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/ediblemushroom.h"

#include "main/dll/bombplant_placement.h"


typedef struct EnemymushroomPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    u16 unk18;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} EnemymushroomPlacement;


extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017a30();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern undefined4 FUN_80017a68();
extern int FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_80081120();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern double FUN_80294c4c();
extern byte FUN_80294ca8();
extern int FUN_80294cb0();

extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e5fa0;
extern f64 DOUBLE_803e5fe0;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E5F90;
extern f32 lbl_803E5F94;
extern f32 lbl_803E5FB0;
extern f32 lbl_803E5FB4;
extern f32 lbl_803E5FB8;
extern f32 lbl_803E5FBC;
extern f32 lbl_803E5FC0;
extern f32 lbl_803E5FC4;
extern f32 lbl_803E5FC8;
extern f32 lbl_803E5FCC;
extern f32 lbl_803E5FD0;
extern f32 lbl_803E5FD4;
extern f32 lbl_803E5FD8;

/*

/*
 * --INFO--
 *
 * Function: enemymushroom_release
 * EN v1.0 Address: 0x801D2864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: enemymushroom_initialise
 * EN v1.0 Address: 0x801D2868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: bombplant_getExtraSize
 * EN v1.0 Address: 0x801D2B34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_getExtraSize(void)
{
    return 0x18;
}

/*
 * --INFO--
 *
 * Function: bombplant_getObjectTypeId
 * EN v1.0 Address: 0x801D2B3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplant_getObjectTypeId(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: bombplant_free
 * EN v1.0 Address: 0x801D2B44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_free(void)
{
}

/*
 * --INFO--
 *
 * Function: bombplant_hitDetect
 * EN v1.0 Address: 0x801D2B6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplant_hitDetect(void)
{
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E5370;
extern void objRenderFn_8003b8f4(f32);
void bombplant_render(void) { objRenderFn_8003b8f4(lbl_803E5370); }

extern void* getTrickyObject(void);
extern void trickyImpress(void* trickyObj);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void fn_801D29E4(int* obj, int* p2);
extern f32 lbl_803E5378;

void fn_801D2B70(int* obj, int unused, int* p3)
{
    int* p4 = *(int**)&((GameObject*)obj)->anim.placementData;
    void* trickyObj = getTrickyObject();
    s16 gbId;
    int i;
    if (trickyObj != NULL)
    {
        trickyImpress(trickyObj);
    }
    Sfx_PlayFromObject(obj, SFXmv_curtainrustle);
    {
        int* p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        ((ObjHitsPriorityState*)p)->flags = (s16)(((ObjHitsPriorityState*)p)->flags | 0x40);
    }
    spawnExplosion((int)obj, lbl_803E5378, 0, 1, 1, 1, 0, 1, 0);
    *(u8*)((char*)p3 + 0x14) = 1;
    *(u8*)((char*)p3 + 0x15) = (u8)(*(u8*)((char*)p3 + 0x15) | 2);
    gbId = *(s16*)((char*)p4 + 0x1c);
    if (gbId != -1)
    {
        GameBit_Set(gbId, 0);
    }
    else
    {
        for (i = 0; i < 3; i++)
        {
            fn_801D29E4(obj, p3);
        }
    }
}

extern void ObjGroup_AddObject(int* obj, int group);
extern f32 lbl_803E52FC;
extern f32 lbl_803E5350;

/* EN v1.0 0x801D27B8  size: 172b  Mushroom enemy constructor: seeds the state
 * block, clamps the spin period, offsets the spawn height, flags the model,
 * optionally resets to spawn, and registers in object group 3. */
void enemymushroom_init(EnemyMushroomObject* obj, EnemyMushroomMapData* arg, int flag);

extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern void setMatrixFromObjectPos(void* mtx, void* build);
extern void Matrix_TransformPoint(void* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E536C;
extern f32 lbl_803E5374;

typedef struct
{
    s16 pos[3];
    f32 w;
    f32 v[3];
} MushSpawnBuild;

/* EN v1.0 0x801D29E4  size: 336b  Spawns a spore object: builds a matrix from
 * the parent's grid pos, transforms a unit offset, and seeds the new object. */
void fn_801D29E4(int* obj, int* p2)
{
    int* spore;
    int* base = *(int**)&((GameObject*)obj)->anim.placementData;

    if (Obj_IsLoadingLocked())
    {
        MushSpawnBuild bd;
        f32 mtx[4][4];
        f32 tz, ty, tx;
        f32 sx;

        spore = Obj_AllocObjectSetup(0x24, 0x198);
        bd.pos[0] = ((GameObject*)obj)->anim.rotX;
        bd.pos[1] = ((GameObject*)obj)->anim.rotY;
        bd.pos[2] = ((GameObject*)obj)->anim.rotZ;
        bd.v[0] = lbl_803E536C;
        bd.v[1] = lbl_803E536C;
        bd.v[2] = lbl_803E536C;
        bd.w = lbl_803E5370;
        setMatrixFromObjectPos(mtx, &bd);
        Matrix_TransformPoint(mtx, lbl_803E536C, lbl_803E5370, lbl_803E536C, &tx, &ty, &tz);
        sx = lbl_803E5374 * tx;
        bd.v[0] = sx;
        bd.v[1] = lbl_803E5374 * ty;
        bd.v[2] = lbl_803E5374 * tz;
        *(f32*)((char*)spore + 0x8) = ((GameObject*)obj)->anim.localPosX + sx;
        *(f32*)((char*)spore + 0xc) = ((GameObject*)obj)->anim.localPosY + bd.v[1];
        *(f32*)&((ObjDef*)spore)->jointData = ((GameObject*)obj)->anim.localPosZ + bd.v[2];
        *(u8*)((char*)spore + 0x5) = 1;
        *(u8*)((char*)spore + 0x4) = 2;
        *(s16*)((char*)spore + 0x1a) = (s16)((s8) * (s8*)((char*)base + 0x1e) << 8);
        *(s16*)((char*)spore + 0x1c) = ((GameObject*)obj)->anim.rotX;
        Obj_SetupObject(spore, 5, -1, -1, 0);
    }
}

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E5358;
extern f32 lbl_803E535C;

/* EN v1.0 0x801D286C  size: 376b  Bombplant per-tick sequencer: on the armed
 * frame snaps the model to the spawn pose and refreshes hits; otherwise keeps
 * the loop sfx alive, jitters the fuse, and fires the spark particle. */
int bombplant_SeqFn(int* obj)
{
    extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int id); /* #57 */
    extern void ObjHits_RefreshObjectState(int* obj); /* #57 */
    extern u32 randomGetRange(int min, int max); /* #57 */
    float* state = ((GameObject*)obj)->extra;

    if (((EnemyMushroomState*)state)->resetToSpawn != 0)
    {
        int* src;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        src = *(int**)&((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)src)->unk8;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)src)->unkC;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)src)->unk10;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5358;
        ((EnemyMushroomState*)state)->riseDuration = lbl_803E535C;
        ((EnemyMushroomState*)state)->heightTarget = ((EnemyMushroomState*)state)->baseScale;
        ((EnemyMushroomState*)state)->riseStep = ((EnemyMushroomState*)state)->heightTarget / ((EnemyMushroomState*)
            state)->riseDuration;
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->riseDuration;
        ObjHits_RefreshObjectState(obj);
        ((EnemyMushroomState*)state)->resetToSpawn = 0;
        ((EnemyMushroomState*)state)->flags = (u8)(((EnemyMushroomState*)state)->flags | 2);
    }
    else
    {
        int* base;
        u8 flags;
        Sfx_KeepAliveLoopedObjectSound(obj, 0x3fd);
        base = *(int**)&((GameObject*)obj)->anim.placementData;
        flags = ((EnemyMushroomState*)state)->flags;
        if (flags & 0x2)
        {
            int v;
            ((EnemyMushroomState*)state)->flags = (u8)(flags & ~0x2);
            v = ((BombplantPlacement*)base)->unk1A + randomGetRange(-0x32, 0x32);
            ((EnemyMushroomState*)state)->timer = (f32)v;
        }
        if (((GameObject*)obj)->objectFlags & 0x800)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
        }
    }
    return 0;
}

extern int objIsFrozen(int* obj);
extern f32 Vec_distance(f32 * a, f32 * b);
extern int EmissionController_IsLingering(u8 * player);
extern int fn_80296448(u8 * player);
extern f32 fn_8029610C(u8 * player);
extern void objFn_8002b67c(int* obj);
extern void Obj_ResetModelColorState(int* obj);
extern f32 sqrtf(f32 x);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern s16 lbl_80326C78[];
extern f32 lbl_80326C90[];
extern f32 lbl_803E52F8;
extern f32 lbl_803E5314;
extern f32 lbl_803E5318;
extern f32 lbl_803E531C;
extern f32 lbl_803E5320;
extern f32 lbl_803E5324;
extern f32 lbl_803E5328;
extern f32 lbl_803E532C;
extern f32 lbl_803E5330;
extern f32 lbl_803E5334;
extern f32 lbl_803E5338;
extern f32 lbl_803E533C;
extern f32 lbl_803E5340;

typedef struct
{
    f32 unk[3];
    f32 x, y, z;
} MushHitInfo;

/* EN v1.0 0x801D1E24  size: 2452b  Mushroom enemy state machine: dormant ->
 * inflate -> chase -> deflate cycle, hit reaction, pop and respawn. */

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/dim_bossgut.h"
#include "main/dll/SH/dll_01A9_bombplant.h"
#include "main/objanim.h"
#include "main/objfx.h"
#include "main/objseq.h"

typedef struct BombplantsporeStartDriftBurstPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeStartDriftBurstPlacement;


typedef struct BombplantsporeUpdateDriftPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeUpdateDriftPlacement;


#include "main/dll/bombplant_placement.h"


extern void ModelLightStruct_free(void* light);
extern double FUN_80017714();
extern undefined4 FUN_80017a28();
extern int FUN_80017a90();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_8013651c();
extern u32 GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void Obj_SetModelColorFadeRecursive(void* obj, int a, int b, int c, int d, int e);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern f64 lbl_803E5360;
extern f32 lbl_803E5368;
extern f32 lbl_803E537C;
extern f32 lbl_803E5380;

extern u8 lbl_80326D20[];
extern ObjectTriggerInterface** gObjectTriggerInterface;

extern undefined4 DAT_80327960;
extern undefined4 DAT_80327964;
extern undefined4 DAT_80327968;
extern f64 DOUBLE_803e5ff8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e5ff0;
extern f32 FLOAT_803e5ff4;
extern f32 FLOAT_803e6000;
extern f32 FLOAT_803e6004;
extern f32 FLOAT_803e6010;
extern f32 FLOAT_803e6014;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E5398;
extern f32 lbl_803E539C;
extern f64 lbl_803E53A0;
extern f32 lbl_803E53A8;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B4;

/*
 * --INFO--
 *
 * Function: bombplantspore_getExtraSize
 * EN v1.0 Address: 0x801D3378
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: bombplantspore_free
 * EN v1.0 Address: 0x801D3380
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801D3970
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: bombplantspore_startDriftBurst
 * EN v1.0 Address: 0x801D33D4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Keep the cross-TU bl: these two drift helpers' only callers
 * (bombplantspore_update/init) live in the BombPlantSpore TU
 * (SHrocketmushroom.c). Once they land there, dont_inline stops MWCC
 * auto-inlining them into bombplantspore_update. */
#pragma dont_inline on

/*
 * --INFO--
 *
 * Function: bombplantspore_updateDrift
 * EN v1.0 Address: 0x801D359C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: bombplant_init
 * EN v1.0 Address: 0x801D3238
 * EN v1.0 Size: 320b
 */
void bombplant_init(void* obj, void* param, int flag)
{
    extern undefined4 ObjHits_RefreshObjectState(); /* #57 */
    void* state;
    void* p4c;
    s16 bitId;

    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)(s8) * ((u8*)param + 0x1f) << 8);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->animEventCallback = (void*)bombplant_SeqFn;
    ((BombPlantState*)state)->growTargetScale = ((GameObject*)obj)->anim.rootMotionScale;

    if (flag != 0)
    {
        return;
    }

    bitId = ((BombplantPlacement*)param)->unk1C;
    if (bitId != -1 && GameBit_Get(bitId) == 0)
    {
        p4c = ((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->unk8;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->unkC;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->unk10;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5358;
        ((BombPlantState*)state)->growDuration = lbl_803E535C;
        ((BombPlantState*)state)->growStartScale = ((BombPlantState*)state)->growTargetScale;
        ((BombPlantState*)state)->growRate =
            ((BombPlantState*)state)->growStartScale / ((BombPlantState*)state)->growDuration;
        ((BombPlantState*)state)->growTimer = ((BombPlantState*)state)->growDuration;
        ObjHits_RefreshObjectState(obj);
        ((BombPlantState*)state)->stateIndex = 1;
    }
    else
    {
        p4c = ((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->unk8;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->unkC;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->unk10;
        ObjHits_RefreshObjectState(obj);
    }
}

/*
 * --INFO--
 *
 * Function: bombplant_update
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 1508b
 */
void bombplant_update(void* obj)
{
    extern void Obj_StartModelFadeIn(void* obj, int duration); /* #57 */
    extern void Sfx_KeepAliveLoopedObjectSound(void* obj, int sndId); /* #57 */
    extern void Sfx_PlayFromObject(void* obj, int sndId); /* #57 */
    extern void fn_801D2B70(void* obj, void* stateEntry, void* state); /* #57 */
    extern undefined4 ObjHits_RefreshObjectState(); /* #57 */
    extern int randomGetRange(int min, int max); /* #57 */
    void* state;
    u8* entry;
    void* param;
    void* p4c;
    void* plr;
    void* p50;
    f32 dist;
    s16 bitId;
    int hitType;
    int outA;
    int outB;
    int outC;
    f32 hitX;
    f32 hitY;
    f32 hitZ;
    f32 lightVec[3];

    Obj_GetPlayerObject();
    if (objIsFrozen(obj) != 0)
    {
        goto epilogue;
    }

    state = ((GameObject*)obj)->extra;
    entry = &lbl_80326D20[((BombPlantState*)state)->stateIndex * 0xc];

    switch (((BombPlantState*)state)->stateIndex)
    {
    case 1:
        param = ((GameObject*)obj)->anim.placementData;
        if ((((BombPlantState*)state)->flags & 0x2) != 0)
        {
            ((BombPlantState*)state)->flags &= ~0x2;
            ((BombPlantState*)state)->growTimer = (f32)(int)((BombplantPlacement*)param)->growTimer;
        }
        bitId = ((BombplantPlacement*)param)->unk1C;
        if (bitId != -1)
        {
            if (GameBit_Get(bitId) != 0)
            {
                plr = Obj_GetPlayerObject();
                dist =
                    vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)plr + 0x18));
                if (dist > lbl_803E5368)
                {
                    ((BombPlantState*)state)->stateIndex = 2;
                    ((BombPlantState*)state)->flags |= 0x2;
                }
            }
        }
        else
        {
            f32 t = ((BombPlantState*)state)->growTimer - timeDelta;
            ((BombPlantState*)state)->growTimer = t;
            if (t <= lbl_803E536C)
            {
                plr = Obj_GetPlayerObject();
                dist =
                    vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)plr + 0x18));
                if (dist > lbl_803E5368)
                {
                    ((BombPlantState*)state)->stateIndex = 2;
                    ((BombPlantState*)state)->flags |= 0x2;
                }
                ((BombPlantState*)state)->growTimer = lbl_803E536C;
            }
        }
        break;

    case 2:
        if ((((BombPlantState*)state)->flags & 0x2) != 0)
        {
            Sfx_PlayFromObject(obj, SFXmv_sliftloop11);
            ((BombPlantState*)state)->flags &= ~0x2;
            p4c = ((GameObject*)obj)->anim.placementData;
            ((GameObject*)obj)->anim.alpha = 0xff;
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->unk8;
            ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->unkC;
            ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->unk10;
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5358;
            ((BombPlantState*)state)->growDuration = lbl_803E535C;
            ((BombPlantState*)state)->growStartScale = ((BombPlantState*)state)->growTargetScale;
            ((BombPlantState*)state)->growRate =
                ((BombPlantState*)state)->growStartScale / ((BombPlantState*)state)->growDuration;
            ((BombPlantState*)state)->growTimer = ((BombPlantState*)state)->growDuration;
            ObjHits_RefreshObjectState(obj);
        }
        if (((GameObject*)obj)->anim.rootMotionScale > ((BombPlantState*)state)->growStartScale)
        {
            ((BombPlantState*)state)->growRate = ((BombPlantState*)state)->growRate / lbl_803E537C;
        }
        if (((BombPlantState*)state)->growRate < lbl_803E5358)
        {
            ((BombPlantState*)state)->growRate = lbl_803E536C;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((BombPlantState*)state)->growRate * timeDelta + ((GameObject*)obj)->anim.rootMotionScale;
        {
            f32 t = ((BombPlantState*)state)->growTimer - timeDelta;
            ((BombPlantState*)state)->growTimer = t;
            if (t < lbl_803E536C)
            {
                ((BombPlantState*)state)->stateIndex = 0;
                ((BombPlantState*)state)->flags |= 0x2;
            }
        }
        break;

    case 4:
        fn_801D2B70(obj, entry, state);
        break;

    case 0:
        Sfx_KeepAliveLoopedObjectSound(obj, 0x3fd);
    /* fallthrough */
    default:
        param = ((GameObject*)obj)->anim.placementData;
        if ((((BombPlantState*)state)->flags & 0x2) != 0)
        {
            ((BombPlantState*)state)->flags &= ~0x2;
            ((BombPlantState*)state)->growTimer =
                (f32)(int)(((BombplantPlacement*)param)->unk1A + randomGetRange(-0x32, 0x32));
        }
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
        }
        break;
    }

    if ((entry[8] & 0x1) != 0)
    {
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &outA, &outB, &outC, &hitX,
                                                     &hitY, &hitZ);
        if (hitType != 0 && outC != 0)
        {
            if (hitType == 0x10)
            {
                Obj_StartModelFadeIn(obj, 0x12c);
            }
            else if (hitType - 0xe <= 1 || hitType == 0x11)
            {
                Sfx_PlayFromObject(obj, SFXmv_curtainloop16);
                hitX = hitX + playerMapOffsetX;
                hitZ = hitZ + playerMapOffsetZ;
                objLightFn_8009a1dc(obj, lbl_803E5380, lightVec, 1, 0);
                Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                ((BombPlantState*)state)->stateIndex = 4;
                ((BombPlantState*)state)->flags |= 0x2;
                p50 = ((GameObject*)obj)->anim.modelInstance;
                ObjHitbox_SetCapsuleBounds(obj, (s16)(((ObjDef*)p50)->primaryHitboxRadius + 0x50),
                                           (s16)(((ObjDef*)p50)->primaryCapsuleOffsetA - 0x50),
                                           (s16)(((ObjDef*)p50)->primaryCapsuleOffsetB + 0x50));
                ObjHits_MarkObjectPositionDirty(obj);
            }
        }
    }

    if ((entry[8] & 0x8) != 0)
    {
        ObjHits_EnableObject(obj);
    }
    else
    {
        ObjHits_DisableObject(obj);
    }

    if ((entry[8] & 0x10) != 0)
    {
        ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
    }
    else
    {
        ObjHits_ClearHitVolumes(obj);
    }

    if ((entry[8] & 0x2) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x4) != 0 && GameBit_Get(0x189) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            GameBit_Set(0x189, 1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
    }

    if ((entry[8] & 0x4) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }

    if (((GameObject*)obj)->anim.currentMove != *(s16*)entry)
    {
        ObjAnim_SetCurrentMove((int)obj, *(s16*)entry, lbl_803E536C, 0);
    }

    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, *(f32*)(entry + 0x4), timeDelta, NULL) != 0)
    {
        ((BombPlantState*)state)->flags |= 0x1;
    }
    else
    {
        ((BombPlantState*)state)->flags &= ~0x1;
    }

epilogue:
    return;
}
