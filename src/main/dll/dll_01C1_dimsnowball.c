/* DLL 0x01C1 (dimsnowball) — DIM snowball object [0x801B0DD4-0x801B13E8). */
#include "main/audio/sfx_ids.h"
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objseq.h"





/* imanimspacecraft_getExtraSize == 0x4. */


STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */


STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */


STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */


STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */


STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int* DIMcannon_GetActiveModel(void* obj);



extern void imicepillar_free(void);
extern int imicepillar_getObjectTypeId(void);
extern int imicepillar_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};





















/* 8b "li r3, N; blr" returners. */

/* Pattern wrappers. */

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */

/* If obj->_F4 == 0, set it to 1; else early-return. */

/* Free: call vtable[6] on obj through global dll-services pointer. */



/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */

/* lavaball1bf "request" hook: set pending if gated, return success. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);






/* if (o->_X == K) return A; else return B;  pattern. */


/* chained byte mask. */
















extern u8 framesThisStep;






























/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavasmash.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objanim_internal.h"





typedef struct DimsnowballState
{
    u8 pad0[0xC - 0x0];
    s8 unkC;
    u8 padD[0x10 - 0xD];
} DimsnowballState;



extern f32 oneOverTimeDelta;
extern s16 lbl_803DBEE8;
extern s16 gDimSnowballCoords[];
extern f32 lbl_803E484C;
extern f32 lbl_803E4850;
extern f32 lbl_803E4854;

/*
 * --INFO--
 *
 * Function: dimlogfire_update
 * EN v1.0 Address: 0x801B0924
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x801B0B58
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801b09dc
 * EN v1.0 Address: 0x801B09DC
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801B0C24
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: dimlogfire_init
 * EN v1.0 Address: 0x801B0BE8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801B0DFC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: dimsnowball_getExtraSize
 * EN v1.0 Address: 0x801B0DD4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getExtraSize(void)
{
    return 0x10;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getObjectTypeId
 * EN v1.0 Address: 0x801B0DDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getObjectTypeId(void)
{
    return 2;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_free
 * EN v1.0 Address: 0x801B0DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B0F60
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimsnowball_free(void)
{
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4848;

void dimsnowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4848);
}

void dimsnowball_hitDetect(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* inner = (int*)state[0];
    if ((*(u16*)((char*)inner + 0xb0) & 0x40) == 0) return;
    state[0] = 0;
}

void dimsnowball_update(int obj)
{
    extern void Obj_FreeObject(int obj); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    s16 idx[4];
    f32 x[4];
    f32 y[4];
    f32 z[4];
    void* ap;
    int* state;
    int player;
    int count;
    int last;
    u8 frames;
    u8* model;
    f32 dy1;
    f32 dy2;
    f32 v24;

    ap = idx;
    ap = x;
    ap = y;
    ap = z;
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (*(void**)state == NULL)
    {
        Obj_FreeObject(obj);
        return;
    }
    frames = framesThisStep;
    idx[1] = (s16)state[2];
    count = lbl_803DBEE8;
    last = count - 1;
    if (idx[1] >= last)
    {
        Obj_FreeObject(obj);
        return;
    }
    idx[0] = idx[1] - 1;
    if (idx[0] < 0)
    {
        idx[0] = 0;
    }
    idx[2] = idx[1] + 1;
    if (idx[2] >= count)
    {
        idx[2] = last;
    }
    idx[3] = idx[1] + 2;
    if (idx[3] >= count)
    {
        idx[3] = last;
    }
    idx[0] *= 3;
    x[0] = (f32)gDimSnowballCoords[idx[0]] * lbl_803E484C;
    y[0] = (f32)gDimSnowballCoords[idx[0] + 1] * lbl_803E484C;
    z[0] = (f32)gDimSnowballCoords[idx[0] + 2] * lbl_803E484C;
    idx[1] *= 3;
    x[1] = (f32)gDimSnowballCoords[idx[1]] * lbl_803E484C;
    y[1] = (f32)gDimSnowballCoords[idx[1] + 1] * lbl_803E484C;
    z[1] = (f32)gDimSnowballCoords[idx[1] + 2] * lbl_803E484C;
    idx[2] *= 3;
    x[2] = (f32)gDimSnowballCoords[idx[2]] * lbl_803E484C;
    y[2] = (f32)gDimSnowballCoords[idx[2] + 1] * lbl_803E484C;
    z[2] = (f32)gDimSnowballCoords[idx[2] + 2] * lbl_803E484C;
    idx[3] *= 3;
    x[3] = (f32)gDimSnowballCoords[idx[3]] * lbl_803E484C;
    y[3] = (f32)gDimSnowballCoords[idx[3] + 1] * lbl_803E484C;
    z[3] = (f32)gDimSnowballCoords[idx[3] + 2] * lbl_803E484C;
    dy1 = y[1] - y[0];
    dy2 = y[2] - y[3];
    if (dy2 <= lbl_803E4850 && dy1 <= lbl_803E4850 && ((DimsnowballState*)state)->unkC <= 0)
    {
        sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
            (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.
                velocityY * ((GameObject*)obj)->anim.velocityY));
        if ((((GameObject*)player)->objectFlags & 0x1000) == 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_run_jingle2);
        }
        ((DimsnowballState*)state)->unkC = 0x1e;
    }
    ((GameObject*)obj)->anim.localPosX = lbl_803E4850 * (x[2] - x[1]) + x[1];
    ((GameObject*)obj)->anim.localPosY = lbl_803E4850 * (y[2] - y[1]) + y[1];
    ((GameObject*)obj)->anim.localPosZ = lbl_803E4850 * (z[2] - z[1]) + z[1];
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + *(f32*)(*state + 0xc);
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + *(f32*)(*state + 0x10);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + *(f32*)(*state + 0x14);
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->
        anim.previousLocalPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->
        anim.previousLocalPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->
        anim.previousLocalPosZ);
    state[2] = state[2] + frames;
    if (((DimsnowballState*)state)->unkC > 0)
    {
        ((DimsnowballState*)state)->unkC -= frames;
    }
    v24 = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.rotY = (int)-(lbl_803E4854 * -((GameObject*)obj)->anim.velocityZ - (f32)((GameObject*)obj)
        ->anim.rotY);
    ((GameObject*)obj)->anim.rotZ = (int)-(lbl_803E4854 * v24 - (f32)((GameObject*)obj)->anim.rotZ);
    model = *(u8**)&((GameObject*)obj)->anim.hitReactState;
    if (model != NULL)
    {
        ((ObjHitsPriorityState*)model)->flags |= 1;
        *(u8*)&((ObjHitsPriorityState*)model)->hitVolumePriority = 4;
        *(u8*)&((ObjHitsPriorityState*)model)->hitVolumeId = 2;
        *(int*)&((ObjHitsPriorityState*)model)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)model)->skeletonHitMask = 0x10;
    }
}

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/DIM/dimsnowball_init.c [801B1354-801B13E8) (TU re-split, docs/boundary_audit.md) === */


typedef struct DimSnowballState
{
    void* target;
    int targetId;
} DimSnowballState;

typedef struct DimSnowballObject
{
    u8 unk0[0x54];
    u8* handle54;
    u8 unk58[0xc];
    u8* handle64;
    u8 unk68[0x48];
    u16 flags;
    u8 unkB2[6];
    DimSnowballState* state;
} DimSnowballObject;

typedef struct DimSnowballDef
{
    u8 unk0[0x14];
    int targetId;
} DimSnowballDef;

void dimsnowball_init(DimSnowballObject* param_1, DimSnowballDef* def)
{
    extern u8* ObjList_FindObjectById(int objectId); /* #57 */
    DimSnowballObject* obj = param_1;
    DimSnowballState* state;

    state = obj->state;
    state->targetId = def->targetId;
    def->targetId = -1;
    state->target = ObjList_FindObjectById(state->targetId);
    if (obj->handle54 != NULL)
    {
        obj->handle54[0x6a] = 0;
    }
    if (obj->handle64 != NULL)
    {
        *(u32*)(obj->handle64 + 0x30) |= 0x810;
    }
    obj->flags = (u16)(obj->flags | 0x4000);
}

void dimsnowball_release(void)
{
}

void dimsnowball_initialise(void)
{
}

int dimsnowball1c2_getExtraSize(void);
