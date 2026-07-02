/*
 * dimsnowball (DLL 0x1C1) - DIM snowball rolling hazard; follows a spline
 * path defined by gDimSnowballCoords, plays a jingle on sharp course changes,
 * and drives a hit-detect object that clears its target on impact.
 */
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll/DIM/DIMcannon.h"

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

extern void imicepillar_free(void);
extern int imicepillar_getObjectTypeId(void);
extern int imicepillar_getExtraSize(void);

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

#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
#include "main/audio/sfx.h"

#define DIMSNOWBALL_OBJFLAG_PARENT_SLACK 0x1000
#define DIMSNOWBALL_OBJFLAG_FREED 0x40

typedef struct DimsnowballState
{
    u8 pad0[0xC - 0x0];
    s8 jingleCooldown;
    u8 padD[0x10 - 0xD];
} DimsnowballState;

extern f32 oneOverTimeDelta;
extern s16 lbl_803DBEE8;
extern s16 gDimSnowballCoords[];
extern f32 lbl_803E484C;
extern const f32 lbl_803E4850;
extern f32 lbl_803E4854;
extern f32 lbl_803E4848;

int dimsnowball_getExtraSize(void)
{
    return 0x10;
}

int dimsnowball_getObjectTypeId(void)
{
    return 2;
}

void dimsnowball_free(void)
{
}

void dimsnowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4848);
}

void dimsnowball_hitDetect(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    GameObject* target = (GameObject*)state[0];
    if ((target->objectFlags & DIMSNOWBALL_OBJFLAG_FREED) == 0) return;
    state[0] = 0;
}

void dimsnowball_update(int obj)
{
    extern int Obj_GetPlayerObject(void); /* #57 */
 /* #57 */
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
    f32 dy2;
    f32 dy1;
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
    idx[1] = state[2];
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
    if ((s16)idx[2] >= count)
    {
        idx[2] = last;
    }
    idx[3] = idx[1] + 2;
    if ((s16)idx[3] >= count)
    {
        idx[3] = last;
    }
    idx[0] *= 3;
    { f32 cc1 = gDimSnowballCoords[idx[0]]; x[0] = cc1 * *(f32*)&lbl_803E484C; }
    { f32 cc2 = gDimSnowballCoords[idx[0] + 1]; y[0] = cc2 * lbl_803E484C; }
    { f32 cc3 = gDimSnowballCoords[idx[0] + 2]; z[0] = cc3 * lbl_803E484C; }
    idx[1] *= 3;
    { f32 cc4 = gDimSnowballCoords[idx[1]]; x[1] = cc4 * lbl_803E484C; }
    { f32 cc5 = gDimSnowballCoords[idx[1] + 1]; y[1] = cc5 * lbl_803E484C; }
    { f32 cc6 = gDimSnowballCoords[idx[1] + 2]; z[1] = cc6 * lbl_803E484C; }
    idx[2] *= 3;
    { f32 cc7 = gDimSnowballCoords[idx[2]]; x[2] = cc7 * lbl_803E484C; }
    { f32 cc8 = gDimSnowballCoords[idx[2] + 1]; y[2] = cc8 * lbl_803E484C; }
    { f32 cc9 = gDimSnowballCoords[idx[2] + 2]; z[2] = cc9 * lbl_803E484C; }
    idx[3] *= 3;
    { f32 cc10 = gDimSnowballCoords[idx[3]]; x[3] = cc10 * lbl_803E484C; }
    { f32 cc11 = gDimSnowballCoords[idx[3] + 1]; y[3] = cc11 * lbl_803E484C; }
    { f32 cc12 = gDimSnowballCoords[idx[3] + 2]; z[3] = cc12 * lbl_803E484C; }
    dy1 = y[1] - y[0];
    dy2 = y[2] - y[3];
    if (dy2 <= lbl_803E4850 && dy1 <= lbl_803E4850 && ((DimsnowballState*)state)->jingleCooldown <= 0)
    {
        sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
            (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.
                velocityY * ((GameObject*)obj)->anim.velocityY));
        if ((((GameObject*)player)->objectFlags & DIMSNOWBALL_OBJFLAG_PARENT_SLACK) == 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_run_jingle2);
        }
        ((DimsnowballState*)state)->jingleCooldown = 0x1e;
    }
    ((GameObject*)obj)->anim.localPosX = x[1] + lbl_803E4850 * (x[2] - x[1]);
    ((GameObject*)obj)->anim.localPosY = y[1] + lbl_803E4850 * (y[2] - y[1]);
    ((GameObject*)obj)->anim.localPosZ = z[1] + lbl_803E4850 * (z[2] - z[1]);
    ((GameObject*)obj)->anim.localPosX =
        ((GameObject*)obj)->anim.localPosX + ((GameObject*)*state)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY =
        ((GameObject*)obj)->anim.localPosY + ((GameObject*)*state)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ =
        ((GameObject*)obj)->anim.localPosZ + ((GameObject*)*state)->anim.localPosZ;
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->
        anim.previousLocalPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->
        anim.previousLocalPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->
        anim.previousLocalPosZ);
    state[2] = state[2] + frames;
    if (((DimsnowballState*)state)->jingleCooldown > 0)
    {
        ((DimsnowballState*)state)->jingleCooldown -= frames;
    }
    v24 = ((GameObject*)obj)->anim.velocityX;
    dy2 = lbl_803E4854;
    ((GameObject*)obj)->anim.rotY = -(dy2 * -((GameObject*)obj)->anim.velocityZ - (f32)((GameObject*)obj)
        ->anim.rotY);
    ((GameObject*)obj)->anim.rotZ = -(dy2 * v24 - (f32)((GameObject*)obj)->anim.rotZ);
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

void dimsnowball_init(DimSnowballObject* objArg, DimSnowballDef* def)
{
    extern u8* ObjList_FindObjectById(int objectId); /* #57 */
    DimSnowballObject* obj = objArg;
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
