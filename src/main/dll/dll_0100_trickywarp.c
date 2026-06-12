#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"

typedef struct TrickyguardPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} TrickyguardPlacement;


typedef struct CurvefishState
{
    u8 pad0[0xA - 0x0];
    s16 unkA;
    u8 padC[0x10 - 0xC];
    s16 unk10;
    u8 pad12[0x108 - 0x12];
    u8 unk108;
    u8 pad109[0x110 - 0x109];
    f32 unk110;
    u8 pad114[0x120 - 0x114];
} CurvefishState;


extern u32 randomGetRange(int min, int max);
extern void mm_free(void* ptr);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* getTrickyObject(void);
extern void* Obj_GetPlayerObject(void);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int extraSize, int objectId);
extern int Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern f32 getXZDistance(f32 * a, f32 * b);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int hitDetectFn_80065e50(int obj, void* outHits, int param_3, int param_4,
                                f32 x, f32 y, f32 z);
extern int Objfsa_GetWalkGroupIndexAtPoint(f32* pos, int param_2);
extern int getPatchGroup(f32* pos, int patchGroup);
extern int cMenuGetSelectedItem(void);
extern int fn_80138F84(int tricky);
extern int fn_8029622C(int obj);
extern int fn_80296448(int obj);
extern int fn_800DA980(int curveState, int firstNode, int secondNode, int thirdNode);
extern int Curve_AdvanceAlongPath(int curveState, f32 step);
extern int curveFn_800da23c(int curveState, int node);
extern void fn_801816F8(int obj, int param_2, u8* state);
extern int Sfx_IsPlayingFromObject(int obj, u16 sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_FreeObject(int obj);
extern int objIsFrozen(int obj);
extern void objRenderFn_80041018(int* obj);

extern int lbl_803DBDA0;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803DBDA4;
extern f32 lbl_803DBDA8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E38A0;
extern f32 lbl_803E38A8;
extern f32 lbl_803E38B0;
extern f32 lbl_803E38B8;
extern f32 lbl_803E38BC;
extern f32 lbl_803E38C0;
extern f32 lbl_803E38C4;
extern f32 lbl_803E38C8;
extern f32 lbl_803E38CC;
extern f32 lbl_803E38D0;
extern f32 lbl_803E38D4;
extern f32 lbl_803E38E0;
extern u32 lbl_803E38E8;
extern f32 lbl_803E38EC;
extern f32 lbl_803E38F0;
extern f32 lbl_803E38F4;
extern f32 lbl_803E38F8;
extern f32 lbl_803E38FC;
extern f32 lbl_803E3900;
extern f32 lbl_803E3904;
extern f32 lbl_803E3908;
extern f32 lbl_803E390C;
extern f32 lbl_803E3910;
extern f32 lbl_803E3914;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f32 lbl_803E3884;
extern f32 lbl_803E3888;
extern f32 lbl_803E388C;
extern f32 lbl_803E3890;
extern f32 lbl_803E3894;
extern f32 lbl_803E3898;
extern f32 timeDelta;
extern u8 framesThisStep;
extern s16 lbl_803DBD98[4];
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern void vecRotateZXY(void* angles, void* outVec);

typedef struct MagicPlantChildSetup
{
    u8 pad00[4];
    u8 mapByte4;
    u8 mapByte5;
    u8 mapByte6;
    u8 yawByte;
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[6];
    u8 field1A;
    u8 pad1B;
    s16 field1C;
    u8 pad1E[6];
    s16 field24;
    u8 pad26[6];
    s16 field2C;
} MagicPlantChildSetup;

extern void fn_8017F334(int obj, MagicPlantSetup* setup, MagicPlantState* state);

/*
 * --INFO--
 *
 * Function: fn_8017F4F4
 * EN v1.0 Address: 0x8017F4F4
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8017F548
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8017F4F4(int obj, MagicPlantSetup* setupParam, MagicPlantState* stateParam);

/*
 * --INFO--
 *
 * Function: fn_8017F7B8
 * EN v1.0 Address: 0x8017F7B8
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void fn_8017F7B8(int obj, int objectId);
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_8017f7ec
 * EN v1.0 Address: 0x8017F7EC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017F88C
 * EN v1.1 Size: 448b
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
 * Function: MagicPlant_update
 * EN v1.0 Address: 0x8017FA10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017FA4C
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void MagicPlant_update(int obj);

/*
 * --INFO--
 *
 * Function: FUN_8017fa14
 * EN v1.0 Address: 0x8017FA14
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017FD10
 * EN v1.1 Size: 272b
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
 * Function: FUN_801804a0
 * EN v1.0 Address: 0x801804A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801802DC
 * EN v1.1 Size: 392b
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
 * Function: FUN_801804a4
 * EN v1.0 Address: 0x801804A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80180464
 * EN v1.1 Size: 60b
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
 * Function: FUN_801804d8
 * EN v1.0 Address: 0x801804D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801804A0
 * EN v1.1 Size: 136b
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
 * Function: FUN_801804dc
 * EN v1.0 Address: 0x801804DC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x80180528
 * EN v1.1 Size: 620b
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
 * Function: FUN_801811c8
 * EN v1.0 Address: 0x801811C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80181204
 * EN v1.1 Size: 292b
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
 * Function: FUN_801811cc
 * EN v1.0 Address: 0x801811CC
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x80181328
 * EN v1.1 Size: 1672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* 8b "li r3, N; blr" returners. */
int MagicPlant_getExtraSize(void);
int trickywarp_getExtraSize(void) { return 0x64; }
int duster_getExtraSize(void);
int curvefish_getExtraSize(void);

typedef struct DusterStateFlags
{
    u8 floorCached : 1;
    u8 pad : 7;
} DusterStateFlags;

typedef struct DusterState
{
    f32 moveStepScale;
    f32 floorY;
    s16 settleTimer;
    s16 hitReactTimer;
    s16 completeGameBit;
    s16 activeGameBit;
    s16 heldObjectId;
    u8 pad12[6];
    u8 driftDir;
    u8 hitReactActive;
    u8 priorityHit;
    u8 active;
    u8 complete;
    u8 useLaunchVelocity;
    DusterStateFlags flags;
    u8 pad1F;
} DusterState;

STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);

#pragma scheduling off
#pragma peephole off
int duster_SeqFn(u8* obj);

/* gCameraInterface: vtable pointer used for state-machine dispatches. */
extern void* gCameraInterface;

/* MagicPlant_SeqFn: vtable[0x13]() with obj passed through implicitly, return 0. */
int MagicPlant_SeqFn(u8* obj);

u32 MagicPlant_getObjectTypeId(MagicPlantObject* obj);

/* obj->u16_X |= MASK */
void StayPoint_init(u16* obj);

extern void objRenderFn_8003b8f4(int obj, float arg);

void MagicPlant_free(int obj, int param_2);

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void trickywarp_free(int obj)
{
    TrickyWarpState* state = ((GameObject*)obj)->extra;
    if (state->active != 0)
    {
        ObjGroup_RemoveObject(obj, 0x4b);
    }
}

typedef struct TrickyWarpCurveEntry
{
    u8 pad00[3];
    u8 entryPatchGroup;
    u8 linkPatchGroups[4];
    u8 pad08[0xc];
    u32 nodeId;
    s8 action;
    s8 type;
} TrickyWarpCurveEntry;

typedef struct TrickyWarpCurveNode
{
    u8 pad00[4];
    u8 linkPatchGroups[4];
    u8 pad08[0x28];
    s16 requiredGameBit;
    s16 forbiddenGameBit;
} TrickyWarpCurveNode;

int fn_8017FFD0(int obj, TrickyWarpState* state)
{
    int curveCount;
    TrickyWarpCurveEntry** curveEntries;
    int i;
    int linkIndex;
    TrickyWarpCurveEntry* entry;
    TrickyWarpCurveNode* node;
    int n;
    int playerObj;
    int playerPatchGroup;

    if (GameBit_Get(0x4e5) == 0)
    {
        return 0;
    }
    if (getTrickyObject() == NULL)
    {
        return 0;
    }
    if (state->patchGroup == 0)
    {
        state->patchGroup = (u8)Objfsa_GetWalkGroupIndexAtPoint(&((GameObject*)obj)->anim.localPosX, 0);
        if (state->patchGroup != 0)
        {
            curveEntries = (TrickyWarpCurveEntry**)(*gRomCurveInterface)->getCurves(&curveCount);
            n = 0;
            for (i = 0; i < curveCount; i++)
            {
                entry = curveEntries[i];
                if (entry->type == '$' && entry->entryPatchGroup == 0)
                {
                    for (linkIndex = 0; linkIndex < 4; linkIndex++)
                    {
                        if (entry->linkPatchGroups[linkIndex] == state->patchGroup)
                        {
                            state->curveNodeIds[n] = entry->nodeId;
                            n++;
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            return 0;
        }
    }
    if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX, lbl_803E38A0) != 0)
    {
        return 0;
    }
    playerObj = (int)Obj_GetPlayerObject();
    playerPatchGroup = Objfsa_GetWalkGroupIndexAtPoint((f32*)(playerObj + 0xc), 0);
    if (playerPatchGroup != 0)
    {
        if (playerPatchGroup == state->patchGroup)
        {
            return 1;
        }
        for (i = 0; i < 0x18; i++)
        {
            if (state->curveNodeIds[i] == 0)
            {
                break;
            }
            node = (TrickyWarpCurveNode*)(*gRomCurveInterface)->getById(state->curveNodeIds[i]);
            if (node != NULL)
            {
                if (node->requiredGameBit == -1 || GameBit_Get(node->requiredGameBit) != 0)
                {
                    if (node->forbiddenGameBit == -1 || GameBit_Get(node->forbiddenGameBit) == 0)
                    {
                        if (node->linkPatchGroups[0] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[1] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[2] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[3] == playerPatchGroup)
                        {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return getPatchGroup((f32*)(playerObj + 0xc), state->patchGroup);
}

void trickywarp_init(s16* obj, u8* param_2)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *obj = (s16)((u32)param_2[0x1a] << 8);
}

void trickyguard_init(s16* obj, u8* param_2);

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit,
                              void* obj, int flags, int mask, int arg9, int arg10);
extern f32 lbl_803E38B4;

void duster_hitDetect(int param_1);

typedef struct DusterSetup
{
    u8 pad00[0x24];
    s16 activeGameBit;
} DusterSetup;

typedef struct DusterMapEventState
{
    u8 pad00[9];
    u8 collectedCount;
    u8 maxCollectedCount;
} DusterMapEventState;

typedef struct DusterLaunchRotation
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DusterLaunchRotation;

void duster_init(int obj, u8* params);

void duster_update(int obj);


void MagicPlant_init(int obj, MagicPlantSetup* setup);

extern f32 lbl_803E3928;

typedef struct CurveFishSetup
{
    u8 pad00[8];
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
    u8 pad14[5];
    u8 speedChange;
    u8 pad1A[6];
    u16 waitFrames;
    u8 targetYOffset;
    u8 playerRadius;
} CurveFishSetup;

typedef struct CurveFishState
{
    u8 pad00[0x10];
    int hasRouteEdge;
    u8 pad14[0x54];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    u8 pad74[0x30];
    int routeCursor;
    u8 padA8[0x60];
    u8 mode;
    u8 pad109[3];
    f32 animTimer;
    f32 maxSpeed;
    f32 speed;
    f32 moveStepScale;
    f32 phaseTimer;
} CurveFishState;

void trickywarp_update(int param_1)
{
    int obj = param_1;
    TrickyWarpState* state;
    int r;
    state = ((GameObject*)obj)->extra;
    r = fn_8017FFD0(obj, state);
    if (r != 0)
    {
        if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject(obj, 0x4b);
        }
    }
    else
    {
        if (state->active != 0)
        {
            state->active = 0;
            ObjGroup_RemoveObject(obj, 0x4b);
        }
    }
}

void curvefish_update(int obj);

void curvefish_init(int obj, u8* param_2);

typedef struct DusterHitEffectPos
{
    u8 pad00[0xc];
    f32 x;
    f32 y;
    f32 z;
} DusterHitEffectPos;

void fn_801814D0(int obj, int param_2, u8* state);

void trickyguard_update(int* obj);

typedef struct StayPointSetup
{
    u8 pad00[0x1e];
    s16 activeGameBit;
    s16 requiredGameBit;
} StayPointSetup;

void StayPoint_update(int obj);

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
