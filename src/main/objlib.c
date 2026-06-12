#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"
#include "main/resource.h"


typedef struct ObjLibRegionList ObjLibRegionList;

extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern float sqrtf(float x);
extern uint buttonGetDisabled(int index);
extern void buttonDisable(int index, uint flags);
extern u32 randomGetRange(int min, int max);
extern void setMatrixFromObjectTransposed(void* transform, float* mtx);
extern float vec3f_distanceSquared(float* posA, float* posB);
extern float Vec_distance(float* param_1, float* param_2);
extern void OSReport(const char* fmt, ...);
extern float* ObjModel_GetJointMatrix(int* model, int jointIndex);
extern void Obj_BuildWorldTransformMatrix(void* obj, float* mtx, int flags);
extern void mtx44Transpose(float* src, float* dst);
extern void mtxRotateByVec3s(float* mtx, void* transform);
extern int* Obj_GetActiveModel(int obj);
extern void* Obj_GetPlayerObject(void);
extern void Obj_UpdateObject(ObjAnimComponent * obj, ObjModelInstance * modelInstance);
extern void fn_80054F74(int obj, float* pos);
extern ObjLibRegionList** RomList_GetLoadedPages(void);
extern void debugPrintf(const char* fmt, ...);
extern void PSMTXConcat(float* a, float* b, float* out);
extern float PSVECSquareDistance(float* a, float* b);
extern f32 mathSinf(f32 x);
extern f32 fn_802943F4(f32 x);
extern f32 mathCosf(f32 x);
extern int playerIsDisguised(int obj);
extern int objGetAnimState80A(void* obj);

#define OBJGROUP_COUNT 0x54
#define OBJGROUP_OFFSET_CLEAR_COUNT (OBJGROUP_COUNT + 1)
#define OBJGROUP_MAX_OBJECTS 0x100
#define OBJLIB_PRIMARY_ROM_PAGE_COUNT 0x50
#define OBJHITREGION_ROM_ENTRY_TYPE 0x130

extern uint gObjGroupObjects[OBJGROUP_MAX_OBJECTS];
extern u8 gObjGroupOffsets[0x58];

typedef struct ObjContactCallbackEntry
{
    int objA;
    int objB;
    ObjContactCallback callback;
} ObjContactCallbackEntry;

typedef struct ObjLibRegionEntry
{
    s16 type;
    u8 wordCount;
    u8 pad03[5];
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[4];
    u16 id;
    u16 halfX;
    u16 halfY;
    u16 halfZ;
    u8 yaw;
    u8 pitch;
} ObjLibRegionEntry;

struct ObjLibRegionList
{
    u8 pad00[8];
    u16 entryBytes;
    u8 pad0A[0x16];
    ObjLibRegionEntry* entries;
};

extern ObjContactCallbackEntry gObjContactCallbacks[];
extern void* lbl_803DCBD8;
extern u8* gObjHitsPriorityHitStates;
extern u8 gObjGroupObjectCount;
extern int gObjContactCallbackCount;
extern f32 gObjHitsPriorityHitTickDelta;
extern f32 lbl_803DE914;
extern f32 lbl_803DE968;
extern f32 OBJLIB_UNIT_SCALE;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DE970;
extern f32 lbl_803DE974;
extern f32 lbl_803DE978;
extern f32 lbl_803DE980;
extern f32 lbl_803DE984;
extern f32 lbl_803DE998;
extern f32 lbl_803DE99C;
extern f32 lbl_803DE9A0;
extern f32 lbl_803DE9A4;
extern f32 lbl_803DE9A8;
extern f32 lbl_803DE9AC;
extern f32 lbl_803DE9B0;
extern f32 lbl_803DE9B4;
extern f32 lbl_803DE9B8;

#define OBJMSG_QUEUE_OFFSET 0xdc
#define OBJMSG_SEND_INCLUDE_SENDER 0x1
#define OBJMSG_SEND_MATCH_ANY 0x2
#define OBJMSG_SEND_MATCH_OBJTYPE 0x4

#define OBJCONTACT_CALLBACK_CAPACITY 0x10
#define OBJCONTACT_CALLBACK_LAST_INDEX (OBJCONTACT_CALLBACK_CAPACITY - 1)
#define OBJCONTACT_OBJECT_REFCOUNT_OFFSET 0xe9
#define OBJTRIGGER_FLAGS_OFFSET 0xaf
#define OBJTRIGGER_CURRENT_ENABLE_FLAG 0x01
#define OBJTRIGGER_CURRENT_BLOCK_FLAG 0x08
#define OBJTRIGGER_ID_ENABLE_FLAG 0x04
#define OBJTRIGGER_ID_BLOCK_FLAG 0x10
#define OBJTRIGGER_BUTTON_DISABLE_INDEX 0
#define OBJTRIGGER_BUTTON_DISABLE_FLAG 0x100
#define OBJTRIGGER_PLAYER_STATE_NONE -1
#define OBJTRIGGER_PLAYER_STATE_CLEAR 0x40

#define OBJLINK_PARENT_OFFSET 0xc4
#define OBJLINK_CHILD_LIST_OFFSET 0xc8
#define OBJLINK_CHILD_COUNT_OFFSET 0xeb
#define OBJLINK_CHILD_STATE_OFFSET 0xe5
#define OBJLINK_FLAGS_OFFSET 0xb0
#define OBJLINK_FLAGS_MODE_MASK 0x0007
#define OBJLINK_FLAGS_DEAD 0x0040

#define OBJ_MODEL_INSTANCE_OFFSET 0x50
#define OBJ_ACTIVE_MODEL_INDEX_OFFSET 0xad
#define OBJ_POSITION_X_OFFSET 0x0c
#define OBJ_POSITION_Y_OFFSET 0x10
#define OBJ_POSITION_Z_OFFSET 0x14

#define OBJ_MODEL_JOINT_COUNT_OFFSET 0xf3
#define OBJLIB_BLINK_LEFT_JOINT_TAG 5
#define OBJLIB_BLINK_RIGHT_JOINT_TAG 4
#define OBJPATH_POINTS_OFFSET 0x2c
#define OBJPATH_POINT_COUNT_OFFSET 0x58
#define OBJPATH_ROOT_JOINT_INDEX -1
typedef struct ObjMsgEntry
{
    uint message;
    uint sender;
    uint param;
} ObjMsgEntry;

typedef struct ObjMsgQueue
{
    uint count;
    uint capacity;
    ObjMsgEntry entries[1];
} ObjMsgQueue;

typedef struct ObjMsgQueueSlotBase
{
    uint count;
    uint capacity;
    ObjMsgEntry entry;
} ObjMsgQueueSlotBase;

typedef struct ObjPathPoint
{
    f32 x;
    f32 y;
    f32 z;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s8 modelIndex[6];
} ObjPathPoint;

typedef struct ObjPathTransform
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad06[2];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjPathTransform;

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetStateIndex
 * EN v1.0 Address: 0x800358D4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x800359CC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma optimization_level 1
#pragma scheduling off
void ObjHitbox_SetStateIndex(int objPtr, int hitStatePtr, int stateIndex)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    int clearedState;
    ObjHitsPriorityWorkSlot* workSlot;
    int slotIndex;
    int slotOffset;
    int modelCount;

    obj = (ObjAnimComponent*)objPtr;
    modelCount = obj->modelInstance->modelCount;
    if (stateIndex >= modelCount)
    {
        stateIndex = modelCount + -1;
    }
    else if (stateIndex < 0)
    {
        stateIndex = 0;
    }
    hitState = (ObjHitsPriorityState*)hitStatePtr;
    if (*(s8*)&hitState->stateIndex == stateIndex)
    {
        return;
    }
    slotIndex = 0;
    slotOffset = slotIndex;
    clearedState = slotIndex;
    for (; (s16)slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT; slotIndex = slotIndex + 1)
    {
        workSlot = (ObjHitsPriorityWorkSlot*)(gObjHitsPriorityHitStates + slotOffset);
        if ((workSlot->active != 0) && ((u32)workSlot->obj == (u32)obj))
        {
            workSlot->active = clearedState;
        }
        slotOffset = slotOffset + OBJHITS_PRIORITY_WORK_SLOT_SIZE;
    }
    hitState->stateIndex = (s8)stateIndex;
    return;
}
#pragma optimization_level reset

/*
 * --INFO--
 *
 * Function: ObjHits_SetTargetMask
 * EN v1.0 Address: 0x80035960
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035A58
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void ObjHits_SetTargetMask(int objPtr, undefined targetMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    hitState->targetMask = targetMask;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetSphereRadius
 * EN v1.0 Address: 0x80035974
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x80035A6C
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitbox_SetSphereRadius(int objPtr, s16 radius)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState != 0)
    {
        if ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0)
        {
            hitState->primaryRadius = radius;
            hitState->primaryRadiusSquared =
                (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
            hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusY)
            {
                hitState->primaryRadiusY = (float)(s32)hitState->primaryRadius;
            }
            hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ)
            {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }
        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0)
        {
            hitState->secondaryRadius = radius;
            hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusY)
            {
                hitState->secondaryRadiusY = (float)(s32)hitState->secondaryRadius;
            }
            hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusXZ)
            {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX)
        {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHitbox_SetCapsuleBounds
 * EN v1.0 Address: 0x80035B50
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x80035C48
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitbox_SetCapsuleBounds(int objPtr, undefined2 radius, short verticalMin, short verticalMax)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    float absMin;
    float absMax;
    s32 absVal;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState != 0)
    {
        if ((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0)
        {
            hitState->primaryCapsuleOffsetA = verticalMin;
            hitState->primaryCapsuleOffsetB = verticalMax;
            hitState->primaryRadius = radius;
            hitState->primaryRadiusSquared =
                (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
            hitState->capsuleScale = OBJHITBOX_DEFAULT_CAPSULE_SCALE;
            hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            absVal = (s32)verticalMin;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = (s32)verticalMax;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMax = (float)absVal;
            if (absMin > absMax)
            {
                absMax = absMin;
            }
            if (absMax > hitState->primaryRadiusY)
            {
                hitState->primaryRadiusY = absMax;
            }
            hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ)
            {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }
        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0)
        {
            hitState->secondaryCapsuleOffsetA = verticalMin;
            hitState->secondaryCapsuleOffsetB = verticalMax;
            hitState->secondaryRadius = radius;
            hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            absVal = (s32)verticalMin;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = (s32)verticalMax;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMax = (float)absVal;
            if (absMin > absMax)
            {
                absMax = absMin;
            }
            if (absMax > hitState->secondaryRadiusY)
            {
                hitState->secondaryRadiusY = absMax;
            }
            hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusXZ)
            {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX)
        {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearHitVolumes
 * EN v1.0 Address: 0x80035DAC
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80035EA4
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearHitVolumes(int objPtr)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->hitVolumePriority = 0;
    hitState->hitVolumeId = 0;
    hitState->objectHitMask = 0;
    hitState->skeletonHitMask = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetHitVolumeMasks
 * EN v1.0 Address: 0x80035DC8
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80035EC0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetHitVolumeMasks(int objPtr, int hitVolume, int hitType, int sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->hitVolumePriority = (s8)hitVolume;
    hitState->hitVolumeId = (s8)hitType;
    if (sourceMask == 0)
    {
        return;
    }
    hitState->objectHitMask = sourceMask << 4;
    hitState->skeletonHitMask = sourceMask << 4;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetHitVolumeSlot
 * EN v1.0 Address: 0x80035DF4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80035EEC
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot)
{
    int hitMask;
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    hitState->hitVolumePriority = (s8)hitVolume;
    hitState->hitVolumeId = (s8)hitType;
    if (sourceSlot == -1)
    {
        return;
    }
    hitMask = 1 << (sourceSlot + 4);
    hitState->objectHitMask = hitMask;
    hitState->skeletonHitMask = hitMask;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearSourceMask
 * EN v1.0 Address: 0x80035E30
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F28
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearSourceMask(int objPtr, int sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->sourceMask = (u8)(hitState->sourceMask & ~sourceMask);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetSourceMask
 * EN v1.0 Address: 0x80035E48
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80035F40
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetSourceMask(int objPtr, u8 sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->sourceMask |= sourceMask;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ClearFlags
 * EN v1.0 Address: 0x80035E5C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F54
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ClearFlags(int objPtr, int flags)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags & ~flags);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SetFlags
 * EN v1.0 Address: 0x80035E74
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F6C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SetFlags(int objPtr, int flags)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags | flags);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_MarkObjectPositionDirty
 * EN v1.0 Address: 0x80035E8C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80035F84
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_MarkObjectPositionDirty(int objPtr)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags | OBJHITS_PRIORITY_STATE_POSITION_DIRTY);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPositionIfDirty
 * EN v1.0 Address: 0x80035EA4
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x80035F9C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SyncObjectPositionIfDirty(u32 objPtr)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    s16 flags;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    flags = hitState->flags;
    if ((flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0)
    {
        return;
    }
    hitState->flags = (s16)(flags & ~OBJHITS_PRIORITY_STATE_POSITION_DIRTY);
    hitState->localPosX = obj->localPosX;
    hitState->localPosY = obj->localPosY;
    hitState->localPosZ = obj->localPosZ;
    hitState->worldPosX = obj->worldPosX;
    hitState->worldPosY = obj->worldPosY;
    hitState->worldPosZ = obj->worldPosZ;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_DisableObject
 * EN v1.0 Address: 0x80035F00
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80035FF8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_DisableObject(u32 objPtr)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_EnableObject
 * EN v1.0 Address: 0x80035F20
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x80036018
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_EnableObject(u32 objPtr)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    s16 flags;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    flags = hitState->flags;
    if ((flags & OBJHITS_PRIORITY_STATE_ENABLED) != 0)
    {
        return;
    }
    hitState->flags = (s16)(flags | OBJHITS_PRIORITY_STATE_ENABLED);
    hitState->localPosX = obj->localPosX;
    hitState->localPosY = obj->localPosY;
    hitState->localPosZ = obj->localPosZ;
    hitState->worldPosX = obj->worldPosX;
    hitState->worldPosY = obj->worldPosY;
    hitState->worldPosZ = obj->worldPosZ;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_IsObjectEnabled
 * EN v1.0 Address: 0x80035F7C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80036074
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort ObjHits_IsObjectEnabled(int objPtr)
{
    return ((ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState)->flags &
        OBJHITS_PRIORITY_STATE_ENABLED;
}

/*
 * --INFO--
 *
 * Function: ObjHits_SyncObjectPosition
 * EN v1.0 Address: 0x80035F8C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80036084
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_SyncObjectPosition(u32 objPtr)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    hitState->localPosX = obj->localPosX;
    hitState->localPosY = obj->localPosY;
    hitState->localPosZ = obj->localPosZ;
    hitState->worldPosX = obj->worldPosX;
    hitState->worldPosY = obj->worldPosY;
    hitState->worldPosZ = obj->worldPosZ;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AllocObjectState
 * EN v1.0 Address: 0x80035FCC
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800360C4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_AllocObjectState(int objPtr, uint arena)
{
    uint stateArena;
    ObjHitsPriorityState* hitState;

    stateArena = roundUpTo4(arena);
    ((ObjAnimComponent*)objPtr)->hitReactState = (ObjHitReactState*)stateArena;
    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    ObjHits_RefreshObjectState(objPtr);
    hitState->activeHitboxMode = OBJHITS_ACTIVE_HITBOX_MODE;
    if ((hitState->shapeFlags & OBJHITS_SHAPE_RESET_MODE_MASK) != 0)
    {
        hitState->resetHitboxMode = OBJHITS_RESET_HITBOX_MODE;
    }
    return stateArena + 0xb8;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RefreshObjectState
 * EN v1.0 Address: 0x80036044
 * EN v1.0 Size: 1036b
 * EN v1.1 Address: 0x8003613C
 * EN v1.1 Size: 1036b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_RefreshObjectState(int objPtr)
{
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    ObjAnimBank* activeBank;
    short capsuleOffsetA;
    short capsuleOffsetB;

    obj = (ObjAnimComponent*)objPtr;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState != 0)
    {
        hitState->flags = obj->modelInstance->hitboxFlags;
        hitState->shapeFlags = obj->modelInstance->primaryHitboxShapeFlags;
        if ((hitState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0)
        {
            activeBank = ObjAnim_GetActiveBank(obj);
            if (((activeBank->animDef->flags & OBJANIM_DEF_FLAG_SKELETON_HITBOXES) == 0) ||
                (*(void**)(((int*)activeBank) + 5) == 0))
            {
                hitState->shapeFlags = *(u8*)((int)hitState + 0x62) & ~OBJHITS_SHAPE_SKELETON;
            }
        }
        hitState->lateralResponseWeight = obj->modelInstance->lateralResponseWeight;
        hitState->axialResponseWeight = obj->modelInstance->axialResponseWeight;
        hitState->primaryRadius = obj->modelInstance->primaryHitboxRadius;
        hitState->primaryCapsuleOffsetA = obj->modelInstance->primaryCapsuleOffsetA;
        hitState->primaryCapsuleOffsetB = obj->modelInstance->primaryCapsuleOffsetB;
        *(s8*)&hitState->stateIndex = (s8)(int)
        obj->modelInstance->hitboxStateIndex;
        hitState->capsuleScale = OBJHITBOX_DEFAULT_CAPSULE_SCALE;
        hitState->primaryRadiusSquared =
            (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
        hitState->secondaryShapeFlags = obj->modelInstance->secondaryHitboxShapeFlags;
        hitState->secondaryRadius = obj->modelInstance->secondaryHitboxRadius;
        hitState->secondaryCapsuleOffsetA = obj->modelInstance->secondaryCapsuleOffsetA;
        hitState->secondaryCapsuleOffsetB = obj->modelInstance->secondaryCapsuleOffsetB;
        hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
        if ((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0)
        {
            capsuleOffsetA = (hitState->primaryCapsuleOffsetA < 0)
                                 ? -hitState->primaryCapsuleOffsetA
                                 : hitState->primaryCapsuleOffsetA;
            capsuleOffsetB = (hitState->primaryCapsuleOffsetB < 0)
                                 ? -hitState->primaryCapsuleOffsetB
                                 : hitState->primaryCapsuleOffsetB;
            if (capsuleOffsetA > capsuleOffsetB)
            {
                capsuleOffsetB = capsuleOffsetA;
            }
            if ((float)(s32)capsuleOffsetB > hitState->primaryRadiusY)
            {
                hitState->primaryRadiusY = (float)(s32)capsuleOffsetB;
            }
        }
        else if ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0)
        {
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusY)
            {
                hitState->primaryRadiusY = (float)(s32)hitState->primaryRadius;
            }
        }
        hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
        if (((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) ||
            ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0))
        {
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ)
            {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }
        hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0)
        {
            capsuleOffsetA = (hitState->secondaryCapsuleOffsetA < 0)
                                 ? -hitState->secondaryCapsuleOffsetA
                                 : hitState->secondaryCapsuleOffsetA;
            capsuleOffsetB = (hitState->secondaryCapsuleOffsetB < 0)
                                 ? -hitState->secondaryCapsuleOffsetB
                                 : hitState->secondaryCapsuleOffsetB;
            if (capsuleOffsetA > capsuleOffsetB)
            {
                capsuleOffsetB = capsuleOffsetA;
            }
            if ((float)(s32)capsuleOffsetB > hitState->secondaryRadiusY)
            {
                hitState->secondaryRadiusY = (float)(s32)capsuleOffsetB;
            }
        }
        else if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0)
        {
            if ((float)(s32)hitState->secondaryRadius > hitState->secondaryRadiusY)
            {
                hitState->secondaryRadiusY = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
        if (((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) ||
            ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0))
        {
            if ((float)(s32)hitState->secondaryRadius > hitState->secondaryRadiusXZ)
            {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX)
        {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
        hitState->sourceMask = obj->modelInstance->sourceHitMask;
        hitState->targetMask = obj->modelInstance->targetHitMask;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RecordObjectHit
 * EN v1.0 Address: 0x80036450
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80036548
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_RecordObjectHit(int obj, int hitObj, char priority, u8 hitVolume, u8 sphereIndex)
{
    ObjAnimComponent* sourceObj;
    ObjAnimComponent* targetObj;
    ObjHitsPriorityState* hitState;
    int hitSlot;

    if (priority == '\0')
    {
        return 0;
    }
    sourceObj = (ObjAnimComponent*)obj;
    targetObj = (ObjAnimComponent*)hitObj;
    hitState = (ObjHitsPriorityState*)sourceObj->hitReactState;
    if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0)
    {
        return 0;
    }
    if ((targetObj != NULL) && (targetObj->hitReactState != NULL))
    {
        ((ObjHitsPriorityState*)targetObj->hitReactState)->lastHitObject = obj;
    }
    hitSlot = 0;
    while (hitSlot < hitState->priorityHitCount)
    {
        if ((void*)hitState->hitObjects[hitSlot] == (void*)hitObj)
        {
            if (hitState->priorities[hitSlot] > priority)
            {
                hitState->sphereIndices[hitSlot] = sphereIndex;
                hitState->priorities[hitSlot] = priority;
                hitState->hitVolumes[hitSlot] = hitVolume;
                hitState->hitPosX[hitSlot] = sourceObj->localPosX;
                hitState->hitPosY[hitSlot] = sourceObj->localPosY;
                hitState->hitPosZ[hitSlot] = sourceObj->localPosZ;
            }
            hitSlot = hitState->priorityHitCount + 1;
        }
        hitSlot = hitSlot + 1;
    }
    if ((hitSlot == hitState->priorityHitCount) &&
        (hitState->priorityHitCount < OBJHITS_PRIORITY_HIT_COUNT))
    {
        hitState->sphereIndices[hitState->priorityHitCount] = sphereIndex;
        *(char*)((int)hitState->priorities + hitState->priorityHitCount) = priority;
        *(undefined*)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
        hitState->hitObjects[hitState->priorityHitCount] = hitObj;
        hitState->hitPosX[hitState->priorityHitCount] = sourceObj->localPosX;
        hitState->hitPosY[hitState->priorityHitCount] = sourceObj->localPosY;
        hitState->hitPosZ[hitState->priorityHitCount] = sourceObj->localPosZ;
        hitState->priorityHitCount = hitState->priorityHitCount + '\x01';
    }
    return 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_RecordPositionHit
 * EN v1.0 Address: 0x800365B8
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800366B0
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_RecordPositionHit(f32 hitPosX, f32 hitPosY, f32 hitPosZ, int obj, int hitObj, char priority,
                              u8 hitVolume, u8 sphereIndex)
{
    ObjAnimComponent* sourceObj;
    ObjAnimComponent* targetObj;
    ObjHitsPriorityState* hitState;
    int hitSlot;

    if (priority == '\0')
    {
        return 0;
    }
    sourceObj = (ObjAnimComponent*)obj;
    targetObj = (ObjAnimComponent*)hitObj;
    hitState = (ObjHitsPriorityState*)sourceObj->hitReactState;
    if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0)
    {
        return 0;
    }
    if ((targetObj != NULL) && (targetObj->hitReactState != NULL))
    {
        ((ObjHitsPriorityState*)targetObj->hitReactState)->lastHitObject = obj;
    }
    hitSlot = 0;
    while (hitSlot < hitState->priorityHitCount)
    {
        if ((void*)hitState->hitObjects[hitSlot] == (void*)hitObj)
        {
            if (hitState->priorities[hitSlot] > priority)
            {
                hitState->sphereIndices[hitSlot] = sphereIndex;
                hitState->priorities[hitSlot] = priority;
                hitState->hitVolumes[hitSlot] = hitVolume;
                hitState->hitPosX[hitSlot] = hitPosX;
                hitState->hitPosY[hitSlot] = hitPosY;
                hitState->hitPosZ[hitSlot] = hitPosZ;
            }
            hitSlot = hitState->priorityHitCount + 1;
        }
        hitSlot = hitSlot + 1;
    }
    if ((hitSlot == hitState->priorityHitCount) &&
        (hitState->priorityHitCount < OBJHITS_PRIORITY_HIT_COUNT))
    {
        hitState->sphereIndices[hitState->priorityHitCount] = sphereIndex;
        *(char*)((int)hitState->priorities + hitState->priorityHitCount) = priority;
        *(undefined*)((int)hitState->hitVolumes + hitState->priorityHitCount) = hitVolume;
        hitState->hitObjects[hitState->priorityHitCount] = hitObj;
        *(float*)((int)hitState->hitPosX + hitState->priorityHitCount * 4) = hitPosX;
        *(float*)((int)hitState->hitPosY + hitState->priorityHitCount * 4) = hitPosY;
        *(float*)((int)hitState->hitPosZ + hitState->priorityHitCount * 4) = hitPosZ;
        hitState->priorityHitCount = hitState->priorityHitCount + '\x01';
    }
    return 1;
}

/*
 * --INFO--
 *
 * Function: ObjHits_AddContactObject
 * EN v1.0 Address: 0x80036708
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80036800
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_AddContactObject(int obj, int contactObj)
{
    int contactObjectIndex;
    int contactObjectCount;
    int contactOffset;
    int contactStore;
    int i;
    int storeState;
    int transformState;

    transformState = *(int*)(obj + OBJHITBOX_TRANSFORM_STATE_OFFSET);
    if ((u32)transformState == 0)
    {
        return;
    }
    contactObjectCount =
        (int)*(char*)(transformState + OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET);
    if (contactObjectCount >= OBJHITBOX_CONTACT_OBJECT_COUNT)
    {
        return;
    }
    contactOffset = 0;
    for (i = 0; i < contactObjectCount; i++)
    {
        u32 entryObj =
            *(u32*)(transformState + contactOffset + OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET);
        if (entryObj == (u32)contactObj)
        {
            return;
        }
        contactOffset = contactOffset + 4;
    }
    storeState = *(volatile int*)(obj + OBJHITBOX_TRANSFORM_STATE_OFFSET);
    contactObjectIndex = (*(u8*)(transformState + OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET))++;
    *(int*)(storeState + OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET +
        (s8)contactObjectIndex * 4) = contactObj;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHitWithPosition
 * EN v1.0 Address: 0x80036770
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x80036868
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
int ObjHits_GetPriorityHitWithPosition(int obj, int* outHitObject, int* outSphereIndex,
                                       uint* outHitVolume, float* outHitPosX, float* outHitPosY, float* outHitPosZ)
{
    u8 hitPriority;
    int hitCount;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 bestPriority;
    s8 bestHitSlot;

    hitState = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
    if (hitState == 0)
    {
        return 0;
    }
    hitCount = (int)hitState->priorityHitCount;
    if (hitCount != 0)
    {
        bestPriority = OBJHITS_PRIORITY_INVALID;
        bestHitSlot = -1;
        for (hitSlot = 0; hitSlot < hitCount; hitSlot++)
        {
            hitPriority = hitState->priorities[hitSlot];
            if ((s8)hitPriority < (s8)bestPriority)
            {
                bestPriority = hitPriority;
                bestHitSlot = (char)hitSlot;
            }
        }
        if (bestHitSlot != -1)
        {
            if (outHitObject != (int*)0x0)
            {
                *outHitObject = hitState->hitObjects[bestHitSlot];
            }
            if (outSphereIndex != (int*)0x0)
            {
                *outSphereIndex = (int)hitState->sphereIndices[bestHitSlot];
            }
            if (outHitVolume != (uint*)0x0)
            {
                *outHitVolume = (uint)hitState->hitVolumes[bestHitSlot];
            }
            if (outHitPosX != (float*)0x0)
            {
                *outHitPosX = *(float*)((int)hitState->hitPosX + bestHitSlot * 4);
                *outHitPosY = *(float*)((int)hitState->hitPosY + bestHitSlot * 4);
                *outHitPosZ = *(float*)((int)hitState->hitPosZ + bestHitSlot * 4);
            }
            return (int)(s8)bestPriority;
        }
    }
    return 0;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHits_GetPriorityHit
 * EN v1.0 Address: 0x8003687C
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80036974
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
int ObjHits_GetPriorityHit(int obj, int* outHitObject, int* outSphereIndex, uint* outHitVolume)
{
    u8 hitPriority;
    int hitCount;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 bestPriority;
    s8 bestHitSlot;

    hitState = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
    if (hitState == 0)
    {
        return 0;
    }
    hitCount = (int)hitState->priorityHitCount;
    if (hitCount != 0)
    {
        bestPriority = OBJHITS_PRIORITY_INVALID;
        bestHitSlot = -1;
        for (hitSlot = 0; hitSlot < hitCount; hitSlot++)
        {
            hitPriority = hitState->priorities[hitSlot];
            if ((s8)hitPriority < (s8)bestPriority)
            {
                bestPriority = hitPriority;
                bestHitSlot = (char)hitSlot;
            }
        }
        if (bestHitSlot != -1)
        {
            if (outHitObject != (int*)0x0)
            {
                *outHitObject = hitState->hitObjects[bestHitSlot];
            }
            if (outSphereIndex != (int*)0x0)
            {
                *outSphereIndex = (int)hitState->sphereIndices[bestHitSlot];
            }
            if (outHitVolume != (uint*)0x0)
            {
                *outHitVolume = (uint)hitState->hitVolumes[bestHitSlot];
            }
            return (int)(s8)bestPriority;
        }
    }
    return 0;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_UpdateResetObjects
 * EN v1.0 Address: 0x80036944
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80036A3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitReact_UpdateResetObjects(void)
{
    ObjAnimComponent* obj;
    int objectIndex;
    int objectOffset;

    objectIndex = 0;
    objectOffset = 0;
    for (; objectIndex < gObjHitReactResetObjectCount; objectIndex = objectIndex + 1)
    {
        obj = gObjHitReactResetObjects[objectIndex];
        if (((obj->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) == 0) &&
            (obj->activeHitboxMode != OBJHITREACT_DISABLED_HITBOX_MODE))
        {
            Obj_UpdateObject(obj, obj->modelInstance);
        }
        objectOffset = objectOffset + 4;
    }
    objectOffset = 0;
    for (; objectOffset < gObjHitReactResetObjectCount; objectOffset = objectOffset + 1)
    {
        ObjHitbox_UpdateRotatedBounds((ObjHitbox*)gObjHitReactResetObjects[objectOffset], 1);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_ResetWorkBuffers
 * EN v1.0 Address: 0x800369F0
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x80036AE8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_ResetWorkBuffers(void)
{
    int slotIndex;

    for (slotIndex = 0; slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT; slotIndex++)
    {
        ((ObjHitsPriorityWorkSlot*)gObjHitsPriorityHitStates)[slotIndex].active = 0;
    }
    gObjHitReactResetObjectCount = 0;
}

/*
 * --INFO--
 *
 * Function: ObjHitReact_GetResetObjects
 * EN v1.0 Address: 0x80036AFC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80036BF4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ObjAnimComponent** ObjHitReact_GetResetObjects(int* outObjectCount)
{
    *outObjectCount = gObjHitReactResetObjectCount;
    return gObjHitReactResetObjects;
}

/*
 * --INFO--
 *
 * Function: ObjHits_InitWorkBuffers
 * EN v1.0 Address: 0x80036B0C
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80036C04
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_InitWorkBuffers(void)
{
    int hitVolumeIndex;

    gObjHitReactResetObjects =
        (ObjAnimComponent**)mmAlloc(OBJHITREACT_MAX_RESET_OBJECTS * sizeof(ObjAnimComponent*), 0xe, 0);
    gObjHitsPriorityHitStates =
        (u8*)mmAlloc(OBJHITS_PRIORITY_WORK_SLOT_COUNT * sizeof(ObjHitsPriorityWorkSlot), 0xe, 0);
    lbl_803DCBD8 = mmAlloc(0x1900, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPriorityHitTickDelta = lbl_803DE914;
    hitVolumeIndex = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex++] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex++] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex++] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex++] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex++] = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_ContainsObject
 * EN v1.0 Address: 0x80036C0C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80036D04
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjGroup_ContainsObject(uint obj, int group)
{
    uint* entry;
    uint index;
    uint limit;
    uint limitXorIndex;
    int halfDiff;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    index = (uint)gObjGroupOffsets[group];
    limit = (uint)gObjGroupOffsets[group + 1];
    for (entry = (uint*)gObjGroupObjects + index; ((int)index < (int)limit && (obj != *entry));
         entry = entry + 1, index = index + 1)
    {
    }
    limitXorIndex = limit ^ index;
    halfDiff = (int)limitXorIndex >> 1;
    limitXorIndex = limitXorIndex & limit;
    return (uint)(halfDiff - limitXorIndex) >> 0x1f;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectToPoint
 * EN v1.0 Address: 0x80036C80
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80036D78
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_FindNearestObjectToPoint(int group, float* point, float* maxDistance)
{
    uint nearest;
    uint index;
    uint limit;
    uint* entry;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    bestDistanceSq = *maxDistance * *maxDistance;
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    index = (uint)gObjGroupOffsets[group];
    limit = (uint)gObjGroupOffsets[group + 1];
    entry = (uint*)gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != 0)
        {
            distanceSq = PSVECSquareDistance(point, (float*)(*entry + 0x18));
            if (distanceSq < bestDistanceSq)
            {
                bestDistanceSq = distanceSq;
                nearest = *entry;
            }
        }
        entry++;
        index++;
    }
    if (nearest != 0)
    {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObjectForObject
 * EN v1.0 Address: 0x80036D60
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80036E58
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_FindNearestObjectForObject(int group, uint obj, float* maxDistance)
{
    uint nearest;
    uint index;
    uint limit;
    uint* entry;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    if (maxDistance != (float*)0x0)
    {
        bestDistanceSq = *maxDistance * *maxDistance;
    }
    else
    {
        bestDistanceSq = lbl_803DE968;
    }
    index = (uint)gObjGroupOffsets[group];
    limit = (uint)gObjGroupOffsets[group + 1];
    entry = (uint*)gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != obj)
        {
            distanceSq = vec3f_distanceSquared((float*)(obj + 0x18), (float*)(*entry + 0x18));
            if (distanceSq < bestDistanceSq)
            {
                bestDistanceSq = distanceSq;
                nearest = *entry;
            }
        }
        entry++;
        index++;
    }
    if ((nearest != 0) && (maxDistance != (float*)0x0))
    {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_FindNearestObject
 * EN v1.0 Address: 0x80036E58
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80036F50
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_FindNearestObject(int group, uint obj, float* maxDistance)
{
    uint nearest;
    uint index;
    uint limit;
    uint* entry;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    if (maxDistance != (float*)0x0)
    {
        bestDistanceSq = *maxDistance * *maxDistance;
    }
    else
    {
        bestDistanceSq = lbl_803DE968;
    }
    index = (uint)gObjGroupOffsets[group];
    limit = (uint)gObjGroupOffsets[group + 1];
    entry = (uint*)gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != obj)
        {
            distanceSq = vec3f_distanceSquared((float*)(obj + 0x18), (float*)(*entry + 0x18));
            if (distanceSq < bestDistanceSq)
            {
                bestDistanceSq = distanceSq;
                nearest = *entry;
            }
        }
        entry++;
        index++;
    }
    if ((nearest != 0) && (maxDistance != (float*)0x0))
    {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjects
 * EN v1.0 Address: 0x80036F50
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80037048
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint* ObjGroup_GetObjects(int group, int* countOut)
{
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        *countOut = 0;
        return (uint*)0x0;
    }
    *countOut = (uint)gObjGroupOffsets[group + 1] - (uint)gObjGroupOffsets[group];
    return (uint*)(gObjGroupObjects + gObjGroupOffsets[group]);
}

/*
 * --INFO--
 *
 * Function: ObjGroup_RemoveObject
 * EN v1.0 Address: 0x80036FA4
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x8003709C
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_RemoveObject(uint obj, int group)
{
    u8* offset;
    u8 count;
    int index;
    int limit;
    uint* entries;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return;
    }
    offset = gObjGroupOffsets;
    index = (int)offset[group];
    offset += group;
    limit = (int)offset[1];
    entries = gObjGroupObjects + index;
    while ((index < limit) && (*entries != obj))
    {
        entries++;
        index++;
    }
    if (index >= limit)
    {
        return;
    }
    count = (gObjGroupObjectCount -= 1);
    entries = gObjGroupObjects + index;
    while (index < count)
    {
        *entries = entries[1];
        entries++;
        index++;
    }
    group++;
    offset = gObjGroupOffsets + group;
    while (group <= OBJGROUP_COUNT)
    {
        (*offset)--;
        offset++;
        group++;
    }
}

/*
 * --INFO--
 *
 * Function: ObjGroup_GetObjectGroup
 * EN v1.0 Address: 0x80037194
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8003728C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjGroup_GetObjectGroup(uint obj)
{
    int group;
    int objectIndex;

    for (objectIndex = 0; objectIndex < (int)(uint)gObjGroupObjectCount; objectIndex++)
    {
        uint entryObj = gObjGroupObjects[objectIndex];
        if (entryObj == obj)
        {
            group = 0;
            while (((int)(uint)gObjGroupOffsets[group] <= objectIndex) &&
                (group < OBJGROUP_OFFSET_CLEAR_COUNT))
            {
                group++;
            }
            return group;
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjGroup_AddObject
 * EN v1.0 Address: 0x80037200
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x800372F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjGroup_AddObject(uint obj, int group)
{
    u8* offset;
    int count;
    int index;
    int insertIndex;
    int limit;
    uint* entries;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return;
    }
    if ((int)(uint)gObjGroupObjectCount >= OBJGROUP_MAX_OBJECTS)
    {
        OSReport(sObjAddObjectTypeReachedMaxTypes);
        return;
    }
    offset = gObjGroupOffsets;
    insertIndex = (int)offset[group];
    offset += group;
    limit = (int)offset[1];
    entries = gObjGroupObjects + insertIndex;
    for (index = insertIndex; index < limit; index++)
    {
        if (*entries == obj)
        {
            return;
        }
        entries++;
    }
    if (limit != insertIndex)
    {
        insertIndex = limit - 1;
    }
    gObjGroupObjectCount++;
    count = (int)(uint)gObjGroupObjectCount - 1;
    entries = gObjGroupObjects + count;
    for (index = count; insertIndex < index; index--)
    {
        *entries = entries[-1];
        entries--;
    }
    gObjGroupObjects[insertIndex] = obj;
    group++;
    offset = gObjGroupOffsets + group;
    while (group <= OBJGROUP_COUNT)
    {
        (*offset)++;
        offset++;
        group++;
    }
}

/*
 * --INFO--
 *
 * Function: ObjGroup_ClearAll
 * EN v1.0 Address: 0x8003744C
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80037544
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* memset(void* dst, int val, u32 n);

void ObjGroup_ClearAll(void)
{
    memset(gObjGroupOffsets, 0, OBJGROUP_OFFSET_CLEAR_COUNT);
    gObjGroupObjectCount = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_Peek
 * EN v1.0 Address: 0x80037484
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8003757C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjMsg_Peek(void* obj, uint* outMessage, uint* outSender, uint* outParam)
{
    ObjMsgQueue* queue;

    if (obj == (void*)0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET);
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0))
    {
        if (outMessage != (uint*)0x0)
        {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != (uint*)0x0)
        {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != (uint*)0x0)
        {
            *outParam = queue->entries[0].param;
        }
        return 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_Pop
 * EN v1.0 Address: 0x800374EC
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800375E4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjMsg_Pop(void* obj, uint* outMessage, uint* outSender, uint* outParam)
{
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    uint i;

    if (obj == (void*)0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET);
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0))
    {
        queue->count = queue->count - 1;
        if (outMessage != (uint*)0x0)
        {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != (uint*)0x0)
        {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != (uint*)0x0)
        {
            *outParam = queue->entries[0].param;
        }
        for (i = 0; i < queue->count; i = i + 1)
        {
            slot = (ObjMsgQueueSlotBase*)((byte*)queue + ((i + i + i) << 2));
            slot->entry.message = *(uint*)((byte*)slot + 0x14);
            slot->entry.sender = *(uint*)((byte*)slot + 0x18);
            slot->entry.param = *(uint*)((byte*)slot + 0x1c);
        }
        return 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToNearbyObjects
 * EN v1.0 Address: 0x8003759C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80037694
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjMsg_SendToNearbyObjects(int targetId, float radius, uint flags, void* sender, uint message, uint param)
{
    int* objects;
    uint count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    int objectIndex;
    int objectCount;
    void* obj;

    objects = (int*)ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1)
    {
        obj = (void*)objects[objectIndex];
        if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
            ((((GameObject*)obj)->anim.seqId == (short)targetId ||
                ((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0))) &&
            ((Vec_distance((float*)((byte*)sender + 0x18), (float*)((byte*)obj + 0x18)) < radius &&
                    (obj != (void*)0x0)) &&
                (queue = *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET),
                    queue != (ObjMsgQueue*)0x0)))
        {
            count = queue->count;
            if (count < queue->capacity)
            {
                slot = (ObjMsgQueueSlotBase*)((byte*)queue + ((count + count + count) << 2));
                slot->entry.message = message;
                slot->entry.sender = (uint)sender;
                slot->entry.param = param;
                queue->count = queue->count + 1;
            }
            else
            {
                debugPrintf(sObjMsgOverflowInObjectWarning, message,
                            (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                            (int)*(short*)((byte*)sender + 0x46));
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObjects
 * EN v1.0 Address: 0x800376D8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x800377D0
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjMsg_SendToObjects(int targetId, uint flags, void* sender, uint message, uint param)
{
    int* objects;
    uint count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    int objectIndex;
    int objectCount;
    void* obj;

    objects = (int*)ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    if ((maskedFlags & OBJMSG_SEND_MATCH_OBJTYPE) != 0)
    {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1)
        {
            obj = (void*)objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 ||
                    (targetId == ((GameObject*)obj)->anim.seqId))) &&
                ((obj != (void*)0x0 &&
                    (queue = *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET),
                        queue != (ObjMsgQueue*)0x0))))
            {
                count = queue->count;
                if (count < queue->capacity)
                {
                    slot = (ObjMsgQueueSlotBase*)((byte*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (uint)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                }
                else
                {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message,
                                (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                                (int)*(short*)((byte*)sender + 0x46));
                }
            }
        }
    }
    else
    {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1)
        {
            obj = (void*)objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 ||
                    (targetId == ((GameObject*)obj)->anim.classId))) &&
                ((obj != (void*)0x0 &&
                    (queue = *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET),
                        queue != (ObjMsgQueue*)0x0))))
            {
                count = queue->count;
                if (count < queue->capacity)
                {
                    slot = (ObjMsgQueueSlotBase*)((byte*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (uint)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                }
                else
                {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message,
                                (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                                (int)*(short*)((byte*)sender + 0x46));
                }
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_SendToObject
 * EN v1.0 Address: 0x800378C4
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x800379BC
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjMsg_SendToObject(void* obj, uint message, void* sender, uint param)
{
    uint count;
    void* dstObj;
    void* senderObj;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;

    dstObj = obj;
    senderObj = sender;
    if (dstObj == (void*)0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((byte*)dstObj + OBJMSG_QUEUE_OFFSET);
    if (queue != (ObjMsgQueue*)0x0)
    {
        count = queue->count;
        if (count < queue->capacity)
        {
            slot = (ObjMsgQueueSlotBase*)((byte*)queue + ((count + count + count) << 2));
            slot->entry.message = message;
            slot->entry.sender = (uint)senderObj;
            slot->entry.param = param;
            queue->count = queue->count + 1;
            return queue->count;
        }
        debugPrintf(sObjMsgOverflowInObjectWarning, message,
                    (int)*(short*)((byte*)dstObj + 0x44), (int)*(short*)((byte*)dstObj + 0x46),
                    (int)*(short*)((byte*)senderObj + 0x46));
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjMsg_AllocQueue
 * EN v1.0 Address: 0x80037964
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80037A5C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjMsg_AllocQueue(void* obj, int capacity)
{
    int queueBytes;
    ObjMsgQueue* queue;

    if (((capacity != 0) && (obj != (void*)0x0)) &&
        (*(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET) == (ObjMsgQueue*)0x0))
    {
        queueBytes = (capacity * 3 + 2) * 4;
        queue = (ObjMsgQueue*)mmAlloc(queueBytes, 0xe, 0);
        queue->count = 0;
        queue->capacity = capacity;
        *(ObjMsgQueue**)((byte*)obj + OBJMSG_QUEUE_OFFSET) = queue;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: Obj_IsObjectAlive
 * EN v1.0 Address: 0x800379DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80037AD4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Obj_IsObjectAlive(u32 obj)
{
    undefined4 alive;

    alive = 0;
    if ((obj != 0) && ((*(ushort*)(obj + OBJLINK_FLAGS_OFFSET) & OBJLINK_FLAGS_DEAD) == 0))
    {
        alive = 1;
    }
    return alive;
}

/*
 * --INFO--
 *
 * Function: ObjTrigger_UpdateIdBlockFlag
 * EN v1.0 Address: 0x80037A04
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80037AFC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool ObjTrigger_UpdateIdBlockFlag(int obj)
{
    int val;
    byte flags;

    val = (int)Obj_GetPlayerObject();
    val = playerIsDisguised(val);
    if (val != 0)
    {
        flags = *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET) | OBJTRIGGER_ID_BLOCK_FLAG;
        *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET) = flags;
        return false;
    }
    flags = *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET) & ~OBJTRIGGER_ID_BLOCK_FLAG;
    *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET) = flags;
    return true;
}

/*
 * --INFO--
 *
 * Function: ObjHits_PollPriorityHitWithCooldown
 * EN v1.0 Address: 0x80037A68
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x80037B60
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_PollPriorityHitWithCooldown(int obj, float* cooldown, int* outHitObject, float* outHitPos)
{
    int collisionType;

    collisionType = 0;
    *cooldown = *cooldown - timeDelta;
    if (*cooldown <= lbl_803DE970)
    {
        if (outHitPos != (float*)0x0)
        {
            collisionType = ObjHits_GetPriorityHitWithPosition(obj, outHitObject, (int*)0x0, (uint*)0x0, outHitPos,
                                                               outHitPos + 1, outHitPos + 2);
            if (collisionType != 0)
            {
                fn_80054F74(obj, outHitPos);
            }
        }
        else
        {
            collisionType = ObjHits_GetPriorityHit(obj, outHitObject, (int*)0x0, (uint*)0x0);
        }
        if (collisionType != 0)
        {
            *cooldown = lbl_803DE974;
        }
    }
    return collisionType;
}

/*
 * --INFO--
 *
 * Function: ObjHits_PollPriorityHitEffectWithCooldown
 * EN v1.0 Address: 0x80037B40
 * EN v1.0 Size: 368b
 * EN v1.1 Address: 0x80037C38
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_PollPriorityHitEffectWithCooldown(int obj, uint hitFxMode, uint colorR, uint colorG,
                                              uint colorB, uint sfxId, float* cooldown)
{
    int collisionType;
    ObjHitReactEffectHandle* effectHandle;
    float hitPos[3];
    ObjHitReactEffectPos effectPos;
    ObjHitReactEffectColorArgs effectArgs;
    u32 hitObject;

    *cooldown = *cooldown - timeDelta;
    collisionType = ObjHits_GetPriorityHitWithPosition(obj, (int*)&hitObject, (int*)0x0,
                                                       (uint*)0x0, &hitPos[0], &hitPos[1], &hitPos[2]);
    if ((*cooldown <= lbl_803DE970) && (collisionType != 0))
    {
        *cooldown = lbl_803DE978;
        if ((collisionType != 0x1a) && (collisionType != 5))
        {
            hitPos[0] = hitPos[0] + playerMapOffsetX;
            hitPos[2] = hitPos[2] + playerMapOffsetZ;
            effectPos.scale = OBJLIB_UNIT_SCALE;
            effectPos.z = 0;
            effectPos.y = 0;
            effectPos.x = 0;
            effectHandle = (ObjHitReactEffectHandle*)
                Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
            effectArgs.hitFxMode = hitFxMode & 0xff;
            effectArgs.colorR = colorR & 0xff;
            effectArgs.colorG = colorG & 0xff;
            effectArgs.colorB = colorB & 0xff;
            effectHandle->vtable->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE,
                                        &effectPos, OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,
                                        OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                                        &effectArgs);
            if ((((sfxId & 0xffff) != 0) && (hitObject != 0)) && (*(short*)(hitObject + 0x46) == 0x69))
            {
                Sfx_PlayFromObject(obj, sfxId);
            }
        }
    }
    return collisionType;
}

/*
 * --INFO--
 *
 * Function: ObjLink_DetachChild
 * EN v1.0 Address: 0x80037CB0
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80037DA8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjLink_DetachChild(int obj, int child)
{
    int q;
    int p;
    int i;

    i = 0;
    for (p = obj; i < (int)*(u8*)(obj + OBJLINK_CHILD_COUNT_OFFSET); i++)
    {
        if ((u32) * (int*)(p + OBJLINK_CHILD_LIST_OFFSET) == (u32)child)
        {
            break;
        }
        p += 4;
    }
    q = obj + i * 4;
    while (i < (int)*(u8*)(obj + OBJLINK_CHILD_COUNT_OFFSET) - 1)
    {
        *(int*)(q + OBJLINK_CHILD_LIST_OFFSET) = *(int*)(q + OBJLINK_CHILD_LIST_OFFSET + sizeof(int));
        q += 4;
        i++;
    }
    (*(u8*)(obj + OBJLINK_CHILD_COUNT_OFFSET))--;
    *(int*)(obj + OBJLINK_CHILD_LIST_OFFSET +
        (uint) * (u8*)(obj + OBJLINK_CHILD_COUNT_OFFSET) * 4) = 0;
    *(int*)(child + OBJLINK_PARENT_OFFSET) = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjLink_AttachChild
 * EN v1.0 Address: 0x80037D2C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80037E24
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjLink_AttachChild(int parent, int child, ushort linkMode)
{
    int childIndex;
    u8* parentBytes;

    childIndex = (int)*(u8*)(parent + OBJLINK_CHILD_COUNT_OFFSET);
    *(u8*)(parent + OBJLINK_CHILD_COUNT_OFFSET) += 1;
    parentBytes = (u8*)parent;
    parentBytes = parentBytes + childIndex * sizeof(int);
    *(int*)(parentBytes + OBJLINK_CHILD_LIST_OFFSET) = child;
    *(int*)(child + OBJLINK_PARENT_OFFSET) = parent;
    *(u16*)(child + OBJLINK_FLAGS_OFFSET) =
        (u16)(*(u16*)(child + OBJLINK_FLAGS_OFFSET) & ~OBJLINK_FLAGS_MODE_MASK);
    *(u16*)(child + OBJLINK_FLAGS_OFFSET) =
        (u16)(*(u16*)(child + OBJLINK_FLAGS_OFFSET) | linkMode);
    *(u8*)(child + OBJLINK_CHILD_STATE_OFFSET) = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: ObjContact_DispatchCallbacks
 * EN v1.0 Address: 0x80037D74
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80037E6C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjContact_DispatchCallbacks(int objA, int objB)
{
    int objARefCount;
    int objBRefCount;
    int count;
    ObjContactCallbackEntry* entry;

    objARefCount = *(u8*)(objA + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
    objBRefCount = *(u8*)(objB + OBJCONTACT_OBJECT_REFCOUNT_OFFSET);
    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    while ((objARefCount != 0) && (objBRefCount != 0) && (count-- != 0))
    {
        if (((u32)entry->objA == (u32)objA) && ((u32)entry->objB == (u32)objB))
        {
            objARefCount = objARefCount - 1;
            entry->callback(objA, objB);
        }
        if (((u32)entry->objA == (u32)objB) && ((u32)entry->objB == (u32)objA))
        {
            objBRefCount = objBRefCount - 1;
            entry->callback(objB, objA);
        }
        entry++;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjContact_RemoveObjectCallbacks
 * EN v1.0 Address: 0x80037E44
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80037F3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjContact_RemoveObjectCallbacks(int obj)
{
    int count;
    ObjContactCallbackEntry* entry;

    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    while (count-- > 0)
    {
        if (((u32)entry->objA == (u32)obj) || ((u32)entry->objB == (u32)obj))
        {
            gObjContactCallbackCount--;
            count--;
            (*(u8*)(entry->objA + OBJCONTACT_OBJECT_REFCOUNT_OFFSET))--;
            (*(u8*)(entry->objB + OBJCONTACT_OBJECT_REFCOUNT_OFFSET))--;
            if ((gObjContactCallbackCount != OBJCONTACT_CALLBACK_LAST_INDEX) &&
                (gObjContactCallbackCount != 0))
            {
                *entry = gObjContactCallbacks[gObjContactCallbackCount];
            }
        }
        entry++;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjContact_AddCallback
 * EN v1.0 Address: 0x80037EF0
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80037FE8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjContact_AddCallback(int obj, int otherObj, ObjContactCallback callback)
{
    int count;
    ObjContactCallbackEntry* entry;
    int i;

    if (((void*)obj == NULL) || ((void*)otherObj == NULL))
    {
        return 0;
    }
    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    for (i = 0; i < count; i++)
    {
        if (((u32)entry->objA == (u32)obj) && ((u32)entry->objB == (u32)otherObj))
        {
            return 0;
        }
        entry++;
    }
    if (count >= OBJCONTACT_CALLBACK_CAPACITY)
    {
        return 0;
    }
    entry = &gObjContactCallbacks[count];
    entry->objA = obj;
    entry->objB = otherObj;
    entry->callback = callback;
    *(undefined*)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) =
        *(u8*)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) + 1;
    *(undefined*)(otherObj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) =
        *(u8*)(otherObj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) + 1;
    gObjContactCallbackCount = gObjContactCallbackCount + 1;
    return 1;
}

/*
 * --INFO--
 *
 * Function: ObjTrigger_IsSetById
 * EN v1.0 Address: 0x80037FA4
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8003809C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjTrigger_IsSetById(int obj, short eventId)
{
    int val;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    triggerFlags = *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET);
    flagEnabled = triggerFlags & OBJTRIGGER_ID_ENABLE_FLAG;
    if (flagEnabled != 0)
    {
        flagBlocked = triggerFlags & OBJTRIGGER_ID_BLOCK_FLAG;
        if ((flagBlocked == 0) && (val = (*gGameUIInterface)->isEventReady((int)eventId), val != 0))
        {
            val = objGetAnimState80A(Obj_GetPlayerObject());
            if (val == OBJTRIGGER_PLAYER_STATE_NONE)
            {
                buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX,OBJTRIGGER_BUTTON_DISABLE_FLAG);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjTrigger_IsSet
 * EN v1.0 Address: 0x80038024
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x8003811C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjTrigger_IsSet(int obj)
{
    uint flags;
    int val;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    if (*(uint*)(*(int*)(obj + 0x50) + 0x40) == 0)
    {
        return 0;
    }
    flags = buttonGetDisabled(0);
    if ((flags & OBJTRIGGER_BUTTON_DISABLE_FLAG) == 0)
    {
        triggerFlags = *(byte*)(obj + OBJTRIGGER_FLAGS_OFFSET);
        flagEnabled = triggerFlags & OBJTRIGGER_CURRENT_ENABLE_FLAG;
        if (flagEnabled != 0)
        {
            flagBlocked = triggerFlags & OBJTRIGGER_CURRENT_BLOCK_FLAG;
            if ((flagBlocked == 0) && (val = (*gGameUIInterface)->isCurrentTriggerClear(), val == 0))
            {
                val = objGetAnimState80A(Obj_GetPlayerObject());
                if ((val == OBJTRIGGER_PLAYER_STATE_NONE) || (val == OBJTRIGGER_PLAYER_STATE_CLEAR))
                {
                    buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX,OBJTRIGGER_BUTTON_DISABLE_FLAG);
                    return 1;
                }
            }
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjList_FindNearestObjectByDefNo
 * EN v1.0 Address: 0x800380E0
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x800381D8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjList_FindNearestObjectByDefNo(int obj, int defNo, float* maxDistanceSq)
{
    int startIndex;
    int objectCount;
    float invalidDistance;
    float distanceSq;
    uint otherObj;
    int objectIndex;
    int* objects;
    int foundObj;

    objects = (int*)ObjList_GetObjects(&startIndex, &objectCount);
    foundObj = 0;
    *maxDistanceSq = *maxDistanceSq * *maxDistanceSq;
    if (defNo != -1)
    {
        objectIndex = startIndex;
        objects = objects + startIndex;
        while (objectIndex < objectCount)
        {
            otherObj = *objects;
            if (((defNo == *(s16*)(otherObj + 0x46)) && (obj != otherObj)) &&
                (distanceSq = vec3f_distanceSquared((float*)(obj + 0x18), (float*)(otherObj + 0x18)),
                    distanceSq < *maxDistanceSq))
            {
                *maxDistanceSq = distanceSq;
                foundObj = *objects;
            }
            objects++;
            objectIndex++;
        }
    }
    else
    {
        objectIndex = startIndex;
        objects = objects + startIndex;
        invalidDistance = lbl_803DE970;
        while (objectIndex < objectCount)
        {
            distanceSq = vec3f_distanceSquared((float*)(obj + 0x18), (float*)(*objects + 0x18));
            if ((distanceSq != invalidDistance) && (distanceSq < *maxDistanceSq))
            {
                *maxDistanceSq = distanceSq;
                foundObj = *objects;
            }
            objects++;
            objectIndex++;
        }
    }
    return foundObj;
}

/*
 * --INFO--
 *
 * Function: ObjList_ContainsObject
 * EN v1.0 Address: 0x80038208
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80038300
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjList_ContainsObject(int obj)
{
    uint* entry;
    int i;
    int count;

    entry = (uint*)ObjList_GetObjects(&i, &count);
    i = 0;
    while (i < count)
    {
        if (*entry == (uint)obj)
        {
            return 1;
        }
        entry = entry + 1;
        i = i + 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPositionArray
 * EN v1.0 Address: 0x80038280
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80038378
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointWorldPositionArray(int obj, int pointIndex, int count, float* positions)
{
    float* position;
    int i;

    i = 0;
    position = positions;
    while (i < count)
    {
        ObjPath_GetPointWorldPosition(obj, pointIndex + i, position, position + 1, position + 2, 0);
        position = position + 3;
        i++;
    }
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalPosition
 * EN v1.0 Address: 0x800382F0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800383E8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointLocalPosition(int obj, int pointIndex, float* xOut, float* yOut,
                                   float* zOut)
{
    *xOut = ((ObjPathPoint*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) +
        pointIndex * sizeof(ObjPathPoint)))->x;
    *yOut = *(f32*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) + 4 +
        pointIndex * sizeof(ObjPathPoint));
    *zOut = *(f32*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINTS_OFFSET) + 8 +
        pointIndex * sizeof(ObjPathPoint));
    return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointLocalMtx
 * EN v1.0 Address: 0x80038330
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80038428
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointLocalMtx(int obj, int pointIndex, float* mtxOut)
{
    ObjPathPoint* pathPoint;
    ObjPathTransform transform;

    pathPoint = (ObjPathPoint*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
        OBJPATH_POINTS_OFFSET));
    transform.x = pathPoint[pointIndex].x;
    pathPoint += pointIndex;
    transform.y = pathPoint->y;
    transform.z = pathPoint->z;
    transform.rotX = pathPoint->rotX;
    transform.rotY = pathPoint->rotY;
    transform.rotZ = pathPoint->rotZ;
    transform.scale = OBJLIB_UNIT_SCALE;
    setMatrixFromObjectTransposed(&transform, mtxOut);
    return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointModelMtx
 * EN v1.0 Address: 0x800383A0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x80038498
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointModelMtx(int obj, int pointIndex)
{
    int* model;
    ObjPathPoint* pathPoint;
    int jointIndex;

    model = Obj_GetActiveModel(obj);
    pathPoint = (ObjPathPoint*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
        OBJPATH_POINTS_OFFSET));
    pathPoint += pointIndex;
    jointIndex = pathPoint->modelIndex[(int)*(char*)(obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
    if ((jointIndex >= 0) && (jointIndex < (int)(uint) * (byte*)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET)))
    {
        ObjModel_GetJointMatrix(model, jointIndex);
    }
    else
    {
        ObjModel_GetJointMatrix(model, 0);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ObjPath_GetPointWorldPosition
 * EN v1.0 Address: 0x8003842C
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x80038524
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ,
                                   int useInputPosition)
{
    ObjPathPoint* pathPoint;
    int* model;
    float* jointMtx;
    int jointIndex;
    int pointOffset;
    ObjPathTransform transform;
    float rootMtx[16];
    float transposedMtx[12];
    float concatMtx[12];
    float rotMtx[16];

    if ((pointIndex < 0) ||
        (pointIndex >=
            (int)(uint) * (u8*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) + OBJPATH_POINT_COUNT_OFFSET)))
    {
        *outX = *(float*)(obj + OBJ_POSITION_X_OFFSET);
        *outY = *(float*)(obj + OBJ_POSITION_Y_OFFSET);
        *outZ = *(float*)(obj + OBJ_POSITION_Z_OFFSET);
    }
    else
    {
        model = Obj_GetActiveModel(obj);
        pathPoint = (ObjPathPoint*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
            OBJPATH_POINTS_OFFSET));
        pointOffset = pointIndex * sizeof(ObjPathPoint);
        pathPoint = (ObjPathPoint*)((int)pathPoint + pointOffset);
        jointIndex = pathPoint->modelIndex[(int)*(char*)(obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
        if ((jointIndex < OBJPATH_ROOT_JOINT_INDEX) ||
            (jointIndex >= (int)(uint) * (u8*)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET)))
        {
            *outX = *(float*)(obj + OBJ_POSITION_X_OFFSET);
            *outY = *(float*)(obj + OBJ_POSITION_Y_OFFSET);
            *outZ = *(float*)(obj + OBJ_POSITION_Z_OFFSET);
        }
        else
        {
            if (jointIndex == OBJPATH_ROOT_JOINT_INDEX)
            {
                Obj_BuildWorldTransformMatrix((void*)obj, rootMtx, 0);
                jointMtx = rootMtx;
            }
            else
            {
                jointMtx = ObjModel_GetJointMatrix(model, jointIndex);
            }
            if (useInputPosition != 0)
            {
                transform.x = *outX;
                transform.y = *outY;
                transform.z = *outZ;
                transform.rotX = 0;
                transform.rotY = 0;
                transform.rotZ = 0;
            }
            else
            {
                transform.x = *(f32*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
                        OBJPATH_POINTS_OFFSET) +
                    pointOffset);
                pathPoint = (ObjPathPoint*)(*(int*)(*(int*)(obj + OBJ_MODEL_INSTANCE_OFFSET) +
                        OBJPATH_POINTS_OFFSET) +
                    pointOffset);
                transform.y = pathPoint->y;
                transform.z = pathPoint->z;
                transform.rotX = pathPoint->rotX;
                transform.rotY = pathPoint->rotY;
                transform.rotZ = pathPoint->rotZ;
            }
            mtxRotateByVec3s(rotMtx, &transform);
            mtx44Transpose(rotMtx, transposedMtx);
            PSMTXConcat(jointMtx, transposedMtx, concatMtx);
            *outX = concatMtx[3] + playerMapOffsetX;
            *outY = concatMtx[7];
            *outZ = concatMtx[11] + playerMapOffsetZ;
        }
    }
}

/*
 * --INFO--
 *
 * Function: Obj_GetYawDeltaToObject
 * EN v1.0 Address: 0x800385E8
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800386E0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int Obj_GetYawDeltaToObject(ushort* obj, int target, float* distOut)
{
    int yawDelta;
    float dx;
    float dz;

    dx = *(float*)(obj + 6) - *(float*)(target + 0xc);
    dz = *(float*)(obj + 10) - *(float*)(target + 0x14);
    yawDelta = getAngle(dx, dz);
    if (distOut != (float*)0x0)
    {
        *distOut = sqrtf(dx * dx + dz * dz);
    }
    yawDelta = (int)(short)yawDelta - (uint)(ushort) * (short*)obj;
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    return (int)(short)yawDelta;
}

/*
 * --INFO--
 *
 * Function: ObjHitRegion_FindContainingId
 * EN v1.0 Address: 0x800386BC
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x800387B4
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z)
{
    ObjLibRegionList** lists;
    ObjLibRegionList* list;
    ObjLibRegionEntry* entry;
    int hitId;
    int listIndex;
    int entryOffset;

    hitId = -1;
    lists = RomList_GetLoadedPages();
    for (listIndex = 0; listIndex < OBJLIB_PRIMARY_ROM_PAGE_COUNT; listIndex++)
    {
        list = lists[listIndex];
        if (list != 0)
        {
            entry = list->entries;
            entryOffset = 0;
            while (entryOffset < (int)(uint)list->entryBytes)
            {
                if (entry->type == OBJHITREGION_ROM_ENTRY_TYPE)
                {
                    f32 yawCos =
                        mathSinf(lbl_803DE980 * (f32) - (s32)((uint)entry->yaw << 8) / lbl_803DE984);
                    f32 yawSin = mathCosf(lbl_803DE980 * (f32) - (s32)((uint)entry->yaw << 8) / lbl_803DE984);
                    f32 pitchCos =
                        mathSinf(lbl_803DE980 * (f32) - (s32)((uint)entry->pitch << 8) / lbl_803DE984);
                    f32 pitchSin =
                        mathCosf(lbl_803DE980 * (f32) - (s32)((uint)entry->pitch << 8) / lbl_803DE984);
                    f32 deltaX = x - entry->x;
                    f32 deltaY = y - entry->y;
                    f32 deltaZ = z - entry->z;
                    f32 localX = deltaX * yawSin - deltaZ * yawCos;
                    f32 yawZ = deltaX * yawCos + deltaZ * yawSin;
                    f32 localY = deltaY * pitchSin - yawZ * pitchCos;
                    f32 localZ = deltaY * pitchCos + yawZ * pitchSin;

                    if (localX < lbl_803DE970)
                    {
                        localX = -localX;
                    }
                    if (localY < lbl_803DE970)
                    {
                        localY = -localY;
                    }
                    if (localZ < lbl_803DE970)
                    {
                        localZ = -localZ;
                    }
                    if ((localX <= (f32)(uint)entry->halfX
                    )
                    &&
                    (localY <= (f32)(uint)
                    entry->halfY
                    )
                    &&
                    (localZ <= (f32)(uint)
                    entry->halfZ
                    )
                    )
                    {
                        hitId = entry->id;
                    }
                }
                entryOffset += (uint)entry->wordCount * 4;
                entry = (ObjLibRegionEntry*)((u8*)entry + (uint)entry->wordCount * 4);
            }
        }
    }
    return (uint)hitId & 0xffff;
}

/*
 * --INFO--
 *
 * Function: playerEyeAnimFn_80038988
 * EN v1.0 Address: 0x80038988
 * EN v1.0 Size: 1428b
 * EN v1.1 Address: 0x80038A80
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct PlayerBlinkState
{
    u8 pad[0x2b];
    u8 mode; /* 0x2b */
    u8 timer; /* 0x2c */
    u8 amount; /* 0x2d */
} PlayerBlinkState;

void playerEyeAnimFn_80038988(int obj, int blinkState, uint flags)
{
    extern int randomGetRange(int min, int max);
    PlayerBlinkState* bs = (PlayerBlinkState*)blinkState;
    ObjAnimComponent* objAnim;
    u8 step;
    f32 leftScale;
    f32 rightScale;
    f32 phase;
    f32 wave;
    int joint;
    ObjModelInstance* model;
    u8* jointData;
    int jointDataOffset;
    int poseOffset;
    int jointCount;
    s16 rotation;

    objAnim = (ObjAnimComponent*)obj;
    step = lbl_803DE998 * timeDelta;
    rightScale = (leftScale = lbl_803DE99C);
    switch (bs->mode)
    {
    case 0:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        bs->amount = 0;
        if (((u16)flags & 1) != 0)
        {
            if (randomGetRange(0, 100) == 1)
            {
                switch (bs->mode)
                {
                case 0:
                    bs->mode = 1;
                    bs->timer = 0;
                    bs->amount = 0;
                    break;
                case 3:
                    bs->mode = 1;
                    break;
                }
            }
            else if (randomGetRange(0, 75) == 1)
            {
                if (randomGetRange(0, 1) == 0)
                {
                    bs->mode = 4;
                }
                else
                {
                    bs->mode = 5;
                }
            }
        }
        break;
    case 1:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount + (s16)step > 255)
        {
            step = (u8)(255 - bs->amount);
            bs->mode = 2;
        }
        bs->amount += step;
        break;
    case 2:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if (randomGetRange(0, 100) == 1)
        {
            switch (bs->mode)
            {
            case 1:
            case 2:
                bs->mode = 3;
                break;
            case 4:
            case 5:
                bs->mode = 0;
                break;
            }
        }
        break;
    case 3:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount - (s16)step < 0)
        {
            step = bs->amount;
            bs->mode = 0;
        }
        bs->amount -= step;
        break;
    case 4:
        bs->timer = (u8)(lbl_803DE9A0 * timeDelta + (f32)bs->timer);
        bs->amount = 0xff;
        rightScale = lbl_803DE9A4;
        if (randomGetRange(0, 25) == 1)
        {
            switch (bs->mode)
            {
            case 1:
            case 2:
                bs->mode = 3;
                break;
            case 4:
            case 5:
                bs->mode = 0;
                break;
            }
        }
        break;
    case 5:
        bs->timer = (u8)(lbl_803DE9A0 * timeDelta + (f32)bs->timer);
        bs->amount = 0xff;
        leftScale = lbl_803DE9A4;
        if (randomGetRange(0, 25) == 1)
        {
            switch (bs->mode)
            {
            case 1:
            case 2:
                bs->mode = 3;
                break;
            case 4:
            case 5:
                bs->mode = 0;
                break;
            }
        }
        break;
    }

    phase = lbl_803DE9AC * (f32)bs->timer;
    wave = lbl_803DE9A8 * fn_802943F4(phase);
    wave = wave * (f32)bs->amount / lbl_803DE9B0;
    rotation = (lbl_803DE9B4 * (leftScale * wave)) / lbl_803DE9B8;
    joint = 0;
    model = objAnim->modelInstance;
    if (model != 0)
    {
        jointDataOffset = 0;
        poseOffset = 0;
        for (jointCount = model->jointCount; jointCount > 0; jointCount--)
        {
            jointData = (u8*)model->jointData;
            if (((int)jointData[objAnim->bankIndex + jointDataOffset + 1] != 0xff) &&
                ((int)jointData[jointDataOffset] == OBJLIB_BLINK_LEFT_JOINT_TAG))
            {
                joint = (int)objAnim->jointPoseData + poseOffset;
            }
            jointDataOffset += model->modelCount + 1;
            poseOffset += 0x12;
        }
    }
    *(s16*)(joint + 2) = rotation;

    rotation = (lbl_803DE9B4 * (rightScale * wave)) / lbl_803DE9B8;
    joint = 0;
    model = objAnim->modelInstance;
    if (model != 0)
    {
        jointDataOffset = 0;
        poseOffset = 0;
        for (jointCount = model->jointCount; jointCount > 0; jointCount--)
        {
            jointData = (u8*)model->jointData;
            if (((int)jointData[objAnim->bankIndex + jointDataOffset + 1] != 0xff) &&
                ((int)jointData[jointDataOffset] == OBJLIB_BLINK_RIGHT_JOINT_TAG))
            {
                joint = (int)objAnim->jointPoseData + poseOffset;
            }
            jointDataOffset += model->modelCount + 1;
            poseOffset += 0x12;
        }
    }
    *(s16*)(joint + 2) = -rotation;
}


typedef struct ObjLibFlagByte
{
    u8 highBit : 1;
    u8 rest : 7;
} ObjLibFlagByte;

extern ObjLibFlagByte lbl_803DCC00;

void fn_80038F1C(int a, u8 b)
{
    if ((int)(u8)a != 0) return;
    lbl_803DCC00.highBit = b;
}
