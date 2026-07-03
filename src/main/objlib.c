#include "main/dll/objpathtransform_struct.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/objlib.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "string.h"
#include "main/sfa_extern_decls.h"

typedef struct ObjLibRegionList ObjLibRegionList;

extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern float sqrtf(float x);
extern u32 buttonGetDisabled(int port);
extern void buttonDisable(int port, u32 mask);
extern void setMatrixFromObjectTransposed(void* obj, f32* out);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern f32 Vec_distance(f32* a, f32* b);
extern void OSReport(const char* msg, ...);
extern float* ObjModel_GetJointMatrix(int* model, int jointIndex);
extern void Obj_BuildWorldTransformMatrix(u8* obj, f32* mtx, int flags);
extern void mtx44Transpose(f32* src, f32* dst);
extern int* Obj_GetActiveModel(int obj);
extern void Obj_UpdateObject(ObjAnimComponent * obj, ObjModelInstance * modelInstance);
extern void fn_80054F74(int obj, float* pos);

extern void debugPrintf(char* fmt, ...);
extern void PSMTXConcat(float* a, float* b, float* out);
extern float PSVECSquareDistance(float* a, float* b);
extern float mathSinf(float x);
extern float fn_802943F4(float x);
extern float mathCosf(float x);
extern int playerIsDisguised(int obj);
extern int objGetAnimState80A(void* obj);

#define OBJGROUP_COUNT 0x54
#define OBJGROUP_OFFSET_CLEAR_COUNT (OBJGROUP_COUNT + 1)
#define OBJGROUP_MAX_OBJECTS 0x100
#define OBJLIB_PRIMARY_ROM_PAGE_COUNT 0x50
#define OBJHITREGION_ROM_ENTRY_TYPE 0x130

u32 gObjGroupObjects[OBJGROUP_MAX_OBJECTS];
u8 gObjGroupOffsets[0x58];

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

ObjContactCallbackEntry gObjContactCallbacks[0xC0 / sizeof(ObjContactCallbackEntry)];
extern void* gObjHitsWorkBuffer;
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
extern f32 gObjLibAnglePiNumerator;
extern f32 gObjLibAngleUnitDivisor;
extern f32 lbl_803DE998;
extern f32 lbl_803DE99C;
extern f32 lbl_803DE9A0;
extern f32 lbl_803DE9A4;
extern f32 lbl_803DE9A8;
extern f32 lbl_803DE9AC;
extern f32 lbl_803DE9B0;
extern f32 gObjLibBlinkAngleUnitScale;
extern f32 gObjLibBlinkAnglePiDivisor;

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
    u32 message;
    u32 sender;
    u32 param;
} ObjMsgEntry;

typedef struct ObjMsgQueue
{
    u32 count;
    u32 capacity;
    ObjMsgEntry entries[1];
} ObjMsgQueue;

typedef struct ObjMsgQueueSlotBase
{
    u32 count;
    u32 capacity;
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

#pragma peephole off
void ObjHits_SetTargetMask(int objPtr, u8 targetMask)
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

void ObjHitbox_SetCapsuleBounds(int objPtr, s16 radius, s16 verticalMin, s16 verticalMax)
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
            absVal = verticalMin;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = verticalMax;
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
            absVal = verticalMin;
            if (absVal < 0)
            {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = verticalMax;
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

void ObjHits_SetHitVolumeMasks(int objPtr, int hitVolume, int hitType, int sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->hitVolumePriority = hitVolume;
    hitState->hitVolumeId = hitType;
    if (sourceMask == 0)
    {
        return;
    }
    hitState->objectHitMask = sourceMask << 4;
    hitState->skeletonHitMask = sourceMask << 4;
    return;
}

void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot)
{
    int hitMask;
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    if (hitState == 0)
    {
        return;
    }
    hitState->hitVolumePriority = hitVolume;
    hitState->hitVolumeId = hitType;
    if (sourceSlot == -1)
    {
        return;
    }
    hitMask = 1 << (sourceSlot + 4);
    hitState->objectHitMask = hitMask;
    hitState->skeletonHitMask = hitMask;
    return;
}

void ObjHits_ClearSourceMask(int objPtr, int sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->sourceMask = (u8)(hitState->sourceMask & ~sourceMask);
    return;
}

void ObjHits_SetSourceMask(int objPtr, u8 sourceMask)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->sourceMask |= sourceMask;
    return;
}

void ObjHits_ClearFlags(int objPtr, int flags)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags & ~flags);
    return;
}

void ObjHits_SetFlags(int objPtr, int flags)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags | flags);
    return;
}

void ObjHits_MarkObjectPositionDirty(int objPtr)
{
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState;
    hitState->flags = (s16)(hitState->flags | OBJHITS_PRIORITY_STATE_POSITION_DIRTY);
    return;
}

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

u16 ObjHits_IsObjectEnabled(int objPtr)
{
    return ((ObjHitsPriorityState*)((ObjAnimComponent*)objPtr)->hitReactState)->flags &
        OBJHITS_PRIORITY_STATE_ENABLED;
}

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

int ObjHits_AllocObjectState(int objPtr, u32 arena)
{
    u32 stateArena;
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

int ObjHits_RecordObjectHit(int obj, int hitObj, s8 priority, s8 hitVolume, s8 sphereIndex)
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
        hitState->priorities[hitState->priorityHitCount] = priority;
        hitState->hitVolumes[hitState->priorityHitCount] = hitVolume;
        hitState->hitObjects[hitState->priorityHitCount] = hitObj;
        hitState->hitPosX[hitState->priorityHitCount] = sourceObj->localPosX;
        hitState->hitPosY[hitState->priorityHitCount] = sourceObj->localPosY;
        hitState->hitPosZ[hitState->priorityHitCount] = sourceObj->localPosZ;
        hitState->priorityHitCount++;
    }
    return 1;
}

int ObjHits_RecordPositionHit(f32 hitPosX, f32 hitPosY, f32 hitPosZ, int obj, int hitObj, s8 priority,
                              s8 hitVolume, s8 sphereIndex)
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
        hitState->priorities[hitState->priorityHitCount] = priority;
        hitState->hitVolumes[hitState->priorityHitCount] = hitVolume;
        hitState->hitObjects[hitState->priorityHitCount] = hitObj;
        hitState->hitPosX[hitState->priorityHitCount] = hitPosX;
        hitState->hitPosY[hitState->priorityHitCount] = hitPosY;
        hitState->hitPosZ[hitState->priorityHitCount] = hitPosZ;
        hitState->priorityHitCount++;
    }
    return 1;
}

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
        if (entryObj == contactObj)
        {
            return;
        }
        contactOffset = contactOffset + 4;
    }
    storeState = *(int*)((u8*)obj + OBJHITBOX_TRANSFORM_STATE_OFFSET);
    contactObjectIndex = (*(char*)(transformState + OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET))++;
    *(int*)(storeState + OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET +
        contactObjectIndex * 4) = contactObj;
    return;
}

#pragma dont_inline on
int ObjHits_GetPriorityHitWithPosition(int obj, int* outHitObject, int* outSphereIndex,
                                       u32* outHitVolume, float* outHitPosX, float* outHitPosY, float* outHitPosZ)
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
    hitCount = hitState->priorityHitCount;
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
                bestHitSlot = hitSlot;
            }
        }
        if (bestHitSlot != -1)
        {
            if (outHitObject != 0x0)
            {
                *outHitObject = hitState->hitObjects[bestHitSlot];
            }
            if (outSphereIndex != 0x0)
            {
                *outSphereIndex = hitState->sphereIndices[bestHitSlot];
            }
            if (outHitVolume != 0x0)
            {
                *outHitVolume = hitState->hitVolumes[bestHitSlot];
            }
            if (outHitPosX != (float*)0x0)
            {
                *outHitPosX = hitState->hitPosX[bestHitSlot];
                *outHitPosY = hitState->hitPosY[bestHitSlot];
                *outHitPosZ = hitState->hitPosZ[bestHitSlot];
            }
            return (int)(s8)bestPriority;
        }
    }
    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
int ObjHits_GetPriorityHit(int obj, int* outHitObject, int* outSphereIndex, u32* outHitVolume)
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
    hitCount = hitState->priorityHitCount;
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
                bestHitSlot = hitSlot;
            }
        }
        if (bestHitSlot != -1)
        {
            if (outHitObject != 0x0)
            {
                *outHitObject = hitState->hitObjects[bestHitSlot];
            }
            if (outSphereIndex != 0x0)
            {
                *outSphereIndex = hitState->sphereIndices[bestHitSlot];
            }
            if (outHitVolume != 0x0)
            {
                *outHitVolume = hitState->hitVolumes[bestHitSlot];
            }
            return (int)(s8)bestPriority;
        }
    }
    return 0;
}
#pragma dont_inline reset

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

void ObjHits_ResetWorkBuffers(void)
{
    int slotIndex;

    for (slotIndex = 0; slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT; slotIndex++)
    {
        ((ObjHitsPriorityWorkSlot*)gObjHitsPriorityHitStates)[slotIndex].active = 0;
    }
    gObjHitReactResetObjectCount = 0;
}

ObjAnimComponent** ObjHitReact_GetResetObjects(int* outObjectCount)
{
    *outObjectCount = gObjHitReactResetObjectCount;
    return gObjHitReactResetObjects;
}

#pragma peephole on
void ObjHits_InitWorkBuffers(void)
{
    int hitVolumeIndex;

    gObjHitReactResetObjects =
        (ObjAnimComponent**)mmAlloc(OBJHITREACT_MAX_RESET_OBJECTS * sizeof(ObjAnimComponent*), 0xe, 0);
    gObjHitsPriorityHitStates =
        mmAlloc(OBJHITS_PRIORITY_WORK_SLOT_COUNT * sizeof(ObjHitsPriorityWorkSlot), 0xe, 0);
    gObjHitsWorkBuffer = mmAlloc(0x1900, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPriorityHitTickDelta = lbl_803DE914;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex = 0] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    return;
}
#pragma peephole reset

u32 ObjGroup_ContainsObject(u32 obj, int group)
{
    u32* entry;
    u32 index;
    u32 limit;
    u32 limitXorIndex;
    int halfDiff;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    index = gObjGroupOffsets[group];
    limit = gObjGroupOffsets[group + 1];
    for (entry = gObjGroupObjects + index; ((int)index < (int)limit && (obj != *entry));
         entry = entry + 1, index = index + 1)
    {
    }
    limitXorIndex = limit ^ index;
    halfDiff = (int)limitXorIndex >> 1;
    limitXorIndex = limitXorIndex & limit;
    return (u32)(halfDiff - limitXorIndex) >> 0x1f;
}

#pragma opt_loop_invariants off
int ObjGroup_FindNearestObjectToPoint(int group, float* point, float* maxDistance)
{
    u32* entry;
    u32 nearest;
    u32 index;
    u32 limit;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    bestDistanceSq = *maxDistance * *maxDistance;
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return 0;
    }
    index = gObjGroupOffsets[group];
    limit = (u32)(&gObjGroupOffsets[group])[1];
    entry = gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != 0)
        {
            distanceSq = PSVECSquareDistance(point, &((GameObject*)*entry)->anim.worldPosX);
            if (distanceSq < bestDistanceSq)
            {
                bestDistanceSq = distanceSq;
                nearest = *entry;
            }
            entry++;
            index++;
        }
    }
    if (nearest != 0)
    {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}
#pragma opt_loop_invariants reset

#pragma opt_loop_invariants off
int ObjGroup_FindNearestObjectForObject(int group, u32 obj, float* maxDistance)
{
    u32* entry;
    u32 nearest;
    u32 index;
    u32 limit;
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
    index = gObjGroupOffsets[group];
    limit = (u32)(&gObjGroupOffsets[group])[1];
    entry = gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != obj)
        {
            distanceSq = vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX,
                                                &((GameObject*)*entry)->anim.worldPosX);
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

int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance)
{
    u32* entry;
    u32 nearest;
    u32 index;
    u32 limit;
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
    index = gObjGroupOffsets[group];
    limit = (u32)(&gObjGroupOffsets[group])[1];
    entry = gObjGroupObjects + index;
    while ((int)index < (int)limit)
    {
        if (*entry != obj)
        {
            distanceSq = vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX,
                                                &((GameObject*)*entry)->anim.worldPosX);
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
#pragma opt_loop_invariants reset

u32* ObjGroup_GetObjects(int group, int* countOut)
{
    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        *countOut = 0;
        return 0x0;
    }
    *countOut = gObjGroupOffsets[group + 1] - gObjGroupOffsets[group];
    return (u32*)(gObjGroupObjects + gObjGroupOffsets[group]);
}

void ObjGroup_RemoveObject(u32 obj, int group)
{
    u8* offset;
    u8 count;
    int index;
    int limit;
    u32* entries;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return;
    }
    offset = gObjGroupOffsets;
    index = offset[group];
    offset += group;
    limit = offset[1];
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

int ObjGroup_GetObjectGroup(u32 obj)
{
    int group;
    int objectIndex;

    for (objectIndex = 0; objectIndex < (int)(u32)gObjGroupObjectCount; objectIndex++)
    {
        u32 entryObj = gObjGroupObjects[objectIndex];
        if (entryObj == obj)
        {
            group = 0;
            while (((int)(u32)gObjGroupOffsets[group] <= objectIndex) &&
                (group < OBJGROUP_OFFSET_CLEAR_COUNT))
            {
                group++;
            }
            return group;
        }
    }
    return 0;
}

void ObjGroup_AddObject(u32 obj, int group)
{
    u8* offset;
    int count;
    int index;
    int insertIndex;
    int limit;
    u32* entries;

    if ((group < 0) || (group >= OBJGROUP_COUNT))
    {
        return;
    }
    if ((int)(u32)gObjGroupObjectCount >= OBJGROUP_MAX_OBJECTS)
    {
        OSReport(sObjAddObjectTypeReachedMaxTypes);
        return;
    }
    offset = gObjGroupOffsets;
    insertIndex = offset[group];
    offset += group;
    limit = offset[1];
    entries = gObjGroupObjects + insertIndex;
    for (index = insertIndex; index < limit; index++)
    {
        if (*entries == obj)
        {
            return;
        }
        entries++;
    }
    insertIndex = (insertIndex - limit == 0) ? insertIndex : (limit - 1);
    gObjGroupObjectCount++;
    count = (int)(u32)gObjGroupObjectCount - 1;
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

void ObjGroup_ClearAll(void)
{
    memset(gObjGroupOffsets, 0, OBJGROUP_OFFSET_CLEAR_COUNT);
    gObjGroupObjectCount = 0;
    return;
}

u32 ObjMsg_Peek(void* obj, u32* outMessage, u32* outSender, u32* outParam)
{
    ObjMsgQueue* queue;

    if (obj == 0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET);
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0))
    {
        if (outMessage != 0x0)
        {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != 0x0)
        {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != 0x0)
        {
            *outParam = queue->entries[0].param;
        }
        return 1;
    }
    return 0;
}

u32 ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam)
{
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    u32 i;

    if (obj == 0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET);
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0))
    {
        queue->count = queue->count - 1;
        if (outMessage != 0x0)
        {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != 0x0)
        {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != 0x0)
        {
            *outParam = queue->entries[0].param;
        }
        for (i = 0; i < queue->count; i = i + 1)
        {
            slot = (ObjMsgQueueSlotBase*)((u8*)queue + ((i + i + i) << 2));
            slot->entry.message = *(u32*)((u8*)slot + 0x14);
            slot->entry.sender = *(u32*)((u8*)slot + 0x18);
            slot->entry.param = *(u32*)((u8*)slot + 0x1c);
        }
        return 1;
    }
    return 0;
}

#pragma opt_loop_invariants off
void ObjMsg_SendToNearbyObjects(int targetId, float radius, u32 flags, void* sender, u32 message, u32 param)
{
    int* objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    int objectIndex;
    int objectCount;
    void* obj;
    int includeSender;
    int matchAny;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    includeSender = maskedFlags & OBJMSG_SEND_INCLUDE_SENDER;
    matchAny = maskedFlags & OBJMSG_SEND_MATCH_ANY;
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1)
    {
        obj = (void*)objects[objectIndex];
        if (((obj != sender) || (includeSender == 0)) &&
            ((((GameObject*)obj)->anim.seqId == (s16)targetId ||
                (matchAny != 0))) &&
            ((Vec_distance(&((GameObject*)sender)->anim.worldPosX,
                           &((GameObject*)obj)->anim.worldPosX) < radius &&
                    (obj != 0x0)) &&
                (queue = *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET),
                    queue != (ObjMsgQueue*)0x0)))
        {
            count = queue->count;
            if (count < queue->capacity)
            {
                slot = (ObjMsgQueueSlotBase*)((u8*)queue + ((count + count + count) << 2));
                slot->entry.message = message;
                slot->entry.sender = (u32)sender;
                slot->entry.param = param;
                queue->count = queue->count + 1;
            }
            else
            {
                debugPrintf(sObjMsgOverflowInObjectWarning, message,
                            (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                            (int)((GameObject*)sender)->anim.seqId);
            }
        }
    }
    return;
}
#pragma opt_loop_invariants reset

void ObjMsg_SendToObjects(int targetId, u32 flags, void* sender, u32 message, u32 param)
{
    int* objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;
    int objectIndex;
    int objectCount;
    void* obj;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    if ((maskedFlags & OBJMSG_SEND_MATCH_OBJTYPE) != 0)
    {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1)
        {
            obj = (void*)objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 ||
                    (targetId == ((GameObject*)obj)->anim.seqId))) &&
                ((obj != 0x0 &&
                    (queue = *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET),
                        queue != (ObjMsgQueue*)0x0))))
            {
                count = queue->count;
                if (count < queue->capacity)
                {
                    slot = (ObjMsgQueueSlotBase*)((u8*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (u32)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                }
                else
                {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message,
                                (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                                (int)((GameObject*)sender)->anim.seqId);
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
                ((obj != 0x0 &&
                    (queue = *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET),
                        queue != (ObjMsgQueue*)0x0))))
            {
                count = queue->count;
                if (count < queue->capacity)
                {
                    slot = (ObjMsgQueueSlotBase*)((u8*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (u32)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                }
                else
                {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message,
                                (int)((GameObject*)obj)->anim.classId, (int)((GameObject*)obj)->anim.seqId,
                                (int)((GameObject*)sender)->anim.seqId);
                }
            }
        }
    }
    return;
}

u32 ObjMsg_SendToObject(void* obj, u32 message, void* sender, u32 param)
{
    u32 count;
    void* dstObj;
    void* senderObj;
    ObjMsgQueue* queue;
    ObjMsgQueueSlotBase* slot;

    dstObj = obj;
    senderObj = sender;
    if (dstObj == 0x0)
    {
        return 0;
    }
    queue = *(ObjMsgQueue**)((u8*)dstObj + OBJMSG_QUEUE_OFFSET);
    if (queue != (ObjMsgQueue*)0x0)
    {
        count = queue->count;
        if (count < queue->capacity)
        {
            slot = (ObjMsgQueueSlotBase*)((u8*)queue + ((count + count + count) << 2));
            slot->entry.message = message;
            slot->entry.sender = (u32)senderObj;
            slot->entry.param = param;
            queue->count = queue->count + 1;
            return queue->count;
        }
        debugPrintf(sObjMsgOverflowInObjectWarning, message,
                    (int)((GameObject*)dstObj)->anim.classId, (int)((GameObject*)dstObj)->anim.seqId,
                    (int)((GameObject*)senderObj)->anim.seqId);
    }
    return 0;
}

void ObjMsg_AllocQueue(void* obj, int capacity)
{
    int queueBytes;
    ObjMsgQueue* queue;

    if (((capacity != 0) && (obj != 0x0)) &&
        (*(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET) == (ObjMsgQueue*)0x0))
    {
        queueBytes = (capacity * 3 + 2) * 4;
        queue = (ObjMsgQueue*)mmAlloc(queueBytes, 0xe, 0);
        queue->count = 0;
        queue->capacity = capacity;
        *(ObjMsgQueue**)((u8*)obj + OBJMSG_QUEUE_OFFSET) = queue;
    }
    return;
}

u32 Obj_IsObjectAlive(u32 obj)
{
    u32 alive;

    alive = 0;
    if ((obj != 0) && ((((GameObject*)obj)->objectFlags & OBJLINK_FLAGS_DEAD) == 0))
    {
        alive = 1;
    }
    return alive;
}

bool ObjTrigger_UpdateIdBlockFlag(int obj)
{
    int val;
    u8 flags;

    val = (int)Obj_GetPlayerObject();
    val = playerIsDisguised(val);
    if (val != 0)
    {
        flags = *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET) | OBJTRIGGER_ID_BLOCK_FLAG;
        *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET) = flags;
        return false;
    }
    flags = *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET) & ~OBJTRIGGER_ID_BLOCK_FLAG;
    *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET) = flags;
    return true;
}

int ObjHits_PollPriorityHitWithCooldown(int obj, float* cooldown, int* outHitObject, float* outHitPos)
{
    int collisionType;

    collisionType = 0;
    *cooldown = *cooldown - timeDelta;
    if (*cooldown <= lbl_803DE970)
    {
        if (outHitPos != (float*)0x0)
        {
            collisionType = ObjHits_GetPriorityHitWithPosition(obj, outHitObject, 0x0, 0x0, outHitPos,
                                                               outHitPos + 1, outHitPos + 2);
            if (collisionType != 0)
            {
                fn_80054F74(obj, outHitPos);
            }
        }
        else
        {
            collisionType = ObjHits_GetPriorityHit(obj, outHitObject, 0x0, 0x0);
        }
        if (collisionType != 0)
        {
            *cooldown = lbl_803DE974;
        }
    }
    return collisionType;
}

int ObjHits_PollPriorityHitEffectWithCooldown(int obj, u32 hitFxMode, u32 colorR, u32 colorG,
                                              u32 colorB, u32 sfxId, float* cooldown)
{
    int collisionType;
    ObjHitReactEffectHandle* effectHandle;
    float hitPos[3];
    ObjHitReactEffectPos effectPos;
    ObjHitReactEffectColorArgs effectArgs;
    u32 hitObject;

    *cooldown = *cooldown - timeDelta;
    collisionType = ObjHits_GetPriorityHitWithPosition(obj, (int*)&hitObject, 0x0,
                                                       0x0, &hitPos[0], &hitPos[1], &hitPos[2]);
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
            if ((((sfxId & 0xffff) != 0) && (hitObject != 0)) &&
                (((GameObject*)hitObject)->anim.seqId == 0x69))
            {
                extern void Sfx_PlayFromObject(int obj, int id);
                Sfx_PlayFromObject(obj, sfxId);
            }
        }
    }
    return collisionType;
}

void ObjLink_DetachChild(int obj, int child)
{
    int q;
    int p;
    int i;

    i = 0;
    for (p = obj; i < (int)((GameObject*)obj)->childCount; i++)
    {
        if ((u32) * (int*)(p + OBJLINK_CHILD_LIST_OFFSET) == child)
        {
            break;
        }
        p += 4;
    }
    q = obj + i * 4;
    while (i < (int)((GameObject*)obj)->childCount - 1)
    {
        *(int*)(q + OBJLINK_CHILD_LIST_OFFSET) = *(int*)(q + OBJLINK_CHILD_LIST_OFFSET + sizeof(int));
        q += 4;
        i++;
    }
    ((GameObject*)obj)->childCount--;
    *(int*)(obj + OBJLINK_CHILD_LIST_OFFSET +
        (u32)((GameObject*)obj)->childCount * 4) = 0;
    ((GameObject*)child)->ownerObj = (void*)0;
    return;
}

void ObjLink_AttachChild(int parent, int child, u16 linkMode)
{
    int childIndex;
    GameObject* parentObj;
    GameObject* childObj;

    parentObj = (GameObject*)parent;
    childObj = (GameObject*)child;
    childIndex = (int)parentObj->childCount;
    parentObj->childCount += 1;
    parentObj->childObjs[childIndex] = (void*)child;
    childObj->ownerObj = (void*)parent;
    childObj->objectFlags = (u16)(childObj->objectFlags & ~OBJLINK_FLAGS_MODE_MASK);
    childObj->objectFlags = (u16)(childObj->objectFlags | linkMode);
    *(u8*)(child + OBJLINK_CHILD_STATE_OFFSET) = 0;
    return;
}

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
        if (((u32)entry->objA == objA) && ((u32)entry->objB == objB))
        {
            objARefCount = objARefCount - 1;
            entry->callback(objA, objB);
        }
        if (((u32)entry->objA == objB) && ((u32)entry->objB == objA))
        {
            objBRefCount = objBRefCount - 1;
            entry->callback(objB, objA);
        }
        entry++;
    }
    return;
}

void ObjContact_RemoveObjectCallbacks(int obj)
{
    int count;
    ObjContactCallbackEntry* entry;

    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    while (count-- > 0)
    {
        if (((u32)entry->objA == obj) || ((u32)entry->objB == obj))
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

u32 ObjContact_AddCallback(int obj, int otherObj, ObjContactCallback callback)
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
    for (i = 0; i != count; i++)
    {
        if (((u32)entry->objA == obj) && ((u32)entry->objB == otherObj))
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
    *(u8*)(obj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) += 1;
    *(u8*)(otherObj + OBJCONTACT_OBJECT_REFCOUNT_OFFSET) += 1;
    gObjContactCallbackCount = gObjContactCallbackCount + 1;
    return 1;
}

u32 ObjTrigger_IsSetById(int obj, short eventId)
{
    int val;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    triggerFlags = *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET);
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

u32 ObjTrigger_IsSet(int obj)
{
    u32 flags;
    int val;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    if (*(u32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x40) == 0)
    {
        return 0;
    }
    flags = buttonGetDisabled(0);
    if ((flags & OBJTRIGGER_BUTTON_DISABLE_FLAG) == 0)
    {
        triggerFlags = *(u8*)(obj + OBJTRIGGER_FLAGS_OFFSET);
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

#pragma opt_loop_invariants off
int ObjList_FindNearestObjectByDefNo(int obj, int defNo, float* maxDistanceSq)
{
    int startIndex;
    int objectCount;
    float invalidDistance;
    float distanceSq;
    u32 otherObj;
    int objectIndex;
    int* objects;
    int* walker;
    int foundObj;

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    foundObj = 0;
    *maxDistanceSq = *maxDistanceSq * *maxDistanceSq;
    walker = objects + startIndex;
    if (defNo != -1)
    {
        objectIndex = startIndex;
        walker = objects + startIndex;
        while (objectIndex < objectCount)
        {
            otherObj = *walker;
            if (((defNo == ((GameObject*)otherObj)->anim.seqId) && (obj != otherObj)) &&
                (distanceSq = vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX,
                                                     &((GameObject*)otherObj)->anim.worldPosX),
                    distanceSq < *maxDistanceSq))
            {
                *maxDistanceSq = distanceSq;
                foundObj = *walker;
            }
            walker++;
            objectIndex++;
        }
    }
    else
    {
        objectIndex = startIndex;
        walker = objects + startIndex;
        invalidDistance = lbl_803DE970;
        while (objectIndex < objectCount)
        {
            distanceSq = vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX,
                                               &((GameObject*)*walker)->anim.worldPosX);
            if ((distanceSq != invalidDistance) && (distanceSq < *maxDistanceSq))
            {
                *maxDistanceSq = distanceSq;
                foundObj = *walker;
            }
            walker++;
            objectIndex++;
        }
    }
    return foundObj;
}
#pragma opt_loop_invariants reset

u32 ObjList_ContainsObject(int obj)
{
    u32* entry;
    int i;
    int count;

    entry = ObjList_GetObjects(&i, &count);
    i = 0;
    while (i < count)
    {
        if (*entry == obj)
        {
            return 1;
        }
        entry = entry + 1;
        i = i + 1;
    }
    return 0;
}

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

void ObjPath_GetPointLocalPosition(int obj, int pointIndex, float* xOut, float* yOut,
                                   float* zOut)
{
    *xOut = ((ObjPathPoint*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + OBJPATH_POINTS_OFFSET) +
        pointIndex * sizeof(ObjPathPoint)))->x;
    *yOut = *(f32*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + OBJPATH_POINTS_OFFSET) + 4 +
        pointIndex * sizeof(ObjPathPoint));
    *zOut = *(f32*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + OBJPATH_POINTS_OFFSET) + 8 +
        pointIndex * sizeof(ObjPathPoint));
    return;
}

void ObjPath_GetPointLocalMtx(int obj, int pointIndex, float* mtxOut)
{
    ObjPathPoint* pathPoint;
    ObjPathTransform transform;

    pathPoint = (ObjPathPoint*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
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

void ObjPath_GetPointModelMtx(int obj, int pointIndex)
{
    int* model;
    ObjPathPoint* pathPoint;
    int jointIndex;

    model = Obj_GetActiveModel(obj);
    pathPoint = (ObjPathPoint*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
        OBJPATH_POINTS_OFFSET));
    pathPoint += pointIndex;
    jointIndex = pathPoint->modelIndex[(int)*(char*)(obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
    if ((jointIndex >= 0) && (jointIndex < (int)(u32) * (u8*)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET)))
    {
        ObjModel_GetJointMatrix(model, jointIndex);
    }
    else
    {
        ObjModel_GetJointMatrix(model, 0);
    }
    return;
}

void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ,
                                   int useInputPosition)
{
    int pointOffset;
    ObjPathPoint* pathPoint;
    int* model;
    float* jointMtx;
    int jointIndex;
    ObjPathTransform transform;
    float rootMtx[16];
    float transposedMtx[12];
    float concatMtx[12];
    float rotMtx[16];

    if ((pointIndex < 0) ||
        (pointIndex >=
            (int)(u32) * (u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + OBJPATH_POINT_COUNT_OFFSET)))
    {
        *outX = ((GameObject*)obj)->anim.localPosX;
        *outY = ((GameObject*)obj)->anim.localPosY;
        *outZ = ((GameObject*)obj)->anim.localPosZ;
    }
    else
    {
        model = Obj_GetActiveModel(obj);
        pathPoint = (ObjPathPoint*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
            OBJPATH_POINTS_OFFSET));
        pointOffset = pointIndex * sizeof(ObjPathPoint);
        pathPoint = (ObjPathPoint*)((int)pathPoint + pointOffset);
        jointIndex = pathPoint->modelIndex[(int)*(char*)(obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
        if ((jointIndex < OBJPATH_ROOT_JOINT_INDEX) ||
            (jointIndex >= (int)(u32) * (u8*)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET)))
        {
            *outX = ((GameObject*)obj)->anim.localPosX;
            *outY = ((GameObject*)obj)->anim.localPosY;
            *outZ = ((GameObject*)obj)->anim.localPosZ;
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
                transform.x = *(f32*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
                        OBJPATH_POINTS_OFFSET) +
                    pointOffset);
                pathPoint = (ObjPathPoint*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
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

int Obj_GetYawDeltaToObject(u16* obj, int target, float* distOut)
{
    int yawDelta;
    float dx;
    float dz;

    dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)target)->anim.localPosX;
    dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)target)->anim.localPosZ;
    yawDelta = getAngle(dx, dz);
    if (distOut != (float*)0x0)
    {
        *distOut = sqrtf(dx * dx + dz * dz);
    }
    yawDelta = (int)(short)yawDelta - (u32)(u16)*(s16*)obj;
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

u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z)
{
    ObjLibRegionList** lists;
    ObjLibRegionList* list;
    ObjLibRegionEntry* entry;
    int listIndex;
    int entryOffset;
    int hitId;

    hitId = -1;
    lists = RomList_GetLoadedPages();
    for (listIndex = 0; listIndex < OBJLIB_PRIMARY_ROM_PAGE_COUNT; listIndex++)
    {
        list = lists[listIndex];
        if (list != 0)
        {
            entry = list->entries;
            entryOffset = 0;
            while (entryOffset < (int)(u32)list->entryBytes)
            {
                if (entry->type == OBJHITREGION_ROM_ENTRY_TYPE)
                {
                    f32 yawCos =
                        mathSinf(gObjLibAnglePiNumerator * (f32) - (s32)((u32)entry->yaw << 8) / gObjLibAngleUnitDivisor);
                    f32 yawSin = mathCosf(gObjLibAnglePiNumerator * (f32) - (s32)((u32)entry->yaw << 8) / gObjLibAngleUnitDivisor);
                    f32 pitchCos =
                        mathSinf(gObjLibAnglePiNumerator * (f32) - (s32)((u32)entry->pitch << 8) / gObjLibAngleUnitDivisor);
                    f32 pitchSin =
                        mathCosf(gObjLibAnglePiNumerator * (f32) - (s32)((u32)entry->pitch << 8) / gObjLibAngleUnitDivisor);
                    f32 deltaZ;
                    f32 deltaY;
                    f32 deltaX;
                    f32 localX;
                    f32 yawZ;
                    f32 localY;
                    f32 localZ;
                    deltaX = x - entry->x;
                    deltaY = y - entry->y;
                    deltaZ = z - entry->z;
                    localX = deltaX * yawSin - deltaZ * yawCos;
                    yawZ = deltaX * yawCos + deltaZ * yawSin;
                    localY = deltaY * pitchSin - yawZ * pitchCos;
                    localZ = deltaY * pitchCos + yawZ * pitchSin;

                    if (localX < 0.0f)
                    {
                        localX = -localX;
                    }
                    if (localY < 0.0f)
                    {
                        localY = -localY;
                    }
                    if (localZ < 0.0f)
                    {
                        localZ = -localZ;
                    }
                    if ((localX <= (f32)(u32)entry->halfX
                    )
                    &&
                    (localY <= (f32)(u32)
                    entry->halfY
                    )
                    &&
                    (localZ <= (f32)(u32)
                    entry->halfZ
                    )
                    )
                    {
                        hitId = entry->id;
                    }
                }
                entryOffset += entry->wordCount * 4;
                entry = (ObjLibRegionEntry*)((u8*)entry + entry->wordCount * 4);
            }
        }
    }
    return hitId & 0xffff;
}

/* Eye-blink state machine (PlayerBlinkState.mode). amount = eyelid closure 0..255. */
typedef enum ObjLibBlinkMode
{
    OBJLIB_BLINK_MODE_OPEN = 0,       /* eyes open; randomly start a blink or a wink */
    OBJLIB_BLINK_MODE_CLOSING = 1,    /* eyelids ramping shut (amount -> 255) */
    OBJLIB_BLINK_MODE_CLOSED = 2,     /* fully shut; randomly start opening */
    OBJLIB_BLINK_MODE_OPENING = 3,    /* eyelids ramping open (amount -> 0) */
    OBJLIB_BLINK_MODE_WINK_RIGHT = 4, /* hold shut, right eye scaled apart */
    OBJLIB_BLINK_MODE_WINK_LEFT = 5,  /* hold shut, left eye scaled apart */
} ObjLibBlinkMode;

typedef struct PlayerBlinkState
{
    u8 pad[0x2b];
    u8 mode; /* 0x2b */
    u8 timer; /* 0x2c */
    u8 amount; /* 0x2d */
} PlayerBlinkState;

void playerEyeAnimFn_80038988(int obj, int blinkState, u32 flags)
{

    PlayerBlinkState* bs = (PlayerBlinkState*)blinkState;
    ObjModelInstance* model;
    int jointDataOffset;
    f32 leftScale;
    int poseOffset;
    u8* jointData;
    s16 rotation;
    int joint;
    ObjAnimComponent* objAnim;
    f32 phase;
    u8 step;
    f32 rightScale;
    int jointCount;
    f32 wave;

    objAnim = (ObjAnimComponent*)obj;
    step = lbl_803DE998 * timeDelta;
    rightScale = (leftScale = lbl_803DE99C);
    switch (bs->mode)
    {
    case OBJLIB_BLINK_MODE_OPEN:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        bs->amount = 0;
        if (((u16)flags & 1) != 0)
        {
            if (randomGetRange(0, 100) == 1)
            {
                switch (bs->mode)
                {
                case OBJLIB_BLINK_MODE_OPEN:
                    bs->mode = OBJLIB_BLINK_MODE_CLOSING;
                    bs->timer = 0;
                    bs->amount = 0;
                    break;
                case OBJLIB_BLINK_MODE_OPENING:
                    bs->mode = OBJLIB_BLINK_MODE_CLOSING;
                    break;
                }
            }
            else if (randomGetRange(0, 75) == 1)
            {
                if (randomGetRange(0, 1) == 0)
                {
                    bs->mode = OBJLIB_BLINK_MODE_WINK_RIGHT;
                }
                else
                {
                    bs->mode = OBJLIB_BLINK_MODE_WINK_LEFT;
                }
            }
        }
        break;
    case OBJLIB_BLINK_MODE_CLOSING:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount + (s16)step > 255)
        {
            step = (u8)(255 - bs->amount);
            bs->mode = OBJLIB_BLINK_MODE_CLOSED;
        }
        bs->amount += step;
        break;
    case OBJLIB_BLINK_MODE_CLOSED:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if (randomGetRange(0, 100) == 1)
        {
            switch (bs->mode)
            {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    case OBJLIB_BLINK_MODE_OPENING:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount - (s16)step < 0)
        {
            step = bs->amount;
            bs->mode = OBJLIB_BLINK_MODE_OPEN;
        }
        bs->amount -= step;
        break;
    case OBJLIB_BLINK_MODE_WINK_RIGHT:
        bs->timer = (u8)(lbl_803DE9A0 * timeDelta + bs->timer);
        bs->amount = 0xff;
        rightScale = lbl_803DE9A4;
        if (randomGetRange(0, 25) == 1)
        {
            switch (bs->mode)
            {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    case OBJLIB_BLINK_MODE_WINK_LEFT:
        bs->timer = (u8)(lbl_803DE9A0 * timeDelta + bs->timer);
        bs->amount = 0xff;
        leftScale = lbl_803DE9A4;
        if (randomGetRange(0, 25) == 1)
        {
            switch (bs->mode)
            {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    }

    phase = lbl_803DE9AC * bs->timer;
    wave = lbl_803DE9A8 * fn_802943F4(phase);
    wave = wave * bs->amount / lbl_803DE9B0;
    rotation = (gObjLibBlinkAngleUnitScale * (leftScale * wave)) / gObjLibBlinkAnglePiDivisor;
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

    rotation = (gObjLibBlinkAngleUnitScale * (rightScale * wave)) / gObjLibBlinkAnglePiDivisor;
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
