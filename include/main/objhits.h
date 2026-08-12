#ifndef MAIN_OBJHITS_H_
#define MAIN_OBJHITS_H_

#include "global.h"
#include "game/objects/object.h"
#include "types.h"
#include "main/model.h"
#include "main/objhits_types.h"

#define OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT       5
#define OBJHITS_CONTACT_SCRATCH_COUNT                0x40
#define OBJHITS_SWEEP_ENTRY_CAPACITY                 400
#define OBJHITS_PRIORITY_INVALID                     0x7f
#define OBJHITS_SHAPE_SPHERE                         0x01
#define OBJHITS_SHAPE_CAPSULE                        0x02
#define OBJHITS_SHAPE_MODEL_HIT_VOLUMES              0x10
#define OBJHITS_SHAPE_SKELETON                       0x20
#define OBJHITS_SHAPE_RESET_MODE_MASK                0x30
#define OBJHITS_ACTIVE_HITBOX_MODE                   1
#define OBJHITS_RESET_HITBOX_MODE                    2
#define OBJHITS_PRIORITY_WORK_SLOT_COUNT             0x32
#define OBJHITS_PRIORITY_WORK_SLOT_SIZE              0x3c
#define OBJHITS_PRIORITY_WORK_SLOT_ACTIVE_OFFSET     0x00
#define OBJHITS_PRIORITY_WORK_SLOT_OBJ_OFFSET        0x08
#define OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SLOTS 8
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SLOTS      0x10
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_COUNT      3
#define OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SIZE                                                                    \
    (OBJHITS_PRIORITY_WORK_SLOT_SIZE * OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SLOTS)
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SIZE                                                                         \
    (OBJHITS_PRIORITY_WORK_SLOT_SIZE * OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SLOTS)
#define OBJHITS_SKELETON_HIT_CAPACITY                0x13
#define OBJHITS_SKELETON_HIT_WORD_COUNT              0x12
#define OBJHITS_SKELETON_HIT_SIZE                    0x48
#define OBJHITS_SKELETON_HIT_POINT_A_OFFSET          0x08
#define OBJHITS_SKELETON_HIT_POINT_B_OFFSET          0x14
#define OBJHITS_SKELETON_HIT_AXIAL_OFFSET            0x2c
#define OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET 0x3c
#define OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET    0x40
#define OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET    0x44
#define OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD      0x10
#define OBJHITS_SKELETON_HIT_POINT_INDEX_B_WORD      0x11
#define OBJHITS_SKELETON_HIT_SENTINEL                -1
#define OBJHITBOX_WORLD_X_OFFSET                     0x18
#define OBJHITBOX_WORLD_Y_OFFSET                     0x1C
#define OBJHITBOX_WORLD_Z_OFFSET                     0x20
#define OBJHITBOX_TRANSFORM_STATE_OFFSET             0x58
#define OBJHITBOX_DEF_OFFSET                         0x54
#define OBJHITBOX_RADIUS_X_OFFSET                    0x18
#define OBJHITBOX_RADIUS_Y_OFFSET                    0x1C
#define OBJHITBOX_RADIUS_Z_OFFSET                    0x20
#define OBJHITBOX_DEF_DISTANCE_CACHE_OFFSET          0x58
#define OBJHITBOX_DEF_RADIUS_OFFSET                  0x5A
#define OBJHITBOX_DEF_VERTICAL_MIN_OFFSET            0x5C
#define OBJHITBOX_DEF_VERTICAL_MAX_OFFSET            0x5E
#define OBJHITBOX_DEF_FLAGS_OFFSET                   0x60
#define OBJHITBOX_DEF_SHAPE_FLAGS_OFFSET             0x62
#define OBJHITBOX_DEF_HIT_TYPE_OFFSET                0x6C
#define OBJHITBOX_DEF_HIT_PRIORITY_OFFSET            0x6D
#define OBJHITBOX_DEF_SKIP_OBJECT_PAIRS_OFFSET       0xAE
#define OBJHITBOX_DEF_SKIP_SKELETON_PAIRS_OFFSET     0xAF
#define OBJHITBOX_DEF_SOLID                          0x0001
#define OBJHITBOX_DEF_NO_SEPARATION_RESPONSE         0x0002
#define OBJHITBOX_DEF_CLAMP_Y                        0x0800
#define OBJHITBOX_DEF_CLAMP_Z                        0x1000
#define OBJHITBOX_DEFAULT_CAPSULE_SCALE              0x400
#define OBJHITBOX_SHAPE_SKELETON_3D                  0x01
#define OBJHITBOX_SHAPE_VERTICAL_SPAN                0x02
#define OBJHITBOX_SHAPE_CHECK_REVERSE                0x20
#define OBJHITBOX_STATE_MATRIX_STRIDE                0x40
#define OBJHITBOX_STATE_MATRIX_FLOAT_COUNT           0x10
#define OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET       0x100
#define OBJHITBOX_STATE_ACTIVE_MATRIX_INDEX_OFFSET   0x10C
#define OBJHITBOX_STATE_RESET_FRAMES_OFFSET          0x10D
#define OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET  0x10F
#define OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES        10

typedef struct ObjHitsContactScratchEntry
{
    f32 responseX;
    f32 responseZ;
    f32 contactOffsetX;
    f32 contactOffsetY;
    f32 contactOffsetZ;
    f32 depth;
    u8 sphereIndexA;
    u8 sphereIndexB;
    u8 reserved[2];
} ObjHitsContactScratchEntry;

STATIC_ASSERT(sizeof(ObjHitsContactScratchEntry) == 0x1C);

extern GameObject* gObjHitsActiveHitVolumeObjects[OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT];
extern ObjHitsContactScratchEntry gObjHitsContactScratch[OBJHITS_CONTACT_SCRATCH_COUNT];
extern void* gObjHitsPrimaryHitboxBufferScratch0;
extern void* gObjHitsSecondaryHitboxBufferScratch0;
extern const f32 gObjHitsScalarZero[1];
extern const f32 gObjHitsScalarTwo[1];
extern const f32 gObjHitsScalarTenth[1];
extern const f32 gObjHitsScalarOne[1];
extern char sObjHitsTooManyHitSpheresWarning[];

void ObjHitbox_SetStateIndex(GameObject* obj, ObjHitReactState* hitState, int stateIndex);
#ifdef OBJHITS_SETTERS_S16
void ObjHitbox_SetSphereRadius(ObjAnimComponent* obj, s16 radius);
void ObjHitbox_SetCapsuleBounds(ObjAnimComponent* obj, s16 radius, s16 verticalMin, s16 verticalMax);
#else
void ObjHitbox_SetSphereRadius(ObjAnimComponent* obj, int radius);
void ObjHitbox_SetCapsuleBounds(ObjAnimComponent* obj, int radius, int verticalMin, int verticalMax);
#endif
int ObjHits_AllocObjectState(GameObject* obj, u32 arena);
void ObjHits_ResetWorkBuffers(void);
void ObjHits_InitWorkBuffers(void);

#define gObjHitsPrimaryHitboxBufferScratch1   (&gObjHitsPrimaryHitboxBufferScratch0)[1]
#define gObjHitsSecondaryHitboxBufferScratch1 (&gObjHitsSecondaryHitboxBufferScratch0)[1]

typedef struct ObjHitboxDef
{
    u8 pad00[OBJHITBOX_DEF_DISTANCE_CACHE_OFFSET];
    s16 distanceCache;
    s16 radius;
    s16 verticalMin;
    s16 verticalMax;
    s16 flags;
    u8 shapeFlags;
    u8 pad63[OBJHITBOX_DEF_HIT_TYPE_OFFSET - 0x63];
    s8 hitType;
    u8 hitPriority;
    u8 pad6E[OBJHITBOX_DEF_SKIP_OBJECT_PAIRS_OFFSET - 0x6E];
    u8 skipObjectPairs;
    u8 skipSkeletonPairs;
} ObjHitboxDef;

typedef struct ObjHitbox
{
    s16 rotationX;
    s16 rotationY;
    s16 rotationZ;
    u8 pad06[OBJHITBOX_RADIUS_X_OFFSET - 6];
    f32 radiusX;
    f32 radiusY;
    f32 radiusZ;
    u8 pad24[OBJHITBOX_DEF_OFFSET - 0x24];
    ObjHitboxDef* def;
    ObjHitboxTransformState* transformState;
} ObjHitbox;

typedef struct ObjHitsSweepEntry
{
    float maxX;
    float minX;
    GameObject* obj;
} ObjHitsSweepEntry;
STATIC_ASSERT(offsetof(ObjHitsSweepEntry, obj) == 0x08);

typedef struct ObjHitsPriorityWorkSlot
{
    int active;
    u8 pad04[OBJHITS_PRIORITY_WORK_SLOT_OBJ_OFFSET - 0x04];
    GameObject* object;
    u8 pad0C[OBJHITS_PRIORITY_WORK_SLOT_SIZE - 0x0C];
} ObjHitsPriorityWorkSlot;

/*
 * The skeleton collectors fill a 0x48-byte hit record and terminate the list
 * by writing -1 to pointIndexA. Response code then walks the same records to
 * blend capsule normals and pair response vectors.
 */
typedef struct ObjHitsSkeletonHit
{
    float* pointARef;
    float* pointBRef;
    float pointA[3];
    float pointB[3];
    float axisDir[3];
    float capsuleAxial;
    float signedSurfaceDistance;
    float centerDistance;
    float radiusSum;
    float inverseDistance;
    s32 pointIndexA;
    s32 pointIndexB;
} ObjHitsSkeletonHit;

STATIC_ASSERT(sizeof(ObjHitsSkeletonHit) == OBJHITS_SKELETON_HIT_SIZE);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointARef) == 0x00);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointBRef) == 0x04);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointA) == OBJHITS_SKELETON_HIT_POINT_A_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointB) == OBJHITS_SKELETON_HIT_POINT_B_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, axisDir) == 0x20);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, capsuleAxial) == OBJHITS_SKELETON_HIT_AXIAL_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, signedSurfaceDistance) == 0x30);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, centerDistance) == 0x34);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, radiusSum) == 0x38);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, inverseDistance) == OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointIndexA) == OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsSkeletonHit, pointIndexB) == OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET);

int ObjHits_CollectSkeletonHitsXZ(f32* point, f32 radius, ModelJointWork* jointData, int* model,
                                  ObjHitsSkeletonHit* hits, ObjHitsSkeletonHit** outBest, f32 yMax, f32 yMin,
                                  f32* outAccum);
int ObjHits_CollectSkeletonHits3D(f32* point, f32 radius, ModelJointWork* jointData, int* model,
                                  ObjHitsSkeletonHit* hits, ObjHitsSkeletonHit** outBest, f32* outAccum);
int ObjHits_CalcSkeletonResponseXZ(f32* pos, f32 radius, GameObject* obj, ObjHitsSkeletonHit* hits,
                                   ModelJointWork* jointPoints, int jointModel, ObjHitsSkeletonHit* bestHit,
                                   f32 t, f32 axial, f32* out);
int ObjHits_CalcSkeletonResponse3D(f32* pos, f32 radius, GameObject* obj, ObjHitsSkeletonHit* hits,
                                   ModelJointWork* jointPoints, int jointModel, ObjHitsSkeletonHit* bestHit,
                                   f32 t, f32 axial, f32* out);
float* ObjHits_ProjectPointToTaperedCapsuleXZ(float* point, float pointRadius, float axial, float* base, float* tip,
                                              float baseRadius, float tipRadius, float length, float* out);
float* ObjHits_ProjectPointToTaperedCapsule3D(float* point, float pointRadius, float axial, float* base, float* tip,
                                              float baseRadius, float tipRadius, float length, float* out);
float* ObjHits_CalcTaperedCapsuleNormal(float* point, float axial, float* base, float* tip, float baseRadius,
                                        float tipRadius, float length, float* out);
int ObjHits_TestTaperedCapsuleXZ(float* point, float pointRadius, float baseRadius, float tipRadius, float* base,
                                 float* axis, float* tip, float length, float* axial, float* dist2, float* sumR);
int ObjHits_TestTaperedCapsule3D(float* point, float pointRadius, float baseRadius, float tipRadius, float* base,
                                 float* axis, float* tip, float length, float* axial, float* dist2, float* sumR);
void ObjHits_SortSweepEntries(ObjHitsSweepEntry** sweepPtrs, int entryCount);
void ObjHits_TickPriorityHitCooldowns(void);
void ObjHitbox_UpdateRotatedBounds(ObjHitbox* hitbox, int advanceMatrix);
int ObjHits_CheckHitVolumes(GameObject* objA, GameObject* objB, GameObject* srcObj, char checkA, char checkB, u32 mask, u32 volMask);
void ObjHits_OnPlayerHitVolumeMiss(GameObject* objA, GameObject* objB, GameObject* attachment, void* state, void* attachmentState, f32 dt);
void ObjHits_CheckObjectHitVolumes(GameObject* objA, GameObject* objB, GameObject* attA, GameObject* attB, f32 dt);
void ObjHits_RegisterActiveHitVolumeObject(GameObject* obj);
void ObjHits_ApplyPairResponse(GameObject* objA, GameObject* objB, f32 x, f32 y, f32 z, int flag);
void ObjHits_DetectObjectPair(GameObject* objA, GameObject* objB);
void ObjHits_CheckSkeletonPair(GameObject* objA, GameObject* objB, void* hits, void* scratchB, void* scratchC, void* scratchD,
                               void* scratchE, int depth);
void ObjHits_CheckTrackContact(GameObject* objA, GameObject* objB);
void ObjHits_Update(int objectCount);
void ObjHits_SetTargetMask(GameObject* obj, u8 targetMask);
void ObjHits_ClearHitVolumes(ObjAnimComponent* obj);
void ObjHits_SetHitVolumeMasks(ObjAnimComponent* obj, int hitVolume, int hitType, int sourceMask);
void ObjHits_SetHitVolumeSlot(ObjAnimComponent* obj, int hitVolume, int hitType, int sourceSlot);
void ObjHits_ClearSourceMask(ObjAnimComponent* obj, int sourceMask);
void ObjHits_SetSourceMask(ObjAnimComponent* obj, u8 sourceMask);
void ObjHits_ClearFlags(ObjAnimComponent* obj, int flags);
void ObjHits_SetFlags(ObjAnimComponent* obj, int flags);
void ObjHits_MarkObjectPositionDirty(ObjAnimComponent* obj);
void ObjHits_SyncObjectPositionIfDirty(GameObject* obj);
void ObjHits_DisableObject(GameObject* obj);
void ObjHits_EnableObject(GameObject* obj);
int ObjHits_IsObjectEnabled(ObjAnimComponent* obj);
void ObjHits_SyncObjectPosition(GameObject* obj);
void ObjHits_RefreshObjectState(GameObject* obj);
void ObjHits_AddContactObject(GameObject* obj, GameObject* contactObj);
int ObjHits_RecordPositionHit(GameObject* obj, GameObject* hitObj, s8 priority, int hitVolume, s8 sphereIndex,
                              f32 hitPosX, f32 hitPosY, f32 hitPosZ);
int ObjHits_RecordObjectHit(GameObject* obj, GameObject* hitObj, s8 priority, int hitVolume, s8 sphereIndex);
int ObjHits_GetPriorityHitWithPosition(GameObject* obj, GameObject** outHitObject, int* outSphereIndex,
                                       u32* outHitVolume, float* outHitPosX, float* outHitPosY, float* outHitPosZ);
int ObjHits_GetPriorityHit(GameObject* obj, GameObject** outHitObject, int* outSphereIndex, u32* outHitVolume);
int ObjHits_PollPriorityHitWithCooldown(GameObject* obj, float* cooldown, GameObject** outHitObject, float* outHitPos);
int ObjHits_PollPriorityHitEffectWithCooldown(GameObject* obj, u32 hitFxMode, u32 colorR, u32 colorG, u32 colorB,
                                              u16 sfxId, float* cooldown);

#endif /* MAIN_OBJHITS_H_ */
