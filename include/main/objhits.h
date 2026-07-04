#ifndef MAIN_OBJHITS_H_
#define MAIN_OBJHITS_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objhits_types.h"

#define OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT 5
#define OBJHITS_CONTACT_SCRATCH_COUNT 0x40
#define OBJHITS_CONTACT_SCRATCH_WORDS 7
#define OBJHITS_SWEEP_ENTRY_CAPACITY 400
#define OBJHITS_PRIORITY_INVALID 0x7f
#define OBJHITS_PRIORITY_STATE_ENABLED 0x0001
#define OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE 0x0002
#define OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED 0x0008
#define OBJHITS_PRIORITY_STATE_POSITION_DIRTY 0x0040
#define OBJHITS_PRIORITY_STATE_HIT_EXCLUDED 0x0100 /* object skipped when scanning candidate hit pairs (set by collectible.c on pickup/hide before ObjHits_DisableObject; read in ObjHits_Update) */
#define OBJHITS_PRIORITY_STATE_TRACK_CONTACT 0x0200
#define OBJHITS_PRIORITY_STATE_IMMOVABLE 0x0400 /* suppresses separation-response displacement of the contacted partner (dbegg.c sets while flocking, cfguardian.c clears on landing; read in the separation-response pass) */
#define OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED 0x2000
#define OBJHITS_SHAPE_SPHERE 0x01
#define OBJHITS_SHAPE_CAPSULE 0x02
#define OBJHITS_SHAPE_MODEL_HIT_VOLUMES 0x10
#define OBJHITS_SHAPE_SKELETON 0x20
#define OBJHITS_SHAPE_RESET_MODE_MASK 0x30
#define OBJHITS_ACTIVE_HITBOX_MODE 1
#define OBJHITS_RESET_HITBOX_MODE 2
#define OBJHITS_PRIORITY_WORK_SLOT_COUNT 0x32
#define OBJHITS_PRIORITY_WORK_SLOT_SIZE 0x3c
#define OBJHITS_PRIORITY_WORK_SLOT_ACTIVE_OFFSET 0x00
#define OBJHITS_PRIORITY_WORK_SLOT_OBJ_OFFSET 0x08
#define OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SLOTS 8
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SLOTS 0x10
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_COUNT 3
#define OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SIZE \
  (OBJHITS_PRIORITY_WORK_SLOT_SIZE * OBJHITS_PRIORITY_WORK_CLEAR_HALF_BLOCK_SLOTS)
#define OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SIZE \
  (OBJHITS_PRIORITY_WORK_SLOT_SIZE * OBJHITS_PRIORITY_WORK_CLEAR_BLOCK_SLOTS)
#define OBJHITS_SKELETON_HIT_CAPACITY 0x13
#define OBJHITS_SKELETON_HIT_WORD_COUNT 0x12
#define OBJHITS_SKELETON_HIT_SIZE 0x48
#define OBJHITS_SKELETON_HIT_POINT_A_OFFSET 0x08
#define OBJHITS_SKELETON_HIT_POINT_B_OFFSET 0x14
#define OBJHITS_SKELETON_HIT_AXIAL_OFFSET 0x2c
#define OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET 0x3c
#define OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET 0x40
#define OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET 0x44
#define OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD 0x10
#define OBJHITS_SKELETON_HIT_POINT_INDEX_B_WORD 0x11
#define OBJHITS_SKELETON_HIT_SENTINEL -1
#define OBJHITS_MODEL_HIT_VOLUME_SIZE 0x18
#define OBJHITS_MODEL_HIT_VOLUME_LINKS_OFFSET 0x14
#define OBJHITS_MODEL_HIT_VOLUME_SPHERE_INDEX_OFFSET 0x16
#define OBJHITS_MODEL_HIT_VOLUME_MASK_BIT_OFFSET 0x17
#define OBJHITBOX_WORLD_X_OFFSET 0x18
#define OBJHITBOX_WORLD_Y_OFFSET 0x1C
#define OBJHITBOX_WORLD_Z_OFFSET 0x20
#define OBJHITBOX_TRANSFORM_STATE_OFFSET 0x58
#define OBJHITBOX_DEF_OFFSET 0x54
#define OBJHITBOX_RADIUS_X_OFFSET 0x18
#define OBJHITBOX_RADIUS_Y_OFFSET 0x1C
#define OBJHITBOX_RADIUS_Z_OFFSET 0x20
#define OBJHITBOX_DEF_DISTANCE_CACHE_OFFSET 0x58
#define OBJHITBOX_DEF_RADIUS_OFFSET 0x5A
#define OBJHITBOX_DEF_VERTICAL_MIN_OFFSET 0x5C
#define OBJHITBOX_DEF_VERTICAL_MAX_OFFSET 0x5E
#define OBJHITBOX_DEF_FLAGS_OFFSET 0x60
#define OBJHITBOX_DEF_SHAPE_FLAGS_OFFSET 0x62
#define OBJHITBOX_DEF_HIT_TYPE_OFFSET 0x6C
#define OBJHITBOX_DEF_HIT_PRIORITY_OFFSET 0x6D
#define OBJHITBOX_DEF_SKIP_OBJECT_PAIRS_OFFSET 0xAE
#define OBJHITBOX_DEF_SKIP_SKELETON_PAIRS_OFFSET 0xAF
#define OBJHITBOX_DEF_SOLID 0x0001
#define OBJHITBOX_DEF_NO_SEPARATION_RESPONSE 0x0002
#define OBJHITBOX_DEF_CLAMP_Y 0x0800
#define OBJHITBOX_DEF_CLAMP_Z 0x1000
#define OBJHITBOX_DEFAULT_CAPSULE_SCALE 0x400
#define OBJHITBOX_SHAPE_SKELETON_3D 0x01
#define OBJHITBOX_SHAPE_VERTICAL_SPAN 0x02
#define OBJHITBOX_SHAPE_CHECK_REVERSE 0x20
#define OBJHITBOX_STATE_MATRIX_STRIDE 0x40
#define OBJHITBOX_STATE_MATRIX_FLOAT_COUNT 0x10
#define OBJHITBOX_CONTACT_OBJECT_COUNT 3
#define OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET 0x100
#define OBJHITBOX_STATE_ACTIVE_MATRIX_INDEX_OFFSET 0x10C
#define OBJHITBOX_STATE_RESET_FRAMES_OFFSET 0x10D
#define OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET 0x10F
#define OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES 10

extern int gObjHitsActiveHitVolumeObjects[OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT];
extern f32 gObjHitsContactScratch[OBJHITS_CONTACT_SCRATCH_COUNT * OBJHITS_CONTACT_SCRATCH_WORDS];
extern void *gObjHitsPrimaryHitboxBufferScratch0;
extern void *gObjHitsSecondaryHitboxBufferScratch0;
extern const f32 gObjHitsScalarZero;
extern f32 gObjHitsScalarOne;
extern char sObjHitsTooManyHitSpheresWarning[];

#define gObjHitsPrimaryHitboxBufferScratch1 (&gObjHitsPrimaryHitboxBufferScratch0)[1]
#define gObjHitsSecondaryHitboxBufferScratch1 (&gObjHitsSecondaryHitboxBufferScratch0)[1]

typedef struct ObjHitboxDef {
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

typedef struct ObjHitboxTransformState {
  f32 matrices[4][4][4];
  int contactObjects[OBJHITBOX_CONTACT_OBJECT_COUNT];
  u8 activeMatrixIndex;
  u8 resetFrames;
  u8 pad10E;
  s8 contactObjectCount;
} ObjHitboxTransformState;

typedef struct ObjHitbox {
  s16 rotationX;
  s16 rotationY;
  s16 rotationZ;
  u8 pad06[OBJHITBOX_RADIUS_X_OFFSET - 6];
  f32 radiusX;
  f32 radiusY;
  f32 radiusZ;
  u8 pad24[OBJHITBOX_DEF_OFFSET - 0x24];
  ObjHitboxDef *def;
  ObjHitboxTransformState *transformState;
} ObjHitbox;

typedef struct ObjHitsSweepEntry {
  float maxX;
  float minX;
  int obj;
} ObjHitsSweepEntry;

typedef struct ObjHitsPriorityWorkSlot {
  int active;
  u8 pad04[OBJHITS_PRIORITY_WORK_SLOT_OBJ_OFFSET - 0x04];
  int obj;
  u8 pad0C[OBJHITS_PRIORITY_WORK_SLOT_SIZE - 0x0C];
} ObjHitsPriorityWorkSlot;

typedef struct ObjHitsModelJointInfo {
  s8 parentJoint;
  u8 pad01[0x1C - 0x01];
} ObjHitsModelJointInfo;

typedef struct ObjHitsModelHitVolume {
  f32 radius;
  f32 x;
  f32 y;
  f32 z;
  u8 pad10[OBJHITS_MODEL_HIT_VOLUME_LINKS_OFFSET - 0x10];
  u16 linkedSpheres;
  s8 sphereIndex;
  s8 maskBit;
} ObjHitsModelHitVolume;

typedef struct ObjHitsModelFileHeader {
  u8 pad00[0x3C];
  ObjHitsModelJointInfo *joints;
  u8 pad40[0x58 - 0x40];
  ObjHitsModelHitVolume *hitVolumes;
  u8 pad5C[0xF3 - 0x5C];
  u8 jointCount;
  u8 padF4[0xF7 - 0xF4];
  u8 hitVolumeCount;
} ObjHitsModelFileHeader;

typedef struct ObjHitsSkeletonJointData {
  u8 pad00[0x04];
  f32 *jointRadii;
  u8 pad08[0x0C - 0x08];
  f32 *jointLengths;
  f32 *jointCullDistances;
  u8 pad14[0x18 - 0x14];
  u8 *touchedJoints;
} ObjHitsSkeletonJointData;

typedef struct ObjHitsModelBank {
  ObjHitsModelFileHeader *modelFile;
  u8 pad04[0x14 - 0x04];
  ObjHitsSkeletonJointData *skeletonJointData;
  u16 hitBufferFlags;
  u8 pad1A[0x48 - 0x1A];
  f32 *hitVolumeSphereBuffers[2];
  f32 *activeHitVolumeSpheres;
} ObjHitsModelBank;

/*
 * The skeleton collectors fill a 0x48-byte hit record and terminate the list
 * by writing -1 to pointIndexA. Response code then walks the same records to
 * blend capsule normals and pair response vectors.
 */
typedef struct ObjHitsSkeletonHit {
  float *pointARef;
  float *pointBRef;
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

STATIC_ASSERT(sizeof(ObjHitsModelJointInfo) == 0x1C);
STATIC_ASSERT(sizeof(ObjHitsModelHitVolume) == OBJHITS_MODEL_HIT_VOLUME_SIZE);
STATIC_ASSERT(offsetof(ObjHitsModelHitVolume, linkedSpheres) == OBJHITS_MODEL_HIT_VOLUME_LINKS_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsModelHitVolume, sphereIndex) == OBJHITS_MODEL_HIT_VOLUME_SPHERE_INDEX_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsModelHitVolume, maskBit) == OBJHITS_MODEL_HIT_VOLUME_MASK_BIT_OFFSET);
STATIC_ASSERT(offsetof(ObjHitsModelFileHeader, joints) == 0x3C);
STATIC_ASSERT(offsetof(ObjHitsModelFileHeader, hitVolumes) == 0x58);
STATIC_ASSERT(offsetof(ObjHitsModelFileHeader, jointCount) == 0xF3);
STATIC_ASSERT(offsetof(ObjHitsModelFileHeader, hitVolumeCount) == 0xF7);
STATIC_ASSERT(offsetof(ObjHitsSkeletonJointData, jointRadii) == 0x04);
STATIC_ASSERT(offsetof(ObjHitsSkeletonJointData, jointLengths) == 0x0C);
STATIC_ASSERT(offsetof(ObjHitsSkeletonJointData, jointCullDistances) == 0x10);
STATIC_ASSERT(offsetof(ObjHitsSkeletonJointData, touchedJoints) == 0x18);
STATIC_ASSERT(offsetof(ObjHitsModelBank, skeletonJointData) == 0x14);
STATIC_ASSERT(offsetof(ObjHitsModelBank, hitBufferFlags) == 0x18);
STATIC_ASSERT(offsetof(ObjHitsModelBank, hitVolumeSphereBuffers) == 0x48);
STATIC_ASSERT(offsetof(ObjHitsModelBank, activeHitVolumeSpheres) == 0x50);

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

int ObjHits_CollectSkeletonHitsXZ(f32 *point,f32 radius,ObjHitsSkeletonJointData *jointData,
                                  int *model,ObjHitsSkeletonHit *hits,
                                  ObjHitsSkeletonHit **outBest,f32 yMax,f32 yMin,f32 *outAccum);
int ObjHits_CollectSkeletonHits3D(f32 *point,f32 radius,ObjHitsSkeletonJointData *jointData,
                                  int *model,ObjHitsSkeletonHit *hits,
                                  ObjHitsSkeletonHit **outBest,f32 *outAccum);
int ObjHits_CalcSkeletonResponseXZ(f32 *pos,f32 radius,int obj,ObjHitsSkeletonHit *hits,
                                   ObjHitsSkeletonJointData *jointPoints,int jointModel,
                                   ObjHitsSkeletonHit *bestHit,f32 t,f32 axial,f32 *out);
int ObjHits_CalcSkeletonResponse3D(f32 *pos,f32 radius,int obj,ObjHitsSkeletonHit *hits,
                                   ObjHitsSkeletonJointData *jointPoints,int jointModel,
                                   ObjHitsSkeletonHit *bestHit,f32 t,f32 axial,f32 *out);
float *ObjHits_ProjectPointToTaperedCapsuleXZ(float *point,float pointRadius,float axial,
                                              float *base,float *tip,float baseRadius,
                                              float tipRadius,float length,float *out);
float *ObjHits_ProjectPointToTaperedCapsule3D(float *point,float pointRadius,float axial,
                                              float *base,float *tip,float baseRadius,
                                              float tipRadius,float length,float *out);
float *ObjHits_CalcTaperedCapsuleNormal(float *point,float axial,float *base,float *tip,
                                        float baseRadius,float tipRadius,float length,
                                        float *out);
int ObjHits_TestTaperedCapsuleXZ(float *point,float pointRadius,float baseRadius,float tipRadius,
                                 float *base,float *axis,float *tip,float length,
                                 float *axial,float *dist2,float *sumR);
int ObjHits_TestTaperedCapsule3D(float *point,float pointRadius,float baseRadius,float tipRadius,
                                 float *base,float *axis,float *tip,float length,
                                 float *axial,float *dist2,float *sumR);
void ObjHits_SortSweepEntries(ObjHitsSweepEntry **sweepPtrs,int entryCount);
void ObjHits_TickPriorityHitCooldowns(void);
void ObjHitbox_UpdateRotatedBounds(ObjHitbox *hitbox,int advanceMatrix);
u8 ObjHits_CheckHitVolumes(int objA,int objB,int srcObj,char checkA,char checkB,u32 mask,
                           u32 volMask);
void doNothing_800333C8(int objA,int objB,int att,void *state,void *attState,f32 dt);
void ObjHits_CheckObjectHitVolumes(int objA,int objB,int attA,int attB,f32 dt);
void ObjHits_RegisterActiveHitVolumeObject(int obj);
void ObjHits_ApplyPairResponse(int objA,int objB,f32 x,f32 y,f32 z,int flag);
void ObjHits_DetectObjectPair(int objA,int objB);
void ObjHits_CheckSkeletonPair(int objA,int objB,void *hits,void *scratchB,void *scratchC,
                               void *scratchD,void *scratchE,int depth);
void ObjHits_CheckTrackContact(int objA,int objB);
void ObjHits_Update(int objectCount);
void ObjHits_SetTargetMask(int obj,u8 targetMask);
void ObjHits_ClearHitVolumes(int obj);
void ObjHits_SetHitVolumeMasks(int obj,int hitVolume,int hitType,int sourceMask);
void ObjHits_SetHitVolumeSlot(u32 obj,int hitVolume,int hitType,int sourceSlot);
void ObjHits_ClearSourceMask(int obj,int sourceMask);
void ObjHits_SetSourceMask(int obj,u8 sourceMask);
void ObjHits_ClearFlags(int obj,int flags);
void ObjHits_SetFlags(int obj,int flags);
void ObjHits_MarkObjectPositionDirty(int obj);
void ObjHits_SyncObjectPositionIfDirty(u32 obj);
void ObjHits_DisableObject(u32 obj);
void ObjHits_EnableObject(u32 obj);
u16 ObjHits_IsObjectEnabled(int obj);
void ObjHits_SyncObjectPosition(u32 obj);
void ObjHits_RefreshObjectState(int obj);
void ObjHits_AddContactObject(int obj,int contactObj);
int ObjHits_RecordObjectHit(int obj,int hitObj,s8 priority,s8 hitVolume,s8 sphereIndex);
int ObjHits_RecordPositionHit(f32 hitPosX,f32 hitPosY,f32 hitPosZ,int obj,int hitObj,
                              s8 priority,s8 hitVolume,s8 sphereIndex);
int ObjHits_GetPriorityHitWithPosition(int obj,int *outHitObject,int *outSphereIndex,
                u32 *outHitVolume,float *outHitPosX,float *outHitPosY,float *outHitPosZ);
int ObjHits_GetPriorityHit(int obj,int *outHitObject,int *outSphereIndex,u32 *outHitVolume);
int ObjHits_PollPriorityHitWithCooldown(int obj,float *cooldown,int *outHitObject,
                                        float *outHitPos);
int ObjHits_PollPriorityHitEffectWithCooldown(int obj,u32 hitFxMode,u32 colorR,u32 colorG,
                                              u32 colorB,u32 sfxId,float *cooldown);

#endif /* MAIN_OBJHITS_H_ */
