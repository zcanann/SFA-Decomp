#ifndef MAIN_OBJHITS_H_
#define MAIN_OBJHITS_H_

#include "ghidra_import.h"

#define OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT 5
#define OBJHITS_CONTACT_SCRATCH_COUNT 0x40
#define OBJHITS_CONTACT_SCRATCH_WORDS 7
#define OBJHITS_SWEEP_ENTRY_CAPACITY 400
#define OBJHITS_PRIORITY_HIT_COUNT 3
#define OBJHITS_PRIORITY_INVALID 0x7f
#define OBJHITS_PRIORITY_STATE_ENABLED 0x0001
#define OBJHITS_PRIORITY_STATE_POSITION_DIRTY 0x0040
#define OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED 0x2000
#define OBJHITS_SHAPE_SPHERE 0x01
#define OBJHITS_SHAPE_CAPSULE 0x02
#define OBJHITS_SHAPE_SKELETON 0x20
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

extern int gObjHitsActiveHitVolumeObjects[OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT];
extern f32 gObjHitsContactScratch[OBJHITS_CONTACT_SCRATCH_COUNT * OBJHITS_CONTACT_SCRATCH_WORDS];
extern void *gObjHitsPrimaryHitboxBufferScratch0;
extern void *gObjHitsSecondaryHitboxBufferScratch0;
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
  float minX;
  float maxX;
  int obj;
} ObjHitsSweepEntry;

typedef struct ObjHitsPriorityWorkSlot {
  int active;
  u8 pad04[OBJHITS_PRIORITY_WORK_SLOT_OBJ_OFFSET - 0x04];
  int obj;
  u8 pad0C[OBJHITS_PRIORITY_WORK_SLOT_SIZE - 0x0C];
} ObjHitsPriorityWorkSlot;

typedef struct ObjHitsPriorityState {
  u8 pad00[0x48];
  u32 objectHitMask;
  u32 skeletonHitMask;
  int lastHitObject;
  u8 pad54[0x0C];
  s16 flags;
  u8 shapeFlags;
  u8 pad63[0x6E - 0x63];
  s8 objectHitType;
  s8 skeletonHitType;
  u8 pad70;
  s8 priorityHitCount;
  s8 sphereIndices[OBJHITS_PRIORITY_HIT_COUNT];
  s8 priorities[OBJHITS_PRIORITY_HIT_COUNT];
  u8 hitVolumes[OBJHITS_PRIORITY_HIT_COUNT];
  u8 pad7B;
  int hitObjects[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosX[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosY[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosZ[OBJHITS_PRIORITY_HIT_COUNT];
  u8 contactHitVolume;
  u8 contactFlags;
  u8 padAE[0xB0 - 0xAE];
  u8 stateIndex;
  u8 padB1[0xB4 - 0xB1];
  u8 sourceMask;
  u8 targetMask;
  u8 secondaryShapeFlags;
} ObjHitsPriorityState;

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
  float axis[3];
  float axial;
  float surfaceDistance;
  float distance;
  float capsuleAxial;
  float inverseDistance;
  s32 pointIndexA;
  s32 pointIndexB;
} ObjHitsSkeletonHit;

void ObjHits_CollectSkeletonHitsXZ(undefined8 param_1,double param_2,double param_3,
                                   undefined4 param_4,undefined4 param_5,int *param_6,
                                   int *param_7,int *param_8,float *param_9);
void ObjHits_CollectSkeletonHits3D(undefined4 param_1,undefined4 param_2,int *param_3,
                                   int *param_4,int *param_5,float *param_6);
void ObjHits_CalcSkeletonResponseXZ(undefined8 param_1,double param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10);
void ObjHits_CalcSkeletonResponse3D(undefined8 param_1,undefined8 param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10);
float *ObjHits_ProjectPointToTaperedCapsuleXZ(float pointRadius,float axial,float baseRadius,
                                              float tipRadius,float length,float *point,
                                              float *base,float *tip,float *out);
float *ObjHits_ProjectPointToTaperedCapsule3D(float pointRadius,float axial,float baseRadius,
                                              float tipRadius,float length,float *point,
                                              float *base,float *tip,float *out);
float *ObjHits_CalcTaperedCapsuleNormal(float axial,float baseRadius,float tipRadius,
                                        float length,float *point,float *base,float *tip,
                                        float *out);
uint ObjHits_TestTaperedCapsuleXZ(float pointRadius,float baseRadius,float tipRadius,float length,
                                  float *point,float *base,float *axis,float *tip,
                                  float *axial,float *dist2,float *sumR);
uint ObjHits_TestTaperedCapsule3D(float pointRadius,float baseRadius,float tipRadius,float length,
                                  float *point,float *base,float *axis,float *tip,
                                  float *axial,float *dist2,float *sumR);
void ObjHits_SortSweepEntries(ObjHitsSweepEntry **sweepPtrs,int entryCount);
void ObjHits_TickPriorityHitCooldowns(void);
void ObjHitbox_UpdateRotatedBounds(ObjHitbox *hitbox,int advanceMatrix);
u8 ObjHits_CheckHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8,undefined4 param_9,undefined4 param_10,
                           int param_11,undefined4 param_12,undefined4 param_13,uint param_14,
                           uint param_15,undefined4 param_16);
void doNothing_800333C8(void);
void ObjHits_CheckObjectHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,
                                   undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                   undefined8 param_7,undefined8 param_8,undefined4 param_9,
                                   undefined4 param_10,int param_11,int param_12);
void ObjHits_RegisterActiveHitVolumeObject(int obj);
void ObjHits_ApplyPairResponse(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                               undefined4 param_5,int param_6);
void ObjHits_DetectObjectPair(void);
void ObjHits_CheckSkeletonPair(undefined4 param_1,undefined4 param_2,int *param_3);
void ObjHits_CheckTrackContact(void);
void ObjHits_Update(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
int ObjHits_GetPriorityHitWithPosition(int obj,undefined4 *outHitObject,int *outSphereIndex,
                uint *outHitVolume,float *outHitPosX,float *outHitPosY,float *outHitPosZ);
int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume);

#endif /* MAIN_OBJHITS_H_ */
