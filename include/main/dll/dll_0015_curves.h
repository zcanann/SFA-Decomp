#ifndef MAIN_DLL_CURVES_H_
#define MAIN_DLL_CURVES_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/dll/curve_walker.h"

typedef struct GameObject GameObject;

#define ROMCURVE_MAX_CURVES 0x514
#define ROMCURVE_DEF_SIZE 0x2c
#define ROMCURVE_POINT_SIZE 0x18
#define ROMCURVE_X_OFFSET 0x08
#define ROMCURVE_Y_OFFSET 0x0c
#define ROMCURVE_Z_OFFSET 0x10
#define ROMCURVE_ID_OFFSET 0x14
#define ROMCURVE_ACTION_OFFSET 0x18
#define ROMCURVE_TYPE_OFFSET 0x19
#define ROMCURVE_LINK_FLAGS_OFFSET 0x1b
#define ROMCURVE_LINK_IDS_OFFSET 0x1c
#define ROMCURVE_LINK_ID_STRIDE sizeof(u32)
#define ROMCURVE_LINK_COUNT 4
#define ROMCURVE_LINK_ID_NONE 0xffffffff
#define ROMCURVE_LINK_SEARCH_RESULT_COUNT ROMCURVE_LINK_COUNT
#define ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY 0x28
#define ROMCURVE_PLACEMENT_ROT_Z_OFFSET 0x2c
#define ROMCURVE_PLACEMENT_ROT_Y_OFFSET 0x2d
#define ROMCURVE_PLACEMENT_ROT_X_OFFSET 0x2e
#define ROMCURVE_PLACEMENT_EXT_SIZE 0x30
#define ROMCURVE_PLACEMENT_SPECIAL_ANGLE_OFFSET 0x38
#define ROMCURVE_TYPE_ACTION 0x15
#define ROMCURVE_TYPE_SPECIAL_ANGLE_8 0x08
#define ROMCURVE_TYPE_SPECIAL_ANGLE_1A 0x1a
#define ROMCURVE_TYPE_SCALE_OVERRIDE_15 0x15
#define ROMCURVE_TYPE_SCALE_OVERRIDE_16 0x16
#define ROMCURVE_GETCURVES_MAX_POINTS 0x23
#define ROMCURVE_POINT_TYPE_WATER 0x0e
#define CURVES_COLLISION_STATE_SIZE 0x268
#define CURVES_COLLISION_STATE_ACTIVE 0x04000000
#define CURVES_COLLISION_STATE_LOCAL_POINTS 0x00000008
#define CURVES_COLLISION_STATE_HIT_SEGMENTS 0x00002000
#define CURVES_COLLISION_STATE_SECONDARY_LOCAL_POINTS 0x02000000
#define CURVES_COLLISION_STATE_X_ROTATION_ONLY 0x00000020
#define CURVES_COLLISION_STATE_KEEP_POSITION 0x00100000
#define CURVES_POINT_COUNT_LOCAL_MASK 0x0f
#define CURVES_POINT_COUNT_SEGMENT_MASK 0xf0
#define CURVES_POINT_COUNT_SEGMENT_SHIFT 4
#define CURVES_COLLISION_SUBTYPE_NONE 0
#define CURVES_COLLISION_SUBTYPE_OBJECT 1
#define CURVES_COLLISION_SUBTYPE_POINT 2

typedef struct RomCurveDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  s8 action;
  s8 type;
  u8 pad1A;
  s8 blockedLinkMask;
  u32 linkIds[ROMCURVE_LINK_COUNT];
} RomCurveDef;

typedef struct RomCurvePlacementDef {
  RomCurveDef base;
  s8 rotZ;
  s8 rotY;
  u8 rotX;
  u8 pad2F;
} RomCurvePlacementDef;

typedef struct CurvePlacementParams {
  RomCurvePlacementDef placement;
  u8 pad30[ROMCURVE_PLACEMENT_SPECIAL_ANGLE_OFFSET - ROMCURVE_PLACEMENT_EXT_SIZE];
  s16 specialAngle;
} CurvePlacementParams;

typedef struct RomCurvePoint {
  f32 x;
  f32 y;
  f32 z;
  f32 w;
  u32 flags;
  u8 type;
} RomCurvePoint;

extern RomCurveDef *romCurves[ROMCURVE_MAX_CURVES];
extern int nRomCurves;
extern RomCurveDef *gRomCurveLastFindStart;
extern RomCurveDef *gRomCurveLastFindEnd;
extern RomCurvePoint sCurvesHitPoints[ROMCURVE_GETCURVES_MAX_POINTS];
extern char sCurvesMaxRomCurvesExceeded[];

#include "main/dll/rom_curve_segment_projection.h"

typedef struct CurvesCollisionState {
  u32 flags;
  f32 *segmentLocalPoints;
  f32 points[4][3];        /* 0x008 world-space segment points; double as trace ends */
  f32 traceStart[4][3];    /* 0x038 per-point raised trace starts */
  f32 segmentHitPlanes[4][4]; /* 0x068 trace hit-plane records (x,y,z,d) */
  f32 segmentRadii[4];
  s8 segmentHitTypes[4];
  s8 segmentSourceTypes[4];
  u8 pad0C0[4];
  u32 traceHitObj;         /* 0x0C4 */
  u8 pad0C8[0x0D4 - 0x0C8];
  s16 traceHitCount;       /* 0x0D4 copied into surfaceCounter after segment traces */
  u8 pad0D6[2];
  u32 contactObj;          /* 0x0D8 latest trace hit forwarded to ObjHits_AddContactObject */
  f32 *localPointPositions;
  f32 *localPointRadii;
  f32 localPointWorld[4][3];   /* 0x0E4 localPointPositions transformed to world */
  f32 localPointTarget[4][3];  /* 0x114 raised copies; bbox-swept against localPointWorld */
  f32 localHitPlanes[4][4]; /* 0x144 local-point hit scratch */
  u8 pad184[0x198 - 0x184];
  s16 tiltPitch;           /* 0x198 smoothed toward tiltPitchTarget */
  s16 tiltRoll;            /* 0x19A */
  s16 tiltPitchTarget;     /* 0x19C from surface normal */
  s16 tiltRollTarget;      /* 0x19E */
  f32 surfaceNormalX;      /* 0x1A0 */
  f32 surfaceNormalY;
  f32 surfaceNormalZ;
  f32 resultFloorGap;      /* 0x1AC latest-point copies of the arrays below */
  f32 resultCeilingY;      /* 0x1B0 */
  f32 resultWaterDepth;    /* 0x1B4 */
  f32 resultFloorY;        /* 0x1B8 */
  f32 resultWaterY;        /* 0x1BC */
  f32 floorGap[4];         /* 0x1C0 posY - floorY per point */
  f32 ceilingY[4];         /* 0x1D0 */
  f32 waterDepth[4];       /* 0x1E0 waterY - posY */
  f32 floorY[4];           /* 0x1F0 */
  f32 waterY[4];           /* 0x200 type-0xE surface height */
  f32 waterNormalX[4];     /* 0x210 */
  f32 waterNormalY[4];     /* 0x220 init 1.0 */
  f32 waterNormalZ[4];     /* 0x230 */
  s32 hitBounds[6];        /* 0x240 swept-sphere bounds (minX..maxZ ints) */
  u8 heightPadding;
  u8 pad259[2];
  s8 subtype;
  u8 pointCounts;
  s8 primaryHitType;
  u8 localPointHitMask;
  u8 surfaceHitMask;
  u8 surfaceFlags;
  u8 surfaceCounter;
  u8 updateMode;
  s8 secondaryHitType;
  u8 activeTimer;
  u8 pad265[CURVES_COLLISION_STATE_SIZE - 0x265];
} CurvesCollisionState;

STATIC_ASSERT(sizeof(RomCurveDef) == ROMCURVE_DEF_SIZE);
STATIC_ASSERT(offsetof(RomCurveDef, x) == ROMCURVE_X_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, y) == ROMCURVE_Y_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, z) == ROMCURVE_Z_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, id) == ROMCURVE_ID_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, action) == ROMCURVE_ACTION_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, type) == ROMCURVE_TYPE_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, blockedLinkMask) == ROMCURVE_LINK_FLAGS_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, linkIds) == ROMCURVE_LINK_IDS_OFFSET);

STATIC_ASSERT(sizeof(RomCurvePlacementDef) == ROMCURVE_PLACEMENT_EXT_SIZE);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotZ) == ROMCURVE_PLACEMENT_ROT_Z_OFFSET);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotY) == ROMCURVE_PLACEMENT_ROT_Y_OFFSET);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotX) == ROMCURVE_PLACEMENT_ROT_X_OFFSET);
STATIC_ASSERT(offsetof(CurvePlacementParams, specialAngle) == ROMCURVE_PLACEMENT_SPECIAL_ANGLE_OFFSET);

STATIC_ASSERT(sizeof(RomCurvePoint) == ROMCURVE_POINT_SIZE);
STATIC_ASSERT(offsetof(RomCurvePoint, flags) == 0x10);
STATIC_ASSERT(offsetof(RomCurvePoint, type) == 0x14);

STATIC_ASSERT(sizeof(RomCurveSegmentProjection) == 0x24);
STATIC_ASSERT(offsetof(RomCurveSegmentProjection, endX) == 0x0C);
STATIC_ASSERT(offsetof(RomCurveSegmentProjection, nearestX) == 0x18);

STATIC_ASSERT(sizeof(CurvesCollisionState) == CURVES_COLLISION_STATE_SIZE);
STATIC_ASSERT(offsetof(CurvesCollisionState, flags) == 0x00);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentLocalPoints) == 0x04);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentRadii) == 0xA8);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHitTypes) == 0xB8);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentSourceTypes) == 0xBC);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointPositions) == 0xDC);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointRadii) == 0xE0);
STATIC_ASSERT(offsetof(CurvesCollisionState, points) == 0x008);
STATIC_ASSERT(offsetof(CurvesCollisionState, traceStart) == 0x038);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHitPlanes) == 0x068);
STATIC_ASSERT(offsetof(CurvesCollisionState, traceHitObj) == 0x0C4);
STATIC_ASSERT(offsetof(CurvesCollisionState, contactObj) == 0x0D8);
STATIC_ASSERT(offsetof(CurvesCollisionState, localHitPlanes) == 0x144);
STATIC_ASSERT(offsetof(CurvesCollisionState, tiltPitch) == 0x198);
STATIC_ASSERT(offsetof(CurvesCollisionState, surfaceNormalX) == 0x1A0);
STATIC_ASSERT(offsetof(CurvesCollisionState, resultFloorGap) == 0x1AC);
STATIC_ASSERT(offsetof(CurvesCollisionState, traceHitCount) == 0x0D4);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointWorld) == 0x0E4);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointTarget) == 0x114);
STATIC_ASSERT(offsetof(CurvesCollisionState, floorGap) == 0x1C0);
STATIC_ASSERT(offsetof(CurvesCollisionState, waterY) == 0x200);
STATIC_ASSERT(offsetof(CurvesCollisionState, waterNormalZ) == 0x230);
STATIC_ASSERT(offsetof(CurvesCollisionState, hitBounds) == 0x240);
STATIC_ASSERT(offsetof(CurvesCollisionState, heightPadding) == 0x258);
STATIC_ASSERT(offsetof(CurvesCollisionState, subtype) == 0x25B);
STATIC_ASSERT(offsetof(CurvesCollisionState, pointCounts) == 0x25C);
STATIC_ASSERT(offsetof(CurvesCollisionState, primaryHitType) == 0x25D);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointHitMask) == 0x25E);
STATIC_ASSERT(offsetof(CurvesCollisionState, updateMode) == 0x262);
STATIC_ASSERT(offsetof(CurvesCollisionState, secondaryHitType) == 0x263);
STATIC_ASSERT(offsetof(CurvesCollisionState, activeTimer) == 0x264);

u32
RomCurve_projectPointToAdjacentWindow(f32 x,f32 y,f32 z,u32 *curveIds,
                                      float *outLateralOffset,float *outVerticalOffset,
                                      float *outPhase);
u32 FUN_800e1b2c(double param_1,u64 param_2,double param_3,int param_4,int param_5);
int curves_distFn15(u32 curveId,f32 x,f32 y,f32 z,f32 *outDistance);
int curves_distanceToNearestOfType16(f32 x,f32 y,f32 z,int param_4);
int RomCurve_func13(u32 curveId,int typeFilter,int param_3,int *param_4);
int RomCurve_func11(RomCurveDef *curve,int typeFilter,int actionFilter,int *outCurveId);
int RomCurve_getRandomLinkedOfTypes(RomCurveDef *curve,int *types,int typeCount,int *previousLinkId);
int curves_findByAction(int action);
f32 curves_distXZ(f32 x,f32 z,u32 curveId);
f32 curves_distFn0B(int obj,u32 curveId);
f32 curves_find(int type,int action,f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ);
RomCurveDef *RomCurve_findByIdWithIndex(u32 curveId,int *outIndex);
int RomCurve_func20(RomCurvePlacementDef *curve, f32 *outX, f32 *outY, f32 *outZ, s8 *outTypes);
int RomCurve_countRandomPoints(RomCurveDef *curve);
int RomCurve_func1E(u32 *curveIds,float *outX,float *outY,float *outZ);
void RomCurve_getAdjacentWindow(RomCurveDef *curve,int *outIds);
int RomCurve_getNearestAdjacentLink(RomCurveDef *curve,int excludeLinkId,f32 x,f32 y,f32 z);
f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,RomCurveSegmentProjection *segment);
int RomCurve_getRandomBlockedLink(RomCurveDef *curve,int excludeLinkId);
int RomCurve_getLinkIds(RomCurveDef *curve,int excludeLinkId,int *outIds);
int RomCurve_getRandomUnblockedLink(RomCurveDef *curve,int excludeLinkId);
RomCurveDef *RomCurve_getById(u32 curveId);
int RomCurve_find(int *types,int typeCount,f32 x,f32 y,f32 z,int action);
void curves_remove(RomCurveDef *curve);
void curves_addCurveDef(RomCurveDef *curve);
void curves_initialise(void);
void curves_release(void);
void curves_countRandomPoints(int obj,CurvesCollisionState *state);
void FUN_800e49c0(int param_1,u32 *param_2);
void fn_800E56A4(int obj,CurvesCollisionState *state);
void fn_800E58FC(int obj,CurvesCollisionState *state);
void fn_800E5CBC(short *param_1,int param_2);
void fn_800E5E38(int obj,CurvesCollisionState *state);
void fn_800E5F1C(int obj,CurvesCollisionState *state);
void FUN_800e4db4(int param_1,int param_2);
void FUN_800e4db8(int param_1,int param_2);
void curves_updateLocalPointCollision(int obj,CurvesCollisionState *state);
void curves_preparePointCollisionFrame(int obj,CurvesCollisionState *state);
void curves_updateLocalPointTransforms(int obj,CurvesCollisionState *state);
void dll_15_func0A(int obj,CurvesCollisionState *state);
f32 dll_15_func0B(int obj,f32 x,f32 baseY,f32 z,f32 height);
double FUN_800e56bc(u64 param_1,double param_2,double param_3,double param_4,int param_5);
RomCurvePoint *curves_getCurves(int obj,f32 x,f32 z,u32 *outCount,int queryAll);
void dll_15_func08(short *curveObj,CurvesCollisionState *state,u32 updateValue,f32 step);
void FUN_800e6140(u32 param_1,CurvesCollisionState *state);
void dll_15_func05(CurvesCollisionState *state,int count,f32 *segmentLocalPoints,f32 *radii,
                   s8 *types);
void dll_15_func06(GameObject *obj,CurvesCollisionState *state);
void FUN_800e65c8(CurvesCollisionState *state,u8 pointCount,f32 *localPointPositions,
                  f32 *localPointRadii,s8 primaryHitType,s8 secondaryHitType);
void curves_setLocalPointCollisionEx(CurvesCollisionState *state,int pointCount,
                                     f32 *localPointPositions,f32 *localPointRadii,
                                     int primaryHitType,int secondaryHitType);
void curves_clear(CurvesCollisionState *state,int updateMode,u32 flags,int subtype);
int pushable_savePos(int obj);
u32 playerHasKrazoaSpirit(u8 checkStoryBits,u32 bit);
void saveFileStruct_setCheatActive(u8 param_1,u8 param_2);


/* extern-cleanup: defining-file public prototypes */
void* getLastSavedGameTexts(void);

#endif /* MAIN_DLL_CURVES_H_ */
