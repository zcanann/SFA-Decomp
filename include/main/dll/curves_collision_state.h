#ifndef MAIN_DLL_CURVES_COLLISION_STATE_H_
#define MAIN_DLL_CURVES_COLLISION_STATE_H_

#include "types.h"
#include "global.h"
#include "game/objects/object.h"
#include "main/track_line_intersect_result.h"
#include "main/track_hit_results.h"

#define CURVES_COLLISION_STATE_SIZE                   0x268
#define CURVES_COLLISION_STATE_ACTIVE                 0x04000000
#define CURVES_COLLISION_STATE_LOCAL_POINTS           0x00000008
#define CURVES_COLLISION_STATE_HIT_SEGMENTS           0x00002000
#define CURVES_COLLISION_STATE_SECONDARY_LOCAL_POINTS 0x02000000
#define CURVES_COLLISION_STATE_X_ROTATION_ONLY        0x00000020
#define CURVES_COLLISION_STATE_KEEP_POSITION          0x00100000
#define CURVES_POINT_COUNT_LOCAL_MASK                 0x0f
#define CURVES_POINT_COUNT_SEGMENT_MASK               0xf0
#define CURVES_POINT_COUNT_SEGMENT_SHIFT              4
#define CURVES_COLLISION_SUBTYPE_NONE                 0
#define CURVES_COLLISION_SUBTYPE_OBJECT               1
#define CURVES_COLLISION_SUBTYPE_POINT                2

typedef struct CurvesCollisionState {
    u32 flags;
    f32* segmentLocalPoints;
    f32 points[4][3];            /* 0x008 world-space segment points; double as trace ends */
    f32 traceStart[4][3];        /* 0x038 per-point raised trace starts */
    TrackHitResults segmentHits; /* 0x068 trackGetIntersect result for the segment sweep */
    GameObject* contactObj;      /* 0x0D8 latest trace hit forwarded to ObjHits_AddContactObject */
    f32* localPointPositions;
    f32* localPointRadii;
    f32 localPointWorld[4][3];  /* 0x0E4 localPointPositions transformed to world */
    f32 localPointTarget[4][3]; /* 0x114 raised copies; bbox-swept against localPointWorld */
    TrackLineIntersectResult localHit;      /* 0x144 trackGetLineIntersect result for the local points */
    s16 tiltPitch;       /* 0x198 smoothed toward tiltPitchTarget */
    s16 tiltRoll;        /* 0x19A */
    s16 tiltPitchTarget; /* 0x19C from surface normal */
    s16 tiltRollTarget;  /* 0x19E */
    f32 surfaceNormalX;  /* 0x1A0 */
    f32 surfaceNormalY;
    f32 surfaceNormalZ;
    f32 resultFloorGap;         /* 0x1AC latest-point copies of the arrays below */
    f32 resultCeilingY;         /* 0x1B0 */
    f32 resultWaterDepth;       /* 0x1B4 */
    f32 resultFloorY;           /* 0x1B8 */
    f32 resultWaterY;           /* 0x1BC */
    f32 floorGap[4];            /* 0x1C0 posY - floorY per point */
    f32 ceilingY[4];            /* 0x1D0 */
    f32 waterDepth[4];          /* 0x1E0 waterY - posY */
    f32 floorY[4];              /* 0x1F0 */
    f32 waterY[4];              /* 0x200 type-0xE surface height */
    f32 waterNormalX[4];        /* 0x210 */
    f32 waterNormalY[4];        /* 0x220 init 1.0 */
    f32 waterNormalZ[4];        /* 0x230 */
    TrackQueryBounds hitBounds; /* 0x240 swept-sphere bounds */
    u8 heightPadding;
    u8 pad259[2];
    s8 subtype;
    u8 pointCounts;
    s8 primaryHitType;
    u8 localPointHitMask;
    u8 surfaceHitMask;
    u8 surfaceFlags;
    s8 surfaceCounter;
    u8 updateMode;
    s8 secondaryHitType;
    u8 activeTimer;
    u8 pad265[CURVES_COLLISION_STATE_SIZE - 0x265];
} CurvesCollisionState;

STATIC_ASSERT(sizeof(CurvesCollisionState) == CURVES_COLLISION_STATE_SIZE);
STATIC_ASSERT(offsetof(CurvesCollisionState, flags) == 0x00);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentLocalPoints) == 0x04);
STATIC_ASSERT(offsetof(CurvesCollisionState, points) == 0x008);
STATIC_ASSERT(offsetof(CurvesCollisionState, traceStart) == 0x038);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits) == 0x068);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits.radii) == 0x0A8);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits.surfaceTypes) == 0x0B8);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits.queryTypes) == 0x0BC);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits.objects) == 0x0C4);
STATIC_ASSERT(offsetof(CurvesCollisionState, segmentHits.hitCount) == 0x0D4);
STATIC_ASSERT(offsetof(CurvesCollisionState, contactObj) == 0x0D8);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointPositions) == 0x0DC);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointRadii) == 0x0E0);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointWorld) == 0x0E4);
STATIC_ASSERT(offsetof(CurvesCollisionState, localPointTarget) == 0x114);
STATIC_ASSERT(offsetof(CurvesCollisionState, localHit) == 0x144);
STATIC_ASSERT(offsetof(CurvesCollisionState, tiltPitch) == 0x198);
STATIC_ASSERT(offsetof(CurvesCollisionState, surfaceNormalX) == 0x1A0);
STATIC_ASSERT(offsetof(CurvesCollisionState, resultFloorGap) == 0x1AC);
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

#endif /* MAIN_DLL_CURVES_COLLISION_STATE_H_ */
