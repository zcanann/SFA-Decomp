#ifndef MAIN_DLL_CURVES_H_
#define MAIN_DLL_CURVES_H_

#include "game/objects/object.h"
#include "main/track_dolphin_api.h"
#include "global.h"
#include "types.h"
#include "main/dll/curve_walker.h"
#include "main/dll/curves_collision_state.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/dll/rom_curve_def.h"
#include "main/dll/savegame_object_api.h"
#include "main/dll/player_spirit_api.h"

typedef struct GameObject GameObject;

#define ROMCURVE_MAX_CURVES                 0x514
#define ROMCURVE_POINT_SIZE                 0x18
#define ROMCURVE_LINK_ID_STRIDE             sizeof(u32)
#define ROMCURVE_LINK_ID_NONE               0xffffffff
#define ROMCURVE_LINK_SEARCH_RESULT_COUNT   ROMCURVE_LINK_COUNT
#define ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY 0x28
#define ROMCURVE_TYPE_ACTION                0x15
#define ROMCURVE_TYPE_SPECIAL_ANGLE_8       0x08
#define ROMCURVE_TYPE_SPECIAL_ANGLE_1A      0x1a
#define ROMCURVE_TYPE_SCALE_OVERRIDE_15     0x15
#define ROMCURVE_TYPE_SCALE_OVERRIDE_16     0x16
/* RomCurve objdef Type field (offset 0x19): selects which curve network an
 * object's "find nearby curve" query targets. Only literal type checks
 * confirmed in live code are named; see docs/wiki/Curves.md for the full list. */
#define ROMCURVE_TYPE_HAGABON_MK2                     0x03 /* firecrawler.c hagabonMK2 (DLL 0xC9) */
#define ROMCURVE_TYPE_DIM2_PATHGEN                    0x15 /* == ROMCURVE_TYPE_ACTION; curves_findByAction */
#define ROMCURVE_TYPE_16                              0x16 /* curves_findNearestOfType16 */
#define ROMCURVE_TYPE_17                              0x17 /* curves_findEnclosingLoopOfType17 */
#define ROMCURVE_TYPE_CURVEFISH                       0x23 /* CurveFish path query */
#define ROMCURVE_TYPE_TRICKY                          0x24 /* Objfsa_FindNearest(Enabled)CurveType24 */
#define ROMCURVE_GETCURVES_MAX_POINTS                 0x23
#define ROMCURVE_POINT_TYPE_WATER                     0x0e

typedef struct TrackGroundHit TrackGroundHit;

extern RomCurveDef* romCurves[ROMCURVE_MAX_CURVES];
extern int nRomCurves;
extern RomCurveDef* gRomCurveLastFindStart;
extern RomCurveDef* gRomCurveLastFindEnd;
extern TrackGroundHit sCurvesHitPoints[ROMCURVE_GETCURVES_MAX_POINTS];
extern char sCurvesMaxRomCurvesExceeded[];

#include "main/dll/rom_curve_segment_projection.h"

STATIC_ASSERT(sizeof(RomCurveSegmentProjection) == 0x24);
STATIC_ASSERT(offsetof(RomCurveSegmentProjection, endX) == 0x0C);
STATIC_ASSERT(offsetof(RomCurveSegmentProjection, nearestX) == 0x18);

int RomCurve_projectPointToAdjacentWindow(int* curveIds, f32 x, f32 y, f32 z, f32* outLateralOffset,
                                          f32* outVerticalOffset, f32* outPhase);
int curves_isPointInsideLoop(int curveId, f32 x, f32 y, f32 z, f32* outDistance);
int curves_findNearestOfType16(f32 x, f32 y, f32 z, int queryAll);
int RomCurve_func13(u32 curveId, int typeFilter, int matchValue, int* outLink);
int RomCurve_findLinkTowardNearestOfType(RomCurveDef* curve, int typeFilter, int actionFilter, int* previousCurveId);
int RomCurve_getRandomLinkedOfTypes(RomCurveDef* curve, int* types, int typeCount, int* previousLinkId);
int curves_findByAction(int action);
f32 curves_distXZ(f32 x, f32 z, u32 curveId);
f32 curves_distToObj(GameObject* obj, u32 curveId);
f32 curves_find(int type, int action, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);
RomCurveDef* RomCurve_findByIdWithIndex(u32 curveId, int* outIndex);
int RomCurve_buildRandomPoints(RomCurveDef* curve, f32* outX, f32* outY, f32* outZ, s8* outTypes);
int RomCurve_countRandomPoints(RomCurveDef* curve);
int RomCurve_buildAdjacentWindowPoints(u32* curveIds, float* outX, float* outY, float* outZ);
void RomCurve_getAdjacentWindow(RomCurveDef* curve, int* outIds);
int RomCurve_getFarthestAdjacentLink(RomCurveDef* curve, int excludeLinkId, f32 x, f32 y, f32 z);
f32 RomCurve_distanceToSegment(f32 x, f32 y, f32 z, RomCurveSegmentProjection* segment);
int RomCurve_getRandomBlockedLink(RomCurveDef* curve, int excludeLinkId);
int RomCurve_getLinkIds(RomCurveDef* curve, int excludeLinkId, int* outIds);
int RomCurve_getRandomUnblockedLink(RomCurveDef* curve, int excludeLinkId);
RomCurveDef* RomCurve_getById(u32 curveId);
int RomCurve_find(f32 x, f32 y, f32 z, int* types, int typeCount, int action);
void RomCurve_remove(RomCurveDef* curve);
void RomCurve_add(RomCurveDef* curve);
void curves_initialise(void);
void RomCurve_release(void);
void curves_countRandomPoints(GameObject* obj, CurvesCollisionState* state);
void curves_resolveSingleTrace(GameObject* obj, CurvesCollisionState* state);
void curves_resolveAveragedSegments(GameObject* obj, CurvesCollisionState* state);
void curves_updateSurfaceTilt(short* obj, int state);
void curves_snapToNearestSurface(GameObject* obj, CurvesCollisionState* state);
void curves_resolveWaterFloorCeiling(GameObject* obj, CurvesCollisionState* state);
void curves_updateLocalPointCollision(GameObject* obj, CurvesCollisionState* state);
void curves_preparePointCollisionFrame(struct GameObject* obj, CurvesCollisionState* state);
void curves_updateLocalPointTransforms(struct GameObject* obj, CurvesCollisionState* state);
void curves_reset(GameObject* obj, CurvesCollisionState* state);
f32 curves_sampleHeight(GameObject* obj, f32 x, f32 baseY, f32 z, f32 height);
TrackGroundHit* curves_getCurves(GameObject* obj, f32 x, f32 z, u32* outCount, int queryAll);
void curves_advanceCollision(GameObject* curveObj, CurvesCollisionState* state, f32 step);
void curves_setSegmentCollision(CurvesCollisionState* state, int count, f32* segmentLocalPoints, f32* radii, s8* types);
void curves_updateQueryBounds(GameObject* obj, CurvesCollisionState* state, f32 step);
void curves_setLocalPointCollisionEx(CurvesCollisionState* state, int pointCount, f32* localPointPositions,
                                     f32* localPointRadii, int primaryHitType, int secondaryHitType);
void curves_clear(CurvesCollisionState* state, int updateMode, u32 flags, int subtype);
void saveFileStruct_setCheatActive(u8 optionIndex, u8 active);

/* extern-cleanup: defining-file public prototypes */
void* getLastSavedGameTexts(void);

void curves_gatherTrackTriangles(GameObject* obj, CurvesCollisionState* state);
void curves_setLocalPointCollision(CurvesCollisionState* state, int pointCount, f32* localPointPositions,
                                   f32* localPointRadii, int primaryHitType);
void dll_15_initialise_nop(void);
void dll_15_release_nop(void);

#endif /* MAIN_DLL_CURVES_H_ */
