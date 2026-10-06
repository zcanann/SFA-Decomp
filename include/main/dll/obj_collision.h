#ifndef MAIN_DLL_OBJ_COLLISION_H_
#define MAIN_DLL_OBJ_COLLISION_H_

#include "global.h"
#include "main/dll/obj_collision_state.h"

#define OBJ_COLLISION_MAX_HEIGHT_HITS 0x23
#define OBJ_COLLISION_SURFACE_WATER   0x0e

typedef struct ObjCollisionInterface {
    u32 reserved;
    void (*init)(ObjCollisionState* state, int mode, u32 flags, int subtype);
    void (*setLocalPoints)(ObjCollisionState* state, int count, f32* positions, f32* radii, int hitType);
    void (*setSegments)(ObjCollisionState* state, int count, f32* positions, f32* radii, const s8* types);
    void (*updateQueryBounds)(GameObject* obj, ObjCollisionState* state, f32 delta);
    void (*gatherTrackTriangles)(GameObject* obj, ObjCollisionState* state);
    void (*resolve)(GameObject* obj, ObjCollisionState* state, f32 delta);
    TrackGroundHit* (*queryHeightHits)(GameObject* obj, f32 x, f32 z, u32* count, int queryAll);
    void (*reset)(GameObject* obj, ObjCollisionState* state);
    f32 (*sampleHeight)(GameObject* obj, f32 x, f32 y, f32 z, f32 height);
} ObjCollisionInterface;

typedef struct ObjCollisionDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    ObjCollisionInterface interface;
} ObjCollisionDescriptor;

extern ObjCollisionInterface** gObjCollisionInterface;
extern ObjCollisionDescriptor gObjCollisionDescriptor;
extern TrackGroundHit sObjCollisionHeightHits[OBJ_COLLISION_MAX_HEIGHT_HITS];

void ObjCollision_ResolveFourPointFloor(GameObject* obj, ObjCollisionState* state);
void ObjCollision_ResolveSingleTrace(GameObject* obj, ObjCollisionState* state);
void ObjCollision_ResolveAveragedSegments(GameObject* obj, ObjCollisionState* state);
void ObjCollision_UpdateSurfaceTilt(GameObject* obj, ObjCollisionState* state);
void ObjCollision_SnapToNearestSurface(GameObject* obj, ObjCollisionState* state);
void ObjCollision_ResolveWaterFloorCeiling(GameObject* obj, ObjCollisionState* state);
void ObjCollision_UpdateLocalPointCollision(GameObject* obj, ObjCollisionState* state);
void ObjCollision_PreparePointCollisionFrame(struct GameObject* obj, ObjCollisionState* state);
void ObjCollision_UpdateLocalPointTransforms(struct GameObject* obj, ObjCollisionState* state);
void ObjCollision_Reset(GameObject* obj, ObjCollisionState* state);
f32 ObjCollision_SampleHeight(GameObject* obj, f32 x, f32 baseY, f32 z, f32 height);
TrackGroundHit* ObjCollision_QueryHeightHits(GameObject* obj, f32 x, f32 z, u32* outCount, int queryAll);
void ObjCollision_Resolve(GameObject* curveObj, ObjCollisionState* state, f32 step);
void ObjCollision_GatherTrackTriangles(GameObject* obj, ObjCollisionState* state);
void ObjCollision_UpdateQueryBounds(GameObject* obj, ObjCollisionState* state, f32 step);
void ObjCollision_SetSegments(ObjCollisionState* state, int count, f32* segmentLocalPoints, f32* radii,
                              const s8* types);
void ObjCollision_SetLocalPointsEx(ObjCollisionState* state, int pointCount, f32* localPointPositions,
                                   f32* localPointRadii, int primaryHitType, int secondaryHitType);
void ObjCollision_SetLocalPoints(ObjCollisionState* state, int pointCount, f32* localPointPositions,
                                 f32* localPointRadii, int primaryHitType);
void ObjCollision_Init(ObjCollisionState* state, int updateMode, u32 flags, int subtype);
void ObjCollision_Initialise(void);
void ObjCollision_Release(void);

STATIC_ASSERT(offsetof(ObjCollisionInterface, init) == 0x04);
STATIC_ASSERT(offsetof(ObjCollisionInterface, setLocalPoints) == 0x08);
STATIC_ASSERT(offsetof(ObjCollisionInterface, setSegments) == 0x0C);
STATIC_ASSERT(offsetof(ObjCollisionInterface, updateQueryBounds) == 0x10);
STATIC_ASSERT(offsetof(ObjCollisionInterface, gatherTrackTriangles) == 0x14);
STATIC_ASSERT(offsetof(ObjCollisionInterface, resolve) == 0x18);
STATIC_ASSERT(offsetof(ObjCollisionInterface, queryHeightHits) == 0x1C);
STATIC_ASSERT(offsetof(ObjCollisionInterface, reset) == 0x20);
STATIC_ASSERT(offsetof(ObjCollisionInterface, sampleHeight) == 0x24);
STATIC_ASSERT(sizeof(ObjCollisionInterface) == 0x28);
STATIC_ASSERT(offsetof(ObjCollisionDescriptor, interface) == 0x18);
STATIC_ASSERT(sizeof(ObjCollisionDescriptor) == 0x40);

#endif /* MAIN_DLL_OBJ_COLLISION_H_ */
