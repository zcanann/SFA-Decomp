#ifndef DLLS_OBJECTS_467_H_
#define DLLS_OBJECTS_467_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/modellight_api.h"
#include "main/vec_types.h"

/*
 * Every active-target retail placement owned by DLL 0x1D3 is a fixed
 * eight-word (0x20-byte) record.
 */
typedef struct WorldObjSetup {
    ObjPlacement base;
    u8 unknown18[3];
    u8 variant;
    u8 unknown1C[4];
} WorldObjSetup;

/*
 * The path callbacks interpret overlapping work views from the start of the
 * state at a 0x18-byte stride. The first view's opaque prefix therefore
 * includes the light slot; this is not an array-element type.
 */
typedef struct WorldObjPathSegmentWork {
    u8 unknown00[0x10];
    Vec start;
    u8 unknown1C[0x0C];
    Vec end;
} WorldObjPathSegmentWork;

/* worldobj_getExtraSize() allocates 0x284 bytes. */
typedef struct WorldObjState {
    ModelLightStruct* light;
    u8 pathPointWork[0x25C - 0x04];
    f32 orbitRadiusZ;
    f32 orbitRadiusX;
    f32 orbitStartY;
    f32 orbitEndY;
    f32 scale;
    s32 orbitAngle;
    s32 lookAtTargetRef;
    s32 attachChildObjectId;
    u8 controlByte;
    u8 effectState;
    s8 spinZStep;
    s8 spinYStep;
    s8 spinXStep;
    u8 unknown281[3];
} WorldObjState;

#define WORLDOBJ_PATH_POINT_STRIDE 0x18

STATIC_ASSERT(offsetof(WorldObjSetup, base) == 0x00);
STATIC_ASSERT(offsetof(WorldObjSetup, unknown18) == 0x18);
STATIC_ASSERT(offsetof(WorldObjSetup, variant) == 0x1B);
STATIC_ASSERT(offsetof(WorldObjSetup, unknown1C) == 0x1C);
STATIC_ASSERT(sizeof(WorldObjSetup) == 0x20);

STATIC_ASSERT(offsetof(WorldObjPathSegmentWork, start) == 0x10);
STATIC_ASSERT(offsetof(WorldObjPathSegmentWork, end) == 0x28);
STATIC_ASSERT(sizeof(WorldObjPathSegmentWork) == 0x34);

STATIC_ASSERT(offsetof(WorldObjState, light) == 0x000);
STATIC_ASSERT(offsetof(WorldObjState, pathPointWork) == 0x004);
STATIC_ASSERT(offsetof(WorldObjState, orbitRadiusZ) == 0x25C);
STATIC_ASSERT(offsetof(WorldObjState, orbitRadiusX) == 0x260);
STATIC_ASSERT(offsetof(WorldObjState, orbitStartY) == 0x264);
STATIC_ASSERT(offsetof(WorldObjState, orbitEndY) == 0x268);
STATIC_ASSERT(offsetof(WorldObjState, scale) == 0x26C);
STATIC_ASSERT(offsetof(WorldObjState, orbitAngle) == 0x270);
STATIC_ASSERT(offsetof(WorldObjState, lookAtTargetRef) == 0x274);
STATIC_ASSERT(offsetof(WorldObjState, attachChildObjectId) == 0x278);
STATIC_ASSERT(offsetof(WorldObjState, controlByte) == 0x27C);
STATIC_ASSERT(offsetof(WorldObjState, effectState) == 0x27D);
STATIC_ASSERT(offsetof(WorldObjState, spinZStep) == 0x27E);
STATIC_ASSERT(offsetof(WorldObjState, spinYStep) == 0x27F);
STATIC_ASSERT(offsetof(WorldObjState, spinXStep) == 0x280);
STATIC_ASSERT(offsetof(WorldObjState, unknown281) == 0x281);
STATIC_ASSERT(sizeof(WorldObjState) == 0x284);

static inline WorldObjPathSegmentWork* WorldObj_GetPathSegmentWork(WorldObjState* state, int index) {
    return (WorldObjPathSegmentWork*)((u8*)state + index * WORLDOBJ_PATH_POINT_STRIDE);
}

void worldobj_spawnGreatFoxEffects(GameObject* obj);
void worldobj_spawnAsteroidBatch(GameObject* obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId);
int worldobj_getExtraSize(void);
int worldobj_getObjectTypeId(GameObject* obj);
void worldobj_free(GameObject* obj);
void worldobj_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void worldobj_hitDetect(void);
void worldobj_update(GameObject* obj);
void worldobj_init(GameObject* obj, const WorldObjSetup* setup);
void worldobj_release(void);
void worldobj_initialise(void);

extern ObjectDescriptor gWorldObjObjDescriptor;

#endif /* DLLS_OBJECTS_467_H_ */
