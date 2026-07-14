#ifndef MAIN_WORLDOBJ_H_
#define MAIN_WORLDOBJ_H_

#include "global.h"
#include "main/modellight_api.h"

typedef struct WorldObjEffectParams {
    u8 pad00[6];
    s16 dispatchTimer;
    f32 effectScale;
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
} WorldObjEffectParams;

typedef struct WorldObjSetup {
    s16 objectId;
    u8 pad02[0x1B - 2];
    u8 variant;
} WorldObjSetup;

typedef struct WorldObjState {
    ModelLightStruct* light;
    u8 pathPointWork[0x25C - 4];
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
    u8 pad281[3];
} WorldObjState;

#define WORLDOBJ_PATH_POINT_STRIDE 0x18
#define WORLDOBJ_PATH_POINT_POS_OFFSET 0x10

STATIC_ASSERT(sizeof(WorldObjEffectParams) == 0x18);
STATIC_ASSERT(offsetof(WorldObjEffectParams, dispatchTimer) == 0x06);
STATIC_ASSERT(offsetof(WorldObjEffectParams, effectScale) == 0x08);
STATIC_ASSERT(offsetof(WorldObjEffectParams, offsetX) == 0x0C);

STATIC_ASSERT(sizeof(WorldObjSetup) == 0x1C);
STATIC_ASSERT(offsetof(WorldObjSetup, objectId) == 0x00);
STATIC_ASSERT(offsetof(WorldObjSetup, variant) == 0x1B);

STATIC_ASSERT(sizeof(WorldObjState) == 0x284);
STATIC_ASSERT(offsetof(WorldObjState, light) == 0x00);
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

static inline char *WorldObj_GetPathPointWork(WorldObjState *state, int index)
{
    return (char *)state + index * WORLDOBJ_PATH_POINT_STRIDE;
}

#endif /* MAIN_WORLDOBJ_H_ */
