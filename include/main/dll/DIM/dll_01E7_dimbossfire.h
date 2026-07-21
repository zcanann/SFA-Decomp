#ifndef MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_
#define MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_

#include "main/game_object.h"
#include "main/model_light.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "types.h"

#define DIMBOSSFIRE_FLAME_COUNT 10

typedef struct DimbossfireState
{
    u8 flags;
    u8 durationIndex;
    u8 pad02[0x4 - 0x2];
    f32 activeTimer;
    f32 initialActiveTimer;
    f32 cooldownTimer;
    ModelLightStruct* light;
} DimbossfireState;

typedef struct DimbossfirePlacement
{
    ObjPlacement base;
    u8 pad18[0x1A - 0x18];
    s16 flameColor;
    u8 pad1C[0x20 - 0x1C];
    s16 triggerGameBit;
    u8 pad22[0x24 - 0x22];
} DimbossfirePlacement;

STATIC_ASSERT(sizeof(DimbossfireState) == 0x14);
STATIC_ASSERT(offsetof(DimbossfireState, activeTimer) == 0x4);
STATIC_ASSERT(offsetof(DimbossfireState, light) == 0x10);
STATIC_ASSERT(sizeof(DimbossfirePlacement) == 0x24);
STATIC_ASSERT(offsetof(DimbossfirePlacement, flameColor) == 0x1A);
STATIC_ASSERT(offsetof(DimbossfirePlacement, triggerGameBit) == 0x20);

extern f32 gDimbossfireActiveDurations[DIMBOSSFIRE_FLAME_COUNT];
extern ObjectDescriptor gDIMbossfireObjDescriptor;
extern f32 gDimbossfireZero;
extern f32 gDimbossfireShakeRadius;
extern f32 gDimbossfireFullIntensity;
extern f32 gDimbossfireShakeMagnitudeDuration;
extern f32 gDimbossfireShakeFalloff;
extern f32 gDimbossfireRumbleMagnitude;
extern f32 gDimbossfireLightNearDistance;
extern f32 gDimbossfireLightFarDistance;
extern f32 gDimbossfireLightFadeFrames;

int dimbossfire_getExtraSize(void);
int dimbossfire_getObjectTypeId(void);
void dimbossfire_free(GameObject* obj);
void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbossfire_hitDetect(void);
void dimbossfire_update(GameObject* obj);
void dimbossfire_init(GameObject* obj, u32 arg2, int placement);
void dimbossfire_release(void);
void dimbossfire_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01E7_DIMBOSSFIRE_H_ */
