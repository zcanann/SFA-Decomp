#ifndef MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_
#define MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_

#include "types.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct FlamethrowerSpePlacement
{
    ObjPlacement base;
    u8 unk18;
    u8 hitVolumeProfile; /* 0x19: selects a row from the hit-volume table */
    s16 scaleParam;      /* 0x1A: fixed-point effect scale */
} FlamethrowerSpePlacement;

typedef struct FlamethrowerSpeState
{
    u8 pad0[0x4];
    f32 lifeTimer;
    f32 sizeScale;
    f32 sphereRadius;
    s32 phase;
} FlamethrowerSpeState;

STATIC_ASSERT(sizeof(FlamethrowerSpePlacement) == 0x1C);
STATIC_ASSERT(offsetof(FlamethrowerSpePlacement, base) == 0x0);
STATIC_ASSERT(offsetof(FlamethrowerSpePlacement, hitVolumeProfile) == 0x19);
STATIC_ASSERT(offsetof(FlamethrowerSpePlacement, scaleParam) == 0x1A);
STATIC_ASSERT(sizeof(FlamethrowerSpeState) == 0x14);
STATIC_ASSERT(offsetof(FlamethrowerSpeState, lifeTimer) == 0x4);
STATIC_ASSERT(offsetof(FlamethrowerSpeState, sizeScale) == 0x8);
STATIC_ASSERT(offsetof(FlamethrowerSpeState, sphereRadius) == 0xC);
STATIC_ASSERT(offsetof(FlamethrowerSpeState, phase) == 0x10);

extern ObjectDescriptor13 gFlameThrowerSpeObjDescriptor;

void flamethrowerspe_free(void);
void flamethrowerspe_func0B(GameObject* obj);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
void flamethrowerspe_hitDetect(void);
void flamethrowerspe_init(GameObject* obj, FlamethrowerSpePlacement* placement);
void flamethrowerspe_initialise(void);
void flamethrowerspe_modelMtxFn(void);
void flamethrowerspe_release(void);
void flamethrowerspe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void flamethrowerspe_setScale(GameObject* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);
void flamethrowerspe_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00E4_FLAMETHROWERSPE_API_H_ */
