#ifndef MAIN_DLL_ARW_DLL_02A2_ARWSPEEDSTR_H
#define MAIN_DLL_ARW_DLL_02A2_ARWSPEEDSTR_H

#include "global.h"
#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/vec_types.h"

#define ARWSPEEDSTR_FLAG_POSITION_INITIALIZED 0x1

typedef struct ARWSpeedStrState
{
    f32 speed;
    f32 lifeTimer;
    f32 alpha;
    f32 spreadX;
    f32 spreadY;
    f32 viewZ;
    u8 flags;
    u8 reserved19[3];
} ARWSpeedStrState;

STATIC_ASSERT(sizeof(ARWSpeedStrState) == 0x1c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, speed) == 0x00);
STATIC_ASSERT(offsetof(ARWSpeedStrState, lifeTimer) == 0x04);
STATIC_ASSERT(offsetof(ARWSpeedStrState, alpha) == 0x08);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadX) == 0x0c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadY) == 0x10);
STATIC_ASSERT(offsetof(ARWSpeedStrState, viewZ) == 0x14);
STATIC_ASSERT(offsetof(ARWSpeedStrState, flags) == 0x18);


int ARWSpeedStr_getExtraSize(void);
int ARWSpeedStr_getObjectTypeId(void);
void ARWSpeedStr_free(void);
void ARWSpeedStr_hitDetect(void);
void ARWSpeedStr_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ARWSpeedStr_init(GameObject* obj, ObjPlacement* placement);
void ARWSpeedStr_update(GameObject* obj);
void ARWSpeedStr_release(void);
void ARWSpeedStr_initialise(void);

void dll_2A3_setSpeed(GameObject* obj, int speed);
void dll_2A3_setVelocity(GameObject* obj, Vec3f* velocity);

extern ObjectDescriptor gARWSpeedStrObjDescriptor;

#endif
