#ifndef MAIN_DLL_DLL_023F_DBEGG_H_
#define MAIN_DLL_DLL_023F_DBEGG_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor12 gDB_eggObjDescriptor;

typedef struct AnimBehaviorConfig
{
    u8 pad00[0x08];
    f32 targetPosX;
    f32 targetPosY;
    f32 targetPosZ;
    u8 pad14[0x19 - 0x14];
    u8 forceRadiusByte;
    u8 speedScaleByte;
    u8 facingAngleByte;
    s16 primaryConditionId;
    s16 secondaryConditionId;
    u8 pad20[0x24 - 0x20];
    s16 readyConditionId;
    u8 behaviorMode;
    u8 pad27[0x2C - 0x27];
    s16 activationEventId;
} AnimBehaviorConfig;

STATIC_ASSERT(offsetof(AnimBehaviorConfig, forceRadiusByte) == 0x19);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, speedScaleByte) == 0x1A);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, facingAngleByte) == 0x1B);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, primaryConditionId) == 0x1C);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, secondaryConditionId) == 0x1E);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, readyConditionId) == 0x24);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, behaviorMode) == 0x26);
STATIC_ASSERT(offsetof(AnimBehaviorConfig, activationEventId) == 0x2C);

int dbegg_setLaunchVelocity(GameObject* obj, f32* velocity);
int dbegg_setScale(GameObject* obj);
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);
void dbegg_free(int obj);
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dbegg_hitDetect(GameObject* obj);
void dbegg_update(GameObject* obj);
void dbegg_init(GameObject* obj);
void dbegg_release(void);
void dbegg_initialise(void);

void dbegg_setupFromDef(GameObject* obj, u8* state);

#endif /* MAIN_DLL_DLL_023F_DBEGG_H_ */
