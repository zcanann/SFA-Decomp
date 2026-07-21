#ifndef MAIN_DLL_DLL_00F9_PROJECTILESWITCH_H_
#define MAIN_DLL_DLL_00F9_PROJECTILESWITCH_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct ProjectileSwitchPlacement
{
    ObjPlacement base;
    s16 gameBitId;
    s16 autoResetDelayTenths;
    u8 rotYByte;
    u8 scale64;
    u8 modelIndexAndMode;
    u8 rotXByte;
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 renderFlags;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchPlacement;

typedef struct ProjectileSwitchState
{
    u8 isOn;
    u8 pad1;
    s16 gameBitId;
    f32 autoResetTimerFrames;
} ProjectileSwitchState;

enum
{
    PROJECTILE_SWITCH_MODE_MASK = 3,
    PROJECTILE_SWITCH_MODE_TOGGLE = 1,
    PROJECTILE_SWITCH_MODE_TIMED_RESET = 2,
    PROJECTILE_SWITCH_PLACEMENT_CUSTOM_COLOR = 1
};

STATIC_ASSERT(sizeof(ProjectileSwitchPlacement) == 0x28);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, gameBitId) == 0x18);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, autoResetDelayTenths) == 0x1A);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, modelIndexAndMode) == 0x1E);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, renderFlags) == 0x23);
STATIC_ASSERT(sizeof(ProjectileSwitchState) == 0x8);
STATIC_ASSERT(offsetof(ProjectileSwitchState, gameBitId) == 0x2);
STATIC_ASSERT(offsetof(ProjectileSwitchState, autoResetTimerFrames) == 0x4);

int ProjectileSwitch_getExtraSize(void);
int ProjectileSwitch_getObjectTypeId(GameObject* obj);
void ProjectileSwitch_free(void);
void ProjectileSwitch_render(GameObject* obj, int p2, int p3, int p4, int p5, char flag);
void ProjectileSwitch_hitDetect(GameObject* obj);
void ProjectileSwitch_update(GameObject* obj);
void ProjectileSwitch_init(GameObject* obj, ProjectileSwitchPlacement* placement);
void ProjectileSwitch_release(void);
void ProjectileSwitch_initialise(void);

extern u32 gProjectileSwitchParentGameBitMap[4];
extern ObjectDescriptor gProjectileSwitchObjDescriptor;

#endif /* MAIN_DLL_DLL_00F9_PROJECTILESWITCH_H_ */
