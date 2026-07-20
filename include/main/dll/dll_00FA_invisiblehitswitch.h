#ifndef MAIN_DLL_DLL_00FA_INVISIBLEHITSWITCH_H_
#define MAIN_DLL_DLL_00FA_INVISIBLEHITSWITCH_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct InvisibleHitSwitchPlacement
{
    ObjPlacement head;
    s16 gameBitId;
    s16 cooldownFrames;
    u8 unk1C;
    u8 radiusScale;
    u8 triggerMode;
    u8 unk1F;
    u8 pad20[3];
    u8 hitType;
} InvisibleHitSwitchPlacement;

typedef struct InvisibleHitSwitchState
{
    u8 active;
    u8 hitId;
    u8 pad2[2];
    f32 cooldownTimer;
    f32 activationTimer;
} InvisibleHitSwitchState;

STATIC_ASSERT(offsetof(InvisibleHitSwitchPlacement, gameBitId) == 0x18);
STATIC_ASSERT(offsetof(InvisibleHitSwitchPlacement, radiusScale) == 0x1D);
STATIC_ASSERT(offsetof(InvisibleHitSwitchPlacement, triggerMode) == 0x1E);
STATIC_ASSERT(offsetof(InvisibleHitSwitchPlacement, hitType) == 0x23);
STATIC_ASSERT(sizeof(InvisibleHitSwitchPlacement) == 0x24);
STATIC_ASSERT(offsetof(InvisibleHitSwitchState, cooldownTimer) == 0x4);
STATIC_ASSERT(offsetof(InvisibleHitSwitchState, activationTimer) == 0x8);
STATIC_ASSERT(sizeof(InvisibleHitSwitchState) == 0xC);

int InvisibleHitSwitch_getExtraSize(void);
void InvisibleHitSwitch_update(GameObject* obj);
void InvisibleHitSwitch_init(GameObject* obj, InvisibleHitSwitchPlacement* placement);

extern ObjectDescriptor gInvisibleHitSwitchObjDescriptor;

#endif /* MAIN_DLL_DLL_00FA_INVISIBLEHITSWITCH_H_ */
