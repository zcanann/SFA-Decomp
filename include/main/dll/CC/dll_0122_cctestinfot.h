#ifndef MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_
#define MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct CCTestInfotSetup
{
    ObjPlacement base;
    u8 rotationZ;
    u8 rotationY;
    u8 rotationX;
} CCTestInfotSetup;

typedef struct CCTestInfotState
{
    f32 holdTimer; /* 0x00: counts down while help text is shown */
    u8 isDisguised; /* 0x04: cached playerIsDisguised() result, hint-text index */
    u8 pad05[3];
} CCTestInfotState;

STATIC_ASSERT(offsetof(CCTestInfotSetup, rotationZ) == 0x18);
STATIC_ASSERT(offsetof(CCTestInfotSetup, rotationY) == 0x19);
STATIC_ASSERT(offsetof(CCTestInfotSetup, rotationX) == 0x1a);
STATIC_ASSERT(offsetof(CCTestInfotState, isDisguised) == 0x4);
STATIC_ASSERT(sizeof(CCTestInfotState) == 0x8);

int CCTestInfot_getExtraSize(void);
void CCTestInfot_update(GameObject* obj);
void CCTestInfot_init(GameObject* obj, CCTestInfotSetup* setup);

#endif /* MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_ */
