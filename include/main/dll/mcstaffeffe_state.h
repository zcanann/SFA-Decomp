#ifndef MAIN_DLL_MCSTAFFEFFE_STATE_H_
#define MAIN_DLL_MCSTAFFEFFE_STATE_H_

#include "global.h"
#include "main/objanim_internal.h"

typedef struct McStaffEffectSetup {
    u8 pad00[0x1B];
    u8 effectProfile;
} McStaffEffectSetup;

typedef struct McStaffEffectObject {
    ObjAnimComponent anim;
    u8 padB0[0xF4 - 0xB0];
    s32 particleType;
    s32 staffGlowLevel;
} McStaffEffectObject;

STATIC_ASSERT(offsetof(McStaffEffectSetup, effectProfile) == 0x1B);
STATIC_ASSERT(offsetof(McStaffEffectObject, particleType) == 0xF4);
STATIC_ASSERT(offsetof(McStaffEffectObject, staffGlowLevel) == 0xF8);

#endif /* MAIN_DLL_MCSTAFFEFFE_STATE_H_ */
