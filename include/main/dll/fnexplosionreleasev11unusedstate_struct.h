#ifndef MAIN_DLL_FNEXPLOSIONRELEASEV11UNUSEDSTATE_STRUCT_H_
#define MAIN_DLL_FNEXPLOSIONRELEASEV11UNUSEDSTATE_STRUCT_H_

#include "types.h"

typedef struct FnExplosionReleaseV11UnusedState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 velZ; /* added to localPosZ each frame, then decayed and clamped to a min */
    u8 padC[0x10 - 0xC];
} FnExplosionReleaseV11UnusedState;

#endif
