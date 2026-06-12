#ifndef MAIN_DLL_SBFIREBALLSTATE_STRUCT_H_
#define MAIN_DLL_SBFIREBALLSTATE_STRUCT_H_

#include "types.h"

typedef struct SBFireBallState
{
    void* owner; /* taken from obj+0xF8 */
    s16 age; /* frames; gates the hitbox enable */
    u8 pad06[2];
    f32 velX;
    f32 velY;
    f32 velZ;
    u8 launched;
    u8 pad15[3];
} SBFireBallState;

#endif
