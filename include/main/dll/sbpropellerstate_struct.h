#ifndef MAIN_DLL_SBPROPELLERSTATE_STRUCT_H_
#define MAIN_DLL_SBPROPELLERSTATE_STRUCT_H_

#include "types.h"

typedef struct SBPropellerState
{
    f32 smokeTimer; /* 0x00: countdown to the next smoke burst */
    f32 spinBlend; /* 0x04 */
    int spinRate; /* 0x08: init 1200 */
    s8 health; /* 0x0c: init 4 */
    u8 pad0D[3];
} SBPropellerState;

#endif
