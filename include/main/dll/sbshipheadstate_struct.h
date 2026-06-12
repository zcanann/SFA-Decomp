#ifndef MAIN_DLL_SBSHIPHEADSTATE_STRUCT_H_
#define MAIN_DLL_SBSHIPHEADSTATE_STRUCT_H_

#include "types.h"

typedef struct SBShipHeadState
{
    int target; /* 0x00: the 0x8c galleon-side object */
    s8 health; /* 0x04: init 4 */
    u8 pad05[3];
    f32 swayA; /* 0x08 */
    f32 swayB; /* 0x0c */
} SBShipHeadState;

#endif
