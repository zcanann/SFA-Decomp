#ifndef MAIN_DLL_VISANIMATORSTATE_STRUCT_H_
#define MAIN_DLL_VISANIMATORSTATE_STRUCT_H_

#include "types.h"

typedef struct VisAnimatorState
{
    u8 flags; /* 0x00: 1 = refresh pending */
    s8 visibilityBit; /* 0x01: map-block visibility state toggled by the gate */
    u8 currentGateState; /* 0x02 */
    u8 previousGateState; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;

STATIC_ASSERT(offsetof(VisAnimatorState, visibilityBit) == 0x1);
STATIC_ASSERT(offsetof(VisAnimatorState, currentGateState) == 0x2);
STATIC_ASSERT(offsetof(VisAnimatorState, previousGateState) == 0x3);
STATIC_ASSERT(offsetof(VisAnimatorState, gateMask) == 0x4);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

#endif
