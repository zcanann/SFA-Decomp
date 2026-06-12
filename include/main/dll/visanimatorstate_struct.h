#ifndef MAIN_DLL_VISANIMATORSTATE_STRUCT_H_
#define MAIN_DLL_VISANIMATORSTATE_STRUCT_H_

#include "types.h"

typedef struct VisAnimatorState
{
    u8 flags; /* 0x00: 1 = refresh pending */
    s8 visBit; /* 0x01 */
    u8 gateNow; /* 0x02 */
    u8 gatePrev; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;

#endif
