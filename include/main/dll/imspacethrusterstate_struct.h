#ifndef MAIN_DLL_IMSPACETHRUSTERSTATE_STRUCT_H_
#define MAIN_DLL_IMSPACETHRUSTERSTATE_STRUCT_H_

#include "types.h"

typedef struct ImSpaceThrusterState
{
    u8 kind; /* 0x00: thruster slot from def+0x19 */
    u8 phase; /* 0x01 */
    s16 blendTimer; /* 0x02 */
    void* bufA; /* 0x04: mmAlloc'd getTabEntry rows */
    void* bufB; /* 0x08 */
} ImSpaceThrusterState;

#endif
