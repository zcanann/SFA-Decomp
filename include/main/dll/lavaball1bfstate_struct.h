#ifndef MAIN_DLL_LAVABALL1BFSTATE_STRUCT_H_
#define MAIN_DLL_LAVABALL1BFSTATE_STRUCT_H_

#include "types.h"

typedef struct Lavaball1bfState
{
    u8 pad00[8];
    int* spawnedObj; /* 0x08: the 0x18d cannon object */
    f32 fireTimer; /* 0x0c */
    f32 firePeriod; /* 0x10 */
    s16 gateA; /* 0x14 */
    s16 pending; /* 0x16 */
    u8 gateB; /* 0x18 */
    u8 pad19;
    u8 gbState; /* 0x1a */
    u8 soloLatch; /* 0x1b */
} Lavaball1bfState;

#endif
