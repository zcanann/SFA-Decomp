#ifndef MAIN_DLL_DRAKORENERGYSTATE_STRUCT_H_
#define MAIN_DLL_DRAKORENERGYSTATE_STRUCT_H_

#include "types.h"

typedef struct DrakorEnergyState
{
    f32 startY; /* spawn height; bounce threshold in mode 1 */
    int phase; /* += framesThisStep * 0x500; drives glow color/bob */
    u8 mode; /* 0x08: 0 idle, 1 falling, 2 bobbing, 3 chasing, 4 collected, 5 reset */
    u8 unk09[3];
} DrakorEnergyState;

#endif
