#ifndef MAIN_DLL_LINKLEVCONTROLSTATE_STRUCT_H_
#define MAIN_DLL_LINKLEVCONTROLSTATE_STRUCT_H_

#include "types.h"

typedef struct LinkLevControlState
{
    s8 areaCell; /* 0x00 */
    u8 pad01[3];
    int unk04; /* 0x04: init -1 */
    int musicTrack; /* 0x08 */
    int latch; /* 0x0c: SCGameBitLatch block */
} LinkLevControlState;

#endif
