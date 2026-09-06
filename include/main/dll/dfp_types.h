#ifndef MAIN_DLL_DFP_TYPES_H_
#define MAIN_DLL_DFP_TYPES_H_

#include "global.h"
#include "types.h"

typedef struct DfpLevelControlSfxState {
    u8 triggerD5d : 1;
    u8 triggerD59 : 1;
    u8 triggerD5a : 1;
    u8 unused : 5;
} DfpLevelControlSfxState;

typedef struct DfpLevelControlState {
    s16 zappedTimer; /* counts down by timeDelta; set to 300 when the player is zapped */
    s16 mode;        /* 1..2, from def+0x1A */
    u16 unused04;
    u8 previousPuzzlePadState; /* GAMEBIT_OFP_PuzzlePadPressed as of the previous frame */
    DfpLevelControlSfxState previousSfxState;
    s32 musicLatchMask; /* persistent latch state for the three GameBitLatch_Update calls in update */
} DfpLevelControlState;

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

#endif
