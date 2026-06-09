#ifndef MAIN_DLL_CNTCOUNTER_STATE_H_
#define MAIN_DLL_CNTCOUNTER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CntCounterState {
    int remainingCount;
    u8 displayHud;
    u8 pad5[0x8 - 0x5];
} CntCounterState;

STATIC_ASSERT(offsetof(CntCounterState, displayHud) == 0x04);
STATIC_ASSERT(sizeof(CntCounterState) == 0x08);

#endif /* MAIN_DLL_CNTCOUNTER_STATE_H_ */
