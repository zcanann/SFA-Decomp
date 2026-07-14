#ifndef MAIN_DLL_SC_SCTOTEMLOGPUZ_H_
#define MAIN_DLL_SC_SCTOTEMLOGPUZ_H_

#include "ghidra_import.h"
#include "main/mapEventTypes.h"

typedef struct SCTotemLogPuzzleRuntime {
    u8 pad00[7];
    u8 eventCountdown;
} SCTotemLogPuzzleRuntime;

typedef struct SCTotemLogPuzzleObject {
    u8 pad00[0xAC];
    s8 animId;
    u8 padAD[0xB8 - 0xAD];
    SCTotemLogPuzzleRuntime *runtime;
} SCTotemLogPuzzleObject;

typedef struct SCTotemLogPuzzleUpdateState {
    u8 pad00[0x81];
    s8 eventHandled[10];
    u8 eventCount;
} SCTotemLogPuzzleUpdateState;

#endif /* MAIN_DLL_SC_SCTOTEMLOGPUZ_H_ */
