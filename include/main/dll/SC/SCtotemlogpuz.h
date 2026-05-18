#ifndef MAIN_DLL_SC_SCTOTEMLOGPUZ_H_
#define MAIN_DLL_SC_SCTOTEMLOGPUZ_H_

#include "ghidra_import.h"

typedef struct SCGameBitLatchState {
  int activeMask;
} SCGameBitLatchState;

typedef struct SCTotemLogPuzzleEventInterface {
    u8 pad00[0x50];
    void (*setAnimEvent)(int animId, int eventId, int value);
} SCTotemLogPuzzleEventInterface;

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
    u8 eventHandled[10];
    u8 eventCount;
} SCTotemLogPuzzleUpdateState;

int SH_LevelControl_SeqFn(void *obj, void *unused, void *p3);
void mapUnloadFn_801d7c94(void *obj, void *p2);
void SCGameBitLatch_Update(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                           s16 clearIfClearBit, s16 latchBit, int musicId);
void SCGameBitLatch_UpdateInverted(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                   s16 clearIfClearBit, s16 latchBit, int musicId);

#endif /* MAIN_DLL_SC_SCTOTEMLOGPUZ_H_ */
