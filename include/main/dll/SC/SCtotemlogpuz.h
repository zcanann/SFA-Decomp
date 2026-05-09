#ifndef MAIN_DLL_SC_SCTOTEMLOGPUZ_H_
#define MAIN_DLL_SC_SCTOTEMLOGPUZ_H_

#include "ghidra_import.h"

typedef struct SCGameBitLatchState {
  int activeMask;
} SCGameBitLatchState;

int fn_801D7C14(void *obj, void *unused, void *p3);
void fn_801D7C94(void *obj, void *p2);
void SCGameBitLatch_Update(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                           s16 clearIfClearBit, s16 latchBit, int musicId);
void SCGameBitLatch_UpdateInverted(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                   s16 clearIfClearBit, s16 latchBit, int musicId);

#endif /* MAIN_DLL_SC_SCTOTEMLOGPUZ_H_ */
