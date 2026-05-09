#ifndef MAIN_DLL_SC_SCTOTEMBONDPUZ_H_
#define MAIN_DLL_SC_SCTOTEMBONDPUZ_H_

#include "main/dll/SC/SCtotemlogpuz.h"

void SCGameBitLatch_UpdateInverted(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                   s16 clearIfClearBit, s16 latchBit, int musicId);

#endif /* MAIN_DLL_SC_SCTOTEMBONDPUZ_H_ */
