#ifndef MAIN_DLL_TREX_TREX_LAZERWALL_H_
#define MAIN_DLL_TREX_TREX_LAZERWALL_H_

#include "ghidra_import.h"

int TREX_Lazerwall_popQueuedState(int obj, int param2);
int TREX_Lazerwall_waitForStartBit(void);
int TREX_Lazerwall_updateTimedChallenge(int obj);

#endif /* MAIN_DLL_TREX_TREX_LAZERWALL_H_ */
