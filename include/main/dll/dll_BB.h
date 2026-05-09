#ifndef MAIN_DLL_DLL_BB_H_
#define MAIN_DLL_DLL_BB_H_

#include "ghidra_import.h"

void camcontrol_applyState(short *param_1);
void camcontrol_applyQueuedAction(void);
void fn_8010204C(int param_1);
void fn_80102068(int enable);
void fn_801020A0(int flags);
void fn_801020B8(int yOffset,int applyNow);

#endif /* MAIN_DLL_DLL_BB_H_ */
