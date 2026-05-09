#ifndef MAIN_DLL_DLL_BB_H_
#define MAIN_DLL_DLL_BB_H_

#include "ghidra_import.h"

void camcontrol_applyState(short *param_1);
void camcontrol_applyQueuedAction(void);
void Camera_func1D(int param_1);
void Camera_func13(int enable);
void Camera_func1C(int flags);
void Camera_setLetterbox(int yOffset,int applyNow);

#endif /* MAIN_DLL_DLL_BB_H_ */
