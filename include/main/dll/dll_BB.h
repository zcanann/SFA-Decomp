#ifndef MAIN_DLL_DLL_BB_H_
#define MAIN_DLL_DLL_BB_H_

#include "ghidra_import.h"
#include "main/dll/CAM/camcontrol.h"

void camcontrol_applyState(CamcontrolCameraState *camera);
void camcontrol_applyQueuedAction(void);
void Camera_func1D(int targetFlagMode);
void Camera_func13(int enable);
void Camera_func1C(int flags);
void Camera_setLetterbox(int yOffset,int applyNow);

#endif /* MAIN_DLL_DLL_BB_H_ */
