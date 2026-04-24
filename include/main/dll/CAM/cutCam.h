#ifndef MAIN_DLL_CAM_CUTCAM_H_
#define MAIN_DLL_CAM_CUTCAM_H_

#include "ghidra_import.h"

void camcontrol_setPosition(double param_1,double param_2,double param_3,undefined4 param_4);
void FUN_80103620(void);
void camcontrol_resetState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8);
undefined4
camcontrol_traceMove(double param_1,float *param_2,float *param_3,float *param_4,int param_5,
                     undefined param_6,char param_7,char param_8);
void FUN_80103884(void);
undefined camcontrol_traceFromTarget(float *param_1,int param_2,float *param_3);
undefined camcontrol_getTargetPosition(int param_1,short *param_2,float *param_3,short *param_4);
void camcontrol_updateTargetAction(int param_1,int param_2);
void FUN_80103e00(void);
void FUN_801043bc(void);

#endif /* MAIN_DLL_CAM_CUTCAM_H_ */
