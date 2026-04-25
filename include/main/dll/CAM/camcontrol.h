#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "ghidra_import.h"

void camcontrol_updateTargetFeedback(void);
void camcontrol_getRelativePosition(double param_1,int param_2,float *param_3,float *param_4,
                                    float *param_5,float *param_6,int param_7);
void camcontrol_loadTriggeredCamAction(int triggerType,uint actionNo,char triggerMode);
void *camcontrol_loadCamAction(int actionNo);
void camcontrol_releaseCurrentHandler(void);
void camcontrol_queueSavedAction(undefined4 param_1,undefined param_2);
void camcontrol_queueCamAction(undefined4 param_1,undefined4 param_2,undefined param_3,int param_4,
                               uint param_5,undefined4 param_6,undefined param_7);
void camcontrol_updateState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                            undefined8 param_5,undefined8 param_6,undefined8 param_7,
                            undefined8 param_8);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
