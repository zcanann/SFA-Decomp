#ifndef MAIN_DLL_CAM_CAMLOCKON_H_
#define MAIN_DLL_CAM_CAMLOCKON_H_

#include "ghidra_import.h"

void camcontrol_releaseModeSettings(void);
void camcontrol_initialiseModeSettings(void);
void camcontrol_samplePathState(undefined4 param_1,undefined4 param_2,undefined4 *param_3,
                                undefined4 param_4,int param_5);
void camcontrol_buildPathAngles(undefined4 param_1,undefined4 param_2,short param_3,short param_4,
                                undefined4 param_5);

#endif /* MAIN_DLL_CAM_CAMLOCKON_H_ */
