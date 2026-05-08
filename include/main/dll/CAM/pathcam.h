#ifndef MAIN_DLL_CAM_PATHCAM_H_
#define MAIN_DLL_CAM_PATHCAM_H_

#include "ghidra_import.h"

void pathcam_loadSettings(undefined2 *param_1,int param_2,int param_3);
void camcontrol_releaseModeSettings(void);
void camcontrol_initialiseModeSettings(void);
void camcontrol_samplePathState(undefined4 param_1,undefined4 param_2,undefined4 *param_3,
                                undefined4 param_4,int param_5);

#endif /* MAIN_DLL_CAM_PATHCAM_H_ */
