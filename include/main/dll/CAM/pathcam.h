#ifndef MAIN_DLL_CAM_PATHCAM_H_
#define MAIN_DLL_CAM_PATHCAM_H_

#include "ghidra_import.h"

void pathcam_loadSettings(undefined2 *param_1,int param_2,int param_3);
void camcontrol_releaseModeSettings(void);
void camcontrol_initialiseModeSettings(void);
void camcontrol_samplePathState(f32 *outX,f32 *height,f32 *outZ,undefined4 param_4,int param_5);

#endif /* MAIN_DLL_CAM_PATHCAM_H_ */
