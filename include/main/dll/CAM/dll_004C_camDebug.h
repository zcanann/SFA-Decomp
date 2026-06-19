#ifndef MAIN_DLL_CAM_CAMDEBUG_H_
#define MAIN_DLL_CAM_CAMDEBUG_H_

#include "ghidra_import.h"
#include "main/camera_object.h"

void CameraModeClimb_init(u32 param_1,int param_2,s8 *param_3);
void CameraModeFixed_init(CameraObject *camera,u32 param_2,CameraObject *src);

#endif /* MAIN_DLL_CAM_CAMDEBUG_H_ */
