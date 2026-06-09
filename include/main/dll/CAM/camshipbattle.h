#ifndef MAIN_DLL_CAM_CAMSHIPBATTLE_H_
#define MAIN_DLL_CAM_CAMSHIPBATTLE_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

void camcontrol_updatePathTargetAction(CameraObject *camera,GameObject *target);
void camcontrol_releasePathState(void);

#endif /* MAIN_DLL_CAM_CAMSHIPBATTLE_H_ */
