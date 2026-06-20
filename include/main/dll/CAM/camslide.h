#ifndef MAIN_DLL_CAM_CAMSLIDE_H_
#define MAIN_DLL_CAM_CAMSLIDE_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

void camslide_update(CameraObject *camera, GameObject *target, f32 upperBound, f32 lowerBound);
void firstperson_updatePitch(f32 targetY, CameraObject *camera);

#endif /* MAIN_DLL_CAM_CAMSLIDE_H_ */
