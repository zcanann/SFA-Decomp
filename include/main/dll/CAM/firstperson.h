#ifndef MAIN_DLL_CAM_FIRSTPERSON_H_
#define MAIN_DLL_CAM_FIRSTPERSON_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/objanim_internal.h"

void firstperson_updatePitch(f32 targetY, CameraObject *camera);
void firstperson_updatePosition(CameraObject *camera,ObjAnimComponent *target);
void firstperson_loadSettings(CamcontrolFirstPersonActionSettings *settings);
void CameraModeNormal_free(CameraObject *camera);

#endif /* MAIN_DLL_CAM_FIRSTPERSON_H_ */
