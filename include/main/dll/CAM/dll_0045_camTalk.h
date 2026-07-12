#ifndef MAIN_DLL_CAM_CAMTALK_H_
#define MAIN_DLL_CAM_CAMTALK_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"
#include "main/vecmath.h"

void CameraModeBike_update(CameraObject *camera);
void CameraModeBike_init(CameraObject *camera);
void CameraModeBike_release(void);
void CameraModeBike_initialise(void);
void firstPersonPlaceCamera(GameObject *focus, int resetClamp);
void firstPersonExit(CameraObject *camera);

#endif /* MAIN_DLL_CAM_CAMTALK_H_ */
