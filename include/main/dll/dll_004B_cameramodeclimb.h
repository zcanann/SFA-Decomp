#ifndef MAIN_DLL_DLL_004B_CAMERAMODECLIMB_H_
#define MAIN_DLL_DLL_004B_CAMERAMODECLIMB_H_

#include "main/camera_object.h"

void CameraModeClimb_copyToCurrent(void);
void CameraModeClimb_free(void);
void CameraModeClimb_update(CameraObject* camObj);
void CameraModeClimb_init(int arg1, int mode, s8* args);
void CameraModeClimb_release(void);
void CameraModeClimb_initialise(void);

#endif /* MAIN_DLL_DLL_004B_CAMERAMODECLIMB_H_ */
