#ifndef MAIN_DLL_DLL_0057_CAMERAMODETITLE_H_
#define MAIN_DLL_DLL_0057_CAMERAMODETITLE_H_

#include "global.h"
#include "main/camera_object.h"

f32 titleScreenGetCamProgress(void);
void CameraModeTitle_moveCam(u8 newCam);
void CameraModeTitle_loadVolumes(void);
void CameraModeTitle_update(CameraObject* camera);
void CameraModeTitle_init(CameraObject* camera);
void CameraModeTitle_release(void);
void CameraModeTitle_initialise(void);

#endif /* MAIN_DLL_DLL_0057_CAMERAMODETITLE_H_ */
