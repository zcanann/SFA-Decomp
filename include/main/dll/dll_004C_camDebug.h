#ifndef MAIN_DLL_DLL_004C_CAMDEBUG_H_
#define MAIN_DLL_DLL_004C_CAMDEBUG_H_

#include "main/camera_object.h"

void CameraModeFixed_copyToCurrent(void);
void CameraModeFixed_free(void);
void CameraModeFixed_update(void);
void CameraModeFixed_init(CameraObject* camera, int unused, CameraObject* src);
void CameraModeFixed_release(void);
void CameraModeFixed_initialise(void);

#endif /* MAIN_DLL_DLL_004C_CAMDEBUG_H_ */
