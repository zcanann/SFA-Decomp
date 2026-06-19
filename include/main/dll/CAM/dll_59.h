#ifndef MAIN_DLL_CAM_DLL_59_H_
#define MAIN_DLL_CAM_DLL_59_H_

#include "ghidra_import.h"
#include "main/camera_object.h"

void CameraModeStaffAnim_init(CameraObject *camera, u32 param_2, u8 *settings);
void CameraModeStaffAnim_release(void);
void CameraModeStaffAnim_initialise(void);
void CameraModeBike_copyToCurrent(f32 *param_1);
void CameraModeBike_free(void);

#endif /* MAIN_DLL_CAM_DLL_59_H_ */
