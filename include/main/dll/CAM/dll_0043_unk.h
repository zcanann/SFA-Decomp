#ifndef MAIN_DLL_CAM_DLL_0043_UNK_H_
#define MAIN_DLL_CAM_DLL_0043_UNK_H_

#include "main/camera_object.h"
#include "main/game_object.h"
#include "types.h"

void camcontrol_updatePathTargetAction(CameraObject* camera, GameObject* target);
void camcontrol_releasePathState(void);
void CameraModeStaffAnim_copyToCurrent(void);
void camclimb_update(CameraObject* camera);
void CameraModeStaffAnim_init(CameraObject* camera, int unused, u8* settings);
void CameraModeStaffAnim_release(void);
void CameraModeStaffAnim_initialise(void);

#endif /* MAIN_DLL_CAM_DLL_0043_UNK_H_ */
