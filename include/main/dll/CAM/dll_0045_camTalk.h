#ifndef MAIN_DLL_CAM_CAMTALK_H_
#define MAIN_DLL_CAM_CAMTALK_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

typedef struct CamTalkTransformInput {
  u16 yaw;
  u16 pitch;
  u16 roll;
  u16 pad;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} CamTalkTransformInput;

void CameraModeBike_update(CameraObject *camera);
void CameraModeBike_init(CameraObject *camera);
void CameraModeBike_release(void);
void CameraModeBike_initialise(void);
void firstPersonPlaceCamera(GameObject *focus, int resetClamp);
void firstPersonExit(CameraObject *camera);

#endif /* MAIN_DLL_CAM_CAMTALK_H_ */
