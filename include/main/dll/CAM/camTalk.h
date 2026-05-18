#ifndef MAIN_DLL_CAM_CAMTALK_H_
#define MAIN_DLL_CAM_CAMTALK_H_

#include "ghidra_import.h"

typedef struct CamTalkTransformInput {
  u16 yaw;
  undefined2 pitch;
  undefined2 roll;
  undefined2 pad;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} CamTalkTransformInput;

void FUN_80107b4c(void);
void CameraModeBike_update(short *param_1);
void CameraModeBike_init(int param_1);
void CameraModeBike_release(void);
void CameraModeBike_initialise(void);
void firstPersonPlaceCamera(int param_1,int param_2);
void firstPersonExit(short *param_1);

#endif /* MAIN_DLL_CAM_CAMTALK_H_ */
