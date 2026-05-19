#ifndef MAIN_DLL_CAM_CUTCAM_H_
#define MAIN_DLL_CAM_CUTCAM_H_

#include "ghidra_import.h"

typedef struct CamcontrolAction43Payload {
  s16 action;
  u8 enabled;
  u8 immediate;
} CamcontrolAction43Payload;

typedef struct CamcontrolAction44Payload {
  f32 distance;
  f32 yOffset;
  undefined2 height;
} CamcontrolAction44Payload;

undefined4
camcontrol_traceMove(float param_1,float *param_2,float *param_3,float *param_4,int param_5,
                     char param_6,u8 param_7,u8 param_8);
undefined camcontrol_traceFromTarget(float *param_1,int param_2,float *param_3);
undefined camcontrol_getTargetPosition(int param_1,short *param_2,float *param_3,short *param_4);
void camcontrol_updateTargetAction(int param_1,int param_2);
void cameraFn_80103b40(void);
void camMoveFn_80104040(void);
void camcontrol_updateModeSettings(void);
void doNothing_80103660(void);

#endif /* MAIN_DLL_CAM_CUTCAM_H_ */
