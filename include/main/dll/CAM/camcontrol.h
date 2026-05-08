#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "ghidra_import.h"

void camcontrol_updateTargetFeedback(void);
void camcontrol_getRelativePosition(f32 param_1,int param_2,float *param_3,float *param_4,
                                    float *param_5,float *param_6,int param_7);
int Camera_isZooming(void);
void Camera_func15(int x);
void Camera_setTarget(int target);
int Camera_getTarget(void);
int Camera_getOverrideTarget(void);
void Camera_moveBy(f32 x,f32 y,f32 z);
void Camera_overridePos(f32 x,f32 y,f32 z);
void Camera_setFocus(void *target);
void camcontrol_loadTriggeredCamAction(int triggerType,uint actionNo,char triggerMode);
void *Camera_getCamActionsBinEntry(int actionNo);
void camcontrol_releaseCurrentHandler(void);
void camcontrol_queueSavedAction(undefined4 param_1,undefined param_2);
void Camera_setMode(s32 actionId,int priority,int startFlags,int dataSize,void *data,
                    undefined4 blendFrames,undefined queueMode);
void Camera_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void *Camera_func08(void);
void *Camera_GetFollowPos(void);
u32 Camera_getMode(void);
u32 Camera_get(void);
void Camera_init(void *focus,f32 x,f32 y,f32 z);
void Camera_release(void);
void Camera_initialise(void);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
