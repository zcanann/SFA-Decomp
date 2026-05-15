#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "ghidra_import.h"

typedef struct CamcontrolTriggeredAction {
  s8 actionKind;
  u8 pad01[0xC];
  u8 triggerMode;
  u8 pad0E[2];
} CamcontrolTriggeredAction;

typedef struct CamcontrolQueuedActionParam {
  uint actionIndex;
  byte noBlendFlag;
} CamcontrolQueuedActionParam;

#define CAMCONTROL_TRIGGER_KIND_LOAD_ACTION 0
#define CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1 1
#define CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2 2
#define CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION 3
#define CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET 4
#define CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT 0
#define CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED 1
#define CAMCONTROL_ACTION_DEFAULT 0x42
#define CAMCONTROL_ACTION_TRIGGERED 0x4B
#define CAMCONTROL_ACTION_TRIGGER_TYPE1 0x48
#define CAMCONTROL_ACTION_TRIGGER_TYPE2 0x47
#define CAMCONTROL_ACTION_NO_NONE 0
#define CAMCONTROL_SAVED_ACTION_NONE -1
#define CAMCONTROL_ACTION_INDEX_MASK 0x7F
#define CAMCONTROL_ACTION_FLAG_NO_BLEND 0x80
#define CAMCONTROL_ACTION_RECORD_SIZE 0x10
#define CAMCONTROL_QUEUED_ACTION_PARAM_SIZE sizeof(CamcontrolQueuedActionParam)
#define CAMCONTROL_ACTION_FILE_ID 0xB
#define CAMCONTROL_ACTION_HEAP 0xF
#define CAMCONTROL_DEFAULT_BLEND_FRAMES 0x78
#define CAMCONTROL_QUEUE_SENTINEL 0xFF

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
void camcontrol_loadTriggeredCamAction(int triggerType,int actionNo,int triggerMode);
void *Camera_getCamActionsBinEntry(int actionNo);
void camcontrol_release(void);
void camcontrol_queueSavedAction(undefined4 param_1,undefined param_2);
void Camera_setMode(s32 actionId,int priority,int startFlags,int dataSize,void *data,
                    undefined4 blendFrames,undefined queueMode);
void Camera_update(void);
void *Camera_func08(void);
void *Camera_GetFollowPos(void);
u32 Camera_getMode(void);
u32 Camera_get(void);
void Camera_init(void *focus,f32 x,f32 y,f32 z);
void Camera_release(void);
void Camera_initialise(void);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
