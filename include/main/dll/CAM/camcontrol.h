#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "global.h"
#include "ghidra_import.h"

typedef struct CamcontrolTriggeredAction {
  s8 actionKind;
  u8 pad01[0xC];
  u8 triggerMode;
  u8 pad0E[2];
} CamcontrolTriggeredAction;

STATIC_ASSERT(sizeof(CamcontrolTriggeredAction) == 0x10);
STATIC_ASSERT(offsetof(CamcontrolTriggeredAction, triggerMode) == 0x0D);

typedef struct CamcontrolQueuedActionParam {
  uint actionIndex;
  byte noBlendFlag;
} CamcontrolQueuedActionParam;

STATIC_ASSERT(sizeof(CamcontrolQueuedActionParam) == 0x08);
STATIC_ASSERT(offsetof(CamcontrolQueuedActionParam, noBlendFlag) == 0x04);

typedef struct CameraViewSlot {
  s16 yaw;
  s16 pitch;
  s16 roll;
  u8 pad06[0xC - 0x6];
  f32 x;
  f32 y;
  f32 z;
} CameraViewSlot;

typedef struct CamcontrolCameraState {
  u8 pad00[0x0C];
  f32 localX;
  f32 localY;
  f32 localZ;
  f32 worldX;
  f32 worldY;
  f32 worldZ;
  u8 pad24[0x30 - 0x24];
  u32 localFrameObj;
  u8 pad34[0xA4 - 0x34];
  void *focusObj;
  f32 prevLocalX;
  f32 prevLocalY;
  f32 prevLocalZ;
  f32 focusHeight;
  f32 prevWorldX;
  f32 prevWorldY;
  f32 prevWorldZ;
  u8 padC4[0xDC - 0xC4];
  f32 overrideWorldX;
  f32 overrideWorldY;
  f32 overrideWorldZ;
  u8 padE8[0xF4 - 0xE8];
  f32 zoomDistance;
  u8 padF8[0x11C - 0xF8];
  int overrideTarget;
  int func15Value;
  int currentTarget;
  int targetReticleFocus;
  u8 pad12C[0x134 - 0x12C];
  f32 targetDistance;
  u8 targetKind;
  u8 triggerType1Pending;
  u8 pad13A[0x13D - 0x13A];
  u8 overrideWorldPosPending;
  u8 pad13E[0x140 - 0x13E];
  u8 frameFlags;
  u8 targetFlags;
  u8 pad142[0x144 - 0x142];
} CamcontrolCameraState;

STATIC_ASSERT(sizeof(CamcontrolCameraState) == 0x144);

typedef struct CamcontrolHandlerVTable {
  void (*func00)();
  void (*activate)(void *camera,int startFlags,void *actionData);
  void (*update)(void *camera);
  void (*release)(void *camera);
  void (*actionCallback)();
} CamcontrolHandlerVTable;

typedef struct CamcontrolHandler {
  CamcontrolHandlerVTable *vtable;
} CamcontrolHandler;

typedef struct CamcontrolHandlerEntry {
  u16 actionId;
  u8 pad02[2];
  CamcontrolHandler *handler;
  u8 priority;
  u8 pad09[3];
} CamcontrolHandlerEntry;

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
#define CAMCONTROL_FALLBACK_ACTION_NO 1
#define CAMCONTROL_FALLBACK_ACTION_FILE_OFFSET 0
#define CAMCONTROL_SAVED_ACTION_NONE -1
#define CAMCONTROL_ACTION_INDEX_MASK 0x7F
#define CAMCONTROL_ACTION_FLAG_NO_BLEND 0x80
#define CAMCONTROL_ACTION_RECORD_SIZE 0x10
#define CAMCONTROL_QUEUED_ACTION_PARAM_SIZE sizeof(CamcontrolQueuedActionParam)
#define CAMCONTROL_ACTION_FILE_ID 0xB
#define CAMCONTROL_ACTION_HEAP 0xF
#define CAMCONTROL_DEFAULT_BLEND_FRAMES 0x78
#define CAMCONTROL_QUEUE_SENTINEL 0xFF
#define CAMCONTROL_CAMERA ((CamcontrolCameraState *)pCamera)

extern char sCamcontrolTriggeredCamActionLoadWarning[];
extern CamcontrolHandlerEntry *gCamcontrolHandlerEntries[20];
extern CamcontrolHandlerEntry *gCamcontrolCurrentHandler;
extern s32 gCamcontrolActiveActionId;
extern int gCamcontrolActiveActionStartFlags;
extern int gCamcontrolActiveActionPriority;
extern int gCamcontrolCurrentHandlerIndex;
extern u8 gCamcontrolHandlerCount;
extern s8 gCamcontrolQueuedActionPriority;
extern s8 gCamcontrolQueuedActionStartFlags;
extern u8 gCamcontrolQueuedActionMode;
extern s32 gCamcontrolQueuedActionBlendFrames;
extern u8 gCamcontrolQueuedActionPending;
extern void *gCamcontrolQueuedActionData;
extern s32 gCamcontrolQueuedActionId;
extern int gCamcontrolSavedActionStartFlags;
extern int gCamcontrolSavedActionPriority;
extern int gCamcontrolSavedActionId;
extern u8 *pCamera;

void camcontrol_updateTargetFeedback(void);
void camcontrol_getRelativePosition(f32 heightOffset,int targetObj,float *outX,float *outY,
                                    float *outZ,float *outDistanceXZ,int useWorldPosition);
void camcontrol_initialise(float *dst,f32 numerator,f32 denominator,f32 minValue,f32 y,f32 z);
int Camera_isZooming(void);
void Camera_func15(int x);
void Camera_setTarget(int target);
int Camera_getTarget(void);
int Camera_getOverrideTarget(void);
void Camera_moveBy(f32 x,f32 y,f32 z);
void Camera_overridePos(f32 x,f32 y,f32 z);
void Camera_setFocus(void *target);
void camcontrol_loadTriggeredCamAction(int triggerType,int actionNo,int triggerMode);
CamcontrolTriggeredAction *Camera_getCamActionsBinEntry(int actionNo);
void camcontrol_release(void);
void camcontrol_queueSavedAction(undefined4 blendFrames,undefined queueMode);
void Camera_setMode(s32 actionId,int priority,int startFlags,int dataSize,void *data,
                    undefined4 blendFrames,undefined queueMode);
void Camera_update(void);
void *Camera_getDefaultHandlerEntry(void);
void *Camera_GetFollowPos(void);
u32 Camera_getMode(void);
u32 Camera_get(void);
void Camera_init(void *focus,f32 x,f32 y,f32 z);
void Camera_release(void);
void Camera_initialise(void);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
