#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objanim_internal.h"

typedef struct CamcontrolBaddieControlInterface {
  u8 pad00[0x60];
  f32 (*getTargetReticleDistance)(int obj);
} CamcontrolBaddieControlInterface;

typedef struct CamcontrolTargetMarkerSlot {
  f32 x;
  f32 y;
  f32 z;
  u8 pad0C[0x18 - 0x0C];
} CamcontrolTargetMarkerSlot;

typedef struct CamcontrolTargetSetup {
  u8 pad00[0x04];
  u8 targetKind;
} CamcontrolTargetSetup;

typedef struct CamcontrolTargetObject {
  u8 pad00[0x44];
  s16 classId;
  s16 objType;
  u8 pad48[0x74 - 0x48];
  CamcontrolTargetMarkerSlot *targetMarkerSlots;
  CamcontrolTargetSetup *targetSetup;
  u8 pad7C[0xAF - 0x7C];
  u8 targetFlags;
  u8 padB0[0xE4 - 0xB0];
  u8 targetSetupIndex;
  u8 padE5[0xE8 - 0xE5];
  u8 targetPaletteIndex;
} CamcontrolTargetObject;

typedef struct CamcontrolReticleObject {
  ObjAnimComponent anim;
} CamcontrolReticleObject;

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
  void *localFrameObj;
  u8 pad34[0xA4 - 0x34];
  ObjAnimComponent *focusObj;
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
  int targetReticleOverride;
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
  void (*actionCallback)(void *actionData,int dataSize);
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

#define CAMCONTROL_TARGET_KIND_MASK 0x0F
#define CAMCONTROL_TARGET_KIND_LOCKON 1
#define CAMCONTROL_TARGET_KIND_A_BUTTON_HINT 2
#define CAMCONTROL_TARGET_KIND_CONTEXT_A 4
#define CAMCONTROL_TARGET_KIND_CONTEXT_B_ICON 5
#define CAMCONTROL_TARGET_KIND_TALK_ICON 6
#define CAMCONTROL_TARGET_KIND_SUPPRESSED 8
#define CAMCONTROL_TARGET_KIND_CONTEXT_B 9
#define CAMCONTROL_TARGET_FLAG_INPUT_PRESSED 0x01
#define CAMCONTROL_TARGET_FLAG_RETICLE_TOUCHING 0x04
#define CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT 0x10
#define CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT 0x20
#define CAMCONTROL_TARGET_BUTTON_PRIMARY 0x100
#define CAMCONTROL_TARGET_BUTTON_CONTEXT 0x900
#define CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE 0
#define CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE 3
#define CAMCONTROL_RETICLE_ICON_LOCKON 1
#define CAMCONTROL_RETICLE_ICON_A_BUTTON 2
#define CAMCONTROL_RETICLE_SPIN_STEP 0x400
#define CAMCONTROL_HELP_TEXT_NONE -1
#define CAMCONTROL_A_BUTTON_ICON_TALK_NPC 8
#define CAMCONTROL_A_BUTTON_ICON_TALK_OBJECT 9
#define CAMCONTROL_A_BUTTON_ICON_HINT 7
#define CAMCONTROL_A_BUTTON_ICON_CONTEXT_B 0x0F
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

STATIC_ASSERT(sizeof(CamcontrolTargetMarkerSlot) == 0x18);
STATIC_ASSERT(sizeof(CamcontrolTargetSetup) == 0x05);
STATIC_ASSERT(offsetof(CamcontrolTargetSetup, targetKind) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, classId) == 0x44);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, objType) == 0x46);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetMarkerSlots) == 0x74);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetSetup) == 0x78);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetFlags) == 0xAF);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetSetupIndex) == 0xE4);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetPaletteIndex) == 0xE8);

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
extern CamcontrolReticleObject *gCamcontrolTargetReticle;
extern s8 gCamcontrolTargetChanged;
extern s8 gCamcontrolTargetState;
extern s16 gCamcontrolTargetHelpTextId;
extern u16 gCamcontrolReticleSpin;

void camcontrol_updateTargetFeedback(void);
void camcontrol_updateTargetReticle(CamcontrolTargetObject *fallbackTarget, int unused2,
                                    undefined4 arg3, undefined4 arg4, undefined4 arg5,
                                    undefined4 arg6);
void camcontrol_getRelativePosition(f32 heightOffset,int targetObj,float *outX,float *outY,
                                    float *outZ,float *outDistanceXZ,int useLocalPosition);
void camcontrol_initialise(float *dst,f32 numerator,f32 denominator,f32 minValue,f32 y,f32 z);
int Camera_isZooming(void);
void Camera_setTargetReticleOverride(int target);
void Camera_setTarget(int target);
int Camera_getTarget(void);
int Camera_getOverrideTarget(void);
void Camera_moveBy(f32 x,f32 y,f32 z);
void Camera_overridePos(f32 x,f32 y,f32 z);
void Camera_setFocus(void *target);
void camcontrol_loadTriggeredCamAction(int triggerType,int actionNo,int triggerMode);
CamcontrolTriggeredAction *Camera_getCamActionsBinEntry(int actionNo);
void camcontrol_release(void *camAction,int recordSize);
void camcontrol_queueSavedAction(int blendFrames,u8 queueMode);
void Camera_setMode(s32 actionId,int priority,int startFlags,int dataSize,void *data,
                    int blendFrames,u8 queueMode);
void Camera_update(void);
void *Camera_getDefaultHandlerEntry(void);
void *Camera_GetFollowPos(void);
u32 Camera_getMode(void);
u32 Camera_get(void);
void Camera_init(void *focus,f32 x,f32 y,f32 z);
void Camera_release(void);
void Camera_initialise(void);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
