#ifndef MAIN_DLL_CAM_CAMCONTROL_H_
#define MAIN_DLL_CAM_CAMCONTROL_H_

#include "game/objects/object.h"
#include "global.h"
#include "main/camera_object.h"
#include "main/dll/DR/dr_types.h"
#include "main/camera_interface.h"
#include "main/resource.h"

typedef struct CamcontrolTriggeredAction CamcontrolTriggeredAction;

typedef struct CamcontrolResourceDescriptor {
    u32 metadata[4];
    ResourceDescriptorCallback initialise;
    ResourceDescriptorCallback release;
    CameraInterface interface;
    void (*queueSavedAction)(int blendFrames, u8 queueMode);
} CamcontrolResourceDescriptor;

STATIC_ASSERT(offsetof(CamcontrolResourceDescriptor, metadata) == 0x00);
STATIC_ASSERT(offsetof(CamcontrolResourceDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(CamcontrolResourceDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(CamcontrolResourceDescriptor, interface) == 0x18);
STATIC_ASSERT(offsetof(CamcontrolResourceDescriptor, queueSavedAction) == 0x88);
STATIC_ASSERT(sizeof(CamcontrolResourceDescriptor) == 0x8C);

typedef void (*CamcontrolHandlerReservedFn)(void);
typedef void (*CamcontrolHandlerActivateFn)(CameraObject* camera, int startFlags, void* actionData);
typedef void (*CamcontrolHandlerUpdateFn)(CameraObject* camera);
typedef void (*CamcontrolHandlerReleaseFn)(CameraObject* camera);
typedef void (*CamcontrolHandlerActionCallbackFn)(void* actionData, int dataSize);
typedef void (*CamcontrolDefaultHandlerFollowFn)(void* camera, ObjAnimComponent* target);
typedef void (*CamcontrolDefaultHandlerUpdatePitchFn)(void* camera, double targetY, double distance);
typedef void (*CamcontrolDefaultHandlerUpdateSlideFn)(void* camera, GameObject* target, f32 floorHeight, f32 ceilingHeight);
typedef void (*CamcontrolDefaultHandlerGetSettingsFn)(f32* minDistance, f32* maxDistance, f32* lowerHeightOffset,
                                                      f32* upperHeightOffset, f32* targetHeight);
typedef void (*CamcontrolDefaultHandlerUpdateVerticalBoundsFn)(void* camera, int flags, int queryType,
                                                               f32* floorHeight, f32* ceilingHeight);

typedef struct CamcontrolHandlerVTable {
    CamcontrolHandlerReservedFn reserved18;
    CamcontrolHandlerActivateFn activate;
    CamcontrolHandlerUpdateFn update;
    CamcontrolHandlerReleaseFn release;
    CamcontrolHandlerActionCallbackFn actionCallback;
} CamcontrolHandlerVTable;

typedef struct CamcontrolDefaultHandlerVTable {
    CamcontrolHandlerReservedFn reserved18;
    CamcontrolHandlerActivateFn activate;
    CamcontrolHandlerUpdateFn update;
    CamcontrolHandlerReleaseFn release;
    CamcontrolHandlerActionCallbackFn actionCallback;
    CamcontrolDefaultHandlerFollowFn follow;
    CamcontrolDefaultHandlerUpdatePitchFn updatePitch;
    CamcontrolDefaultHandlerUpdateSlideFn updateSlide;
    CamcontrolDefaultHandlerGetSettingsFn getSettings;
    CamcontrolDefaultHandlerUpdateVerticalBoundsFn updateVerticalBounds;
} CamcontrolDefaultHandlerVTable;

typedef struct CamcontrolHandler {
    CamcontrolHandlerVTable* vtable;
} CamcontrolHandler;

typedef struct CamcontrolDefaultHandler {
    CamcontrolDefaultHandlerVTable* vtable;
} CamcontrolDefaultHandler;

typedef struct CamcontrolDefaultHandlerEntry {
    u16 actionId;
    u8 pad02[2];
    CamcontrolDefaultHandler* handler;
    u8 priority;
    u8 pad09[3];
} CamcontrolDefaultHandlerEntry;

STATIC_ASSERT(sizeof(CamcontrolHandlerVTable) == 0x14);
STATIC_ASSERT(offsetof(CamcontrolHandlerVTable, activate) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolHandlerVTable, actionCallback) == 0x10);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerVTable, follow) == 0x14);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerVTable, updatePitch) == 0x18);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerVTable, updateSlide) == 0x1C);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerVTable, getSettings) == 0x20);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerVTable, updateVerticalBounds) == 0x24);
STATIC_ASSERT(sizeof(CamcontrolHandler) == 0x04);
STATIC_ASSERT(sizeof(CamcontrolDefaultHandler) == 0x04);
STATIC_ASSERT(sizeof(CamcontrolDefaultHandlerEntry) == 0x0C);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerEntry, handler) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolDefaultHandlerEntry, priority) == 0x08);

enum CamcontrolBlendFlags {
    CAMCONTROL_BLEND_YAW = 0x01,
    CAMCONTROL_BLEND_PITCH = 0x02,
    CAMCONTROL_BLEND_ROLL = 0x04,
    CAMCONTROL_BLEND_X = 0x08,
    CAMCONTROL_BLEND_Y = 0x10,
    CAMCONTROL_BLEND_Z = 0x20
};

enum CamcontrolTargetKind {
    CAMCONTROL_TARGET_KIND_MASK = 0x0F,
    CAMCONTROL_TARGET_KIND_LOCKON = 1,
    CAMCONTROL_TARGET_KIND_A_BUTTON_HINT = 2,
    CAMCONTROL_TARGET_KIND_CONTEXT_A = 4,
    CAMCONTROL_TARGET_KIND_CONTEXT_B_ICON = 5,
    CAMCONTROL_TARGET_KIND_TALK_ICON = 6,
    CAMCONTROL_TARGET_KIND_SUPPRESSED = 8,
    CAMCONTROL_TARGET_KIND_CONTEXT_B = 9
};

enum CamcontrolCameraTargetFlags {
    CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT = 0x02,
    CAMCONTROL_CAMERA_TARGET_FLAG_APPLY_MODE_MASK = 0x18,
    CAMCONTROL_CAMERA_TARGET_FLAG_PROMPT_SUPPRESSED = 0x20
};

enum CamcontrolTriggerKind {
    CAMCONTROL_TRIGGER_KIND_LOAD_ACTION,
    CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1,
    CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2,
    CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION,
    CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET
};

enum CamcontrolActionId {
    CAMCONTROL_ACTION_DEFAULT = 0x42,
    CAMCONTROL_ACTION_TRIGGER_TYPE2 = 0x47,
    CAMCONTROL_ACTION_TRIGGER_TYPE1 = 0x48,
    CAMCONTROL_ACTION_TRIGGERED = 0x4B
};

enum CamcontrolActionEncoding {
    CAMCONTROL_ACTION_INDEX_MASK = 0x7F,
    CAMCONTROL_ACTION_FLAG_NO_BLEND = 0x80,
    CAMCONTROL_QUEUE_SENTINEL = 0xFF
};

extern CamcontrolResourceDescriptor gCamcontrolResourceDescriptor;

int Camera_getTargetKind(void);
int Camera_getMinimapInfoText(void);
void camcontrol_updateTargetReticle(GameObject* fallbackTarget, int unused2, u32 renderArg2, u32 renderArg3,
                                    u32 renderArg4, u32 renderArg5);
int camcontrol_aButtonIconTextureCallback(GameObject* obj, ObjModel* model, u32 renderOpIndex);
int camcontrol_lockIconTextureCallback(GameObject* obj, ObjModel* model, int renderOpIndex);
void camcontrol_initialiseTargetReticle(void);
GameObject* camcontrol_findBestTarget(CameraObject* cameraState, ObjAnimComponent* focus);
void camcontrol_updateMoveAverage(CameraObject* cameraState, ObjAnimComponent* focus);
void camcontrol_activateHandler(u16 actionId, void* actionData);
void firstPersonZoomOutOnExit(u8 blendFrames, u8 blendFlags);
void Camera_setBlendCurveMode(u8 mode);
void camcontrol_applyState(CameraObject* camera);
void camcontrol_applyQueuedAction(void);
void Camera_applyTargetFlags(int targetFlagMode);
void Camera_setTargetFlag2(int enable);
void Camera_applyFrameFlags(int flags);
void Camera_setLetterbox(int yOffset, int applyNow);
void Camera_minimapShowHelpTextForTarget(int renderArg2, int renderArg3, int renderArg4, int renderArg5);
void camcontrol_setAButtonIconForTarget(void);
void camcontrol_updateTargetFeedback(void);
int Camera_isZooming(void);
void Camera_setTargetReticleOverride(GameObject* target);
void Camera_setTarget(GameObject* target);
GameObject* Camera_getTarget(void);
GameObject* Camera_getOverrideTarget(void);
void camcontrol_getRelativePosition(void* targetObj, f32* outX, f32* outY, f32* outZ, f32* outDistanceXZ,
                                    f32 heightOffset, int useLocalPosition);
void camcontrol_initialise(f32 numerator, f32* dst, f32 denominator, f32 minValue, f32 y, f32 z);
void Camera_moveBy(f32 x, f32 y, f32 z);
void Camera_overridePos(f32 x, f32 y, f32 z);
void Camera_setFocus(void* target, int flags);
void camcontrol_loadTriggeredCamAction(int triggerType, int actionNo, int triggerMode);
CamcontrolTriggeredAction* Camera_getCamActionsBinEntry(int actionNo);
void camcontrol_release(void* camAction, int recordSize);
void camcontrol_queueSavedAction(int blendFrames, u8 queueMode);
void Camera_setMode(s32 actionId, int priority, int startFlags, int dataSize, void* data, int blendFrames,
                    u8 queueMode);
void* Camera_getDefaultHandlerEntry(void);
void* Camera_getActiveHandler(void);
int Camera_getMode(void);
void* Camera_get(void);
void Camera_update(u8 framesThisStep);
void Camera_init(void* focus, f32 x, f32 y, f32 z);
void Camera_release(void);
void Camera_initialise(void);

#endif /* MAIN_DLL_CAM_CAMCONTROL_H_ */
