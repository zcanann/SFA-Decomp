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

typedef struct CamcontrolCameraState {
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad06[0x0C - 0x06];
    f32 localX;
    f32 localY;
    f32 localZ;
    f32 worldX;
    f32 worldY;
    f32 worldZ;
    u8 pad24[0x30 - 0x24];
    GameObject* localFrameObj;
    u8 pad34[0xA4 - 0x34];
    ObjAnimComponent* focusObj;
    f32 prevLocalX;
    f32 prevLocalY;
    f32 prevLocalZ;
    f32 fovY;
    f32 prevWorldX;
    f32 prevWorldY;
    f32 prevWorldZ;
    f32 focusMoveAverage;
    f32 focusMoveHistory[5];
    f32 overrideWorldX;
    f32 overrideWorldY;
    f32 overrideWorldZ;
    u8 padE8[0xF4 - 0xE8];
    f32 blendProgress;
    f32 blendStep;
    u8 padFC[0x100 - 0xFC];
    s16 blendDeltaYaw;
    s16 blendDeltaPitch;
    s16 blendDeltaRoll;
    s16 blendStartYaw;
    s16 blendStartPitch;
    s16 blendStartRoll;
    f32 blendStartX;
    f32 blendStartY;
    f32 blendStartZ;
    f32 blendStartFovY;
    GameObject* overrideTarget;
    GameObject* targetReticleOverride;
    GameObject* currentTarget;
    GameObject* targetReticleFocus;
    u8 pad12C[0x134 - 0x12C];
    f32 targetDistance;
    u8 targetKind;
    u8 blendCurveMode;
    u8 pad13A;
    s8 letterboxTargetOffset;
    s8 letterboxStep;
    u8 overrideWorldPosPending;
    u8 pad13E;
    u8 queuedBlendFlags;
    u8 frameFlags;
    u8 targetFlags;
    u8 pad142;
    BitFlags8 smoothingFlags;
} CamcontrolCameraState;

STATIC_ASSERT(sizeof(CamcontrolCameraState) == 0x144);
STATIC_ASSERT(offsetof(CamcontrolCameraState, yaw) == 0x00);
STATIC_ASSERT(offsetof(CamcontrolCameraState, localX) == 0x0C);
STATIC_ASSERT(offsetof(CamcontrolCameraState, worldX) == 0x18);
STATIC_ASSERT(offsetof(CamcontrolCameraState, localFrameObj) == 0x30);
STATIC_ASSERT(offsetof(CamcontrolCameraState, focusObj) == 0xA4);
STATIC_ASSERT(offsetof(CamcontrolCameraState, prevLocalX) == 0xA8);
STATIC_ASSERT(offsetof(CamcontrolCameraState, fovY) == 0xB4);
STATIC_ASSERT(offsetof(CamcontrolCameraState, prevWorldX) == 0xB8);
STATIC_ASSERT(offsetof(CamcontrolCameraState, focusMoveAverage) == 0xC4);
STATIC_ASSERT(offsetof(CamcontrolCameraState, focusMoveHistory) == 0xC8);
STATIC_ASSERT(offsetof(CamcontrolCameraState, overrideWorldX) == 0xDC);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendProgress) == 0xF4);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendDeltaYaw) == 0x100);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendStartYaw) == 0x106);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendStartX) == 0x10C);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendStartFovY) == 0x118);
STATIC_ASSERT(offsetof(CamcontrolCameraState, overrideTarget) == 0x11C);
STATIC_ASSERT(offsetof(CamcontrolCameraState, targetReticleOverride) == 0x120);
STATIC_ASSERT(offsetof(CamcontrolCameraState, currentTarget) == 0x124);
STATIC_ASSERT(offsetof(CamcontrolCameraState, targetReticleFocus) == 0x128);
STATIC_ASSERT(offsetof(CamcontrolCameraState, targetDistance) == 0x134);
STATIC_ASSERT(offsetof(CamcontrolCameraState, targetKind) == 0x138);
STATIC_ASSERT(offsetof(CamcontrolCameraState, blendCurveMode) == 0x139);
STATIC_ASSERT(offsetof(CamcontrolCameraState, letterboxTargetOffset) == 0x13B);
STATIC_ASSERT(offsetof(CamcontrolCameraState, overrideWorldPosPending) == 0x13D);
STATIC_ASSERT(offsetof(CamcontrolCameraState, queuedBlendFlags) == 0x13F);
STATIC_ASSERT(offsetof(CamcontrolCameraState, frameFlags) == 0x140);
STATIC_ASSERT(offsetof(CamcontrolCameraState, targetFlags) == 0x141);
STATIC_ASSERT(offsetof(CamcontrolCameraState, smoothingFlags) == 0x143);

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
GameObject* camcontrol_findBestTarget(CamcontrolCameraState* cameraState, ObjAnimComponent* focus);
void camcontrol_updateMoveAverage(CamcontrolCameraState* cameraState, ObjAnimComponent* focus);
void camcontrol_activateHandler(u16 actionId, void* actionData);
void firstPersonZoomOutOnExit(u8 blendFrames, u8 blendFlags);
void Camera_setBlendCurveMode(u8 mode);
void camcontrol_applyState(CamcontrolCameraState* camera);
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
