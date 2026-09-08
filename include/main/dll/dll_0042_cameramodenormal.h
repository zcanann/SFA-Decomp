#ifndef MAIN_DLL_DLL_0042_CAMERAMODENORMAL_H_
#define MAIN_DLL_DLL_0042_CAMERAMODENORMAL_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/camera_object.h"
#include "main/resource.h"
#include "main/track_hit_results.h"

typedef struct CameraModeNormalActionSettings {
    u8 pad00[2];
    s8 fov;
    u8 minDistance;
    u8 maxDistance;
    s8 targetHeight;
    u8 lowerHeightOffset;
    u8 unknownFlags;
    u8 upperHeightOffset;
    u8 slideRightAmount;
    u8 slideLeftAmount;
    u8 distanceAdjustRate;
    u8 heightAdjustRate;
} CameraModeNormalActionSettings;

STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, fov) == 0x02);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, minDistance) == 0x03);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, maxDistance) == 0x04);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, targetHeight) == 0x05);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, lowerHeightOffset) == 0x06);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, unknownFlags) == 0x07);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, upperHeightOffset) == 0x08);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, slideRightAmount) == 0x09);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, slideLeftAmount) == 0x0A);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, distanceAdjustRate) == 0x0B);
STATIC_ASSERT(offsetof(CameraModeNormalActionSettings, heightAdjustRate) == 0x0C);
STATIC_ASSERT(sizeof(CameraModeNormalActionSettings) == 0x0D);

typedef struct CameraModeNormalInitSettings {
    u8 pad00;
    s8 transitionFrames;
    s8 fov;
    u8 minDistance;
    u8 maxDistance;
    u8 pad05;
    u8 lowerHeightOffset;
    u8 letterboxOffset;
    u8 upperHeightOffset;
    u8 slideRightAmount;
    u8 slideLeftAmount;
    u8 distanceAdjustRate;
    u8 heightAdjustRate;
    u8 snapToTarget;
    u8 pad0E[0x0B];
    u8 fovWide;
    u16 maxDistanceWide;
    u16 minDistanceWide;
    u8 pad1E;
    u8 heightOffsetWide;
} CameraModeNormalInitSettings;

STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, transitionFrames) == 0x01);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, fov) == 0x02);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, minDistance) == 0x03);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, maxDistance) == 0x04);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, lowerHeightOffset) == 0x06);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, letterboxOffset) == 0x07);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, upperHeightOffset) == 0x08);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, slideRightAmount) == 0x09);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, slideLeftAmount) == 0x0A);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, distanceAdjustRate) == 0x0B);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, heightAdjustRate) == 0x0C);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, snapToTarget) == 0x0D);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, fovWide) == 0x19);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, maxDistanceWide) == 0x1A);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, minDistanceWide) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeNormalInitSettings, heightOffsetWide) == 0x1F);
STATIC_ASSERT(sizeof(CameraModeNormalInitSettings) == 0x20);

typedef struct CameraModeNormalWallAvoidanceFlags {
    u8 active : 1;
    u8 savedActive : 1;
    u8 rest : 6;
} CameraModeNormalWallAvoidanceFlags;

STATIC_ASSERT(sizeof(CameraModeNormalWallAvoidanceFlags) == 0x01);

typedef struct CameraModeNormalClampFlags {
    u8 distanceClamped : 1;
    u8 heightLocked : 1;
    u8 rest : 6;
} CameraModeNormalClampFlags;

STATIC_ASSERT(sizeof(CameraModeNormalClampFlags) == 0x01);

typedef struct CameraModeNormalState {
    f32 minDistance;
    f32 maxDistance;
    f32 lowerHeightOffset;
    f32 upperHeightOffset;
    f32 distanceAdjustRate;
    f32 heightAdjustRate;
    f32 slideRightAmount;
    f32 slideLeftAmount;
    f32 unknown20;
    f32 unknown24;
    f32 avoidanceYawOffset;
    f32 savedMinDistance;
    f32 targetMinDistance;
    f32 savedMaxDistance;
    f32 targetMaxDistance;
    f32 savedLowerHeightOffset;
    f32 targetLowerHeightOffset;
    f32 savedUpperHeightOffset;
    f32 targetUpperHeightOffset;
    f32 savedDistanceAdjustRate;
    f32 targetDistanceAdjustRate;
    f32 savedHeightAdjustRate;
    f32 targetHeightAdjustRate;
    f32 savedSlideRightAmount;
    f32 targetSlideRightAmount;
    f32 savedSlideLeftAmount;
    f32 targetSlideLeftAmount;
    f32 savedFov;
    f32 fov;
    f32 savedWorldX;
    f32 savedWorldY;
    f32 savedWorldZ;
    s16 pitchOffset;
    s16 transitionTimer;
    s16 transitionDuration;
    s16 savedRotX;
    s16 savedRotY;
    s16 savedRotZ;
    f32 targetHeight;
    f32 savedTargetHeight;
    f32 targetTargetHeight;
    f32 baseLowerHeightOffset;
    f32 baseUpperHeightOffset;
    f32 verticalUpperBound;
    f32 verticalLowerBound;
    u8 unknownA8[4];
    s32 slideAngle;
    u8 unknownB0[0x0C];
    f32 heightLockLimit;
    u8 collisionBlocked;
    u8 initialized;
    u8 yawResponseFrames;
    u8 collisionProbeTimer;
    u8 collisionState;
    u8 targetActionFlags;
    CameraModeNormalWallAvoidanceFlags wallAvoidanceFlags;
    u8 wallAvoidanceTimer;
    CameraModeNormalClampFlags clampFlags;
    u8 padC9[3];
} CameraModeNormalState;

STATIC_ASSERT(offsetof(CameraModeNormalState, minDistance) == 0x00);
STATIC_ASSERT(offsetof(CameraModeNormalState, maxDistance) == 0x04);
STATIC_ASSERT(offsetof(CameraModeNormalState, lowerHeightOffset) == 0x08);
STATIC_ASSERT(offsetof(CameraModeNormalState, upperHeightOffset) == 0x0C);
STATIC_ASSERT(offsetof(CameraModeNormalState, distanceAdjustRate) == 0x10);
STATIC_ASSERT(offsetof(CameraModeNormalState, heightAdjustRate) == 0x14);
STATIC_ASSERT(offsetof(CameraModeNormalState, slideRightAmount) == 0x18);
STATIC_ASSERT(offsetof(CameraModeNormalState, slideLeftAmount) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeNormalState, unknown20) == 0x20);
STATIC_ASSERT(offsetof(CameraModeNormalState, unknown24) == 0x24);
STATIC_ASSERT(offsetof(CameraModeNormalState, avoidanceYawOffset) == 0x28);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedMinDistance) == 0x2C);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetMinDistance) == 0x30);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedMaxDistance) == 0x34);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetMaxDistance) == 0x38);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedLowerHeightOffset) == 0x3C);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetLowerHeightOffset) == 0x40);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedUpperHeightOffset) == 0x44);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetUpperHeightOffset) == 0x48);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedDistanceAdjustRate) == 0x4C);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetDistanceAdjustRate) == 0x50);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedHeightAdjustRate) == 0x54);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetHeightAdjustRate) == 0x58);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedSlideRightAmount) == 0x5C);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetSlideRightAmount) == 0x60);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedSlideLeftAmount) == 0x64);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetSlideLeftAmount) == 0x68);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedFov) == 0x6C);
STATIC_ASSERT(offsetof(CameraModeNormalState, fov) == 0x70);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedWorldX) == 0x74);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedWorldY) == 0x78);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedWorldZ) == 0x7C);
STATIC_ASSERT(offsetof(CameraModeNormalState, pitchOffset) == 0x80);
STATIC_ASSERT(offsetof(CameraModeNormalState, transitionTimer) == 0x82);
STATIC_ASSERT(offsetof(CameraModeNormalState, transitionDuration) == 0x84);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedRotX) == 0x86);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedRotY) == 0x88);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedRotZ) == 0x8A);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetHeight) == 0x8C);
STATIC_ASSERT(offsetof(CameraModeNormalState, savedTargetHeight) == 0x90);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetTargetHeight) == 0x94);
STATIC_ASSERT(offsetof(CameraModeNormalState, baseLowerHeightOffset) == 0x98);
STATIC_ASSERT(offsetof(CameraModeNormalState, baseUpperHeightOffset) == 0x9C);
STATIC_ASSERT(offsetof(CameraModeNormalState, verticalUpperBound) == 0xA0);
STATIC_ASSERT(offsetof(CameraModeNormalState, verticalLowerBound) == 0xA4);
STATIC_ASSERT(offsetof(CameraModeNormalState, unknownA8) == 0xA8);
STATIC_ASSERT(offsetof(CameraModeNormalState, slideAngle) == 0xAC);
STATIC_ASSERT(offsetof(CameraModeNormalState, unknownB0) == 0xB0);
STATIC_ASSERT(offsetof(CameraModeNormalState, heightLockLimit) == 0xBC);
STATIC_ASSERT(offsetof(CameraModeNormalState, collisionBlocked) == 0xC0);
STATIC_ASSERT(offsetof(CameraModeNormalState, initialized) == 0xC1);
STATIC_ASSERT(offsetof(CameraModeNormalState, yawResponseFrames) == 0xC2);
STATIC_ASSERT(offsetof(CameraModeNormalState, collisionProbeTimer) == 0xC3);
STATIC_ASSERT(offsetof(CameraModeNormalState, collisionState) == 0xC4);
STATIC_ASSERT(offsetof(CameraModeNormalState, targetActionFlags) == 0xC5);
STATIC_ASSERT(offsetof(CameraModeNormalState, wallAvoidanceFlags) == 0xC6);
STATIC_ASSERT(offsetof(CameraModeNormalState, wallAvoidanceTimer) == 0xC7);
STATIC_ASSERT(offsetof(CameraModeNormalState, clampFlags) == 0xC8);
STATIC_ASSERT(offsetof(CameraModeNormalState, padC9) == 0xC9);
STATIC_ASSERT(sizeof(CameraModeNormalState) == 0xCC);

typedef struct CameraModeNormalDescriptor {
    u32 metadata[4];
    void (*initialise)(void);
    void (*release)(void);
    ResourceDescriptorCallback reserved18;
    void (*init)(CameraObject* camera, int mode, CameraModeNormalInitSettings* settings);
    void (*update)(CameraObject* camera);
    void (*free)(CameraObject* camera);
    void (*copyToCurrent)(CameraModeNormalActionSettings* settings);
    void (*follow)(CameraObject* camera, ObjAnimComponent* target);
    void (*updatePitch)(f32 targetY, f32 distance, CameraObject* camera);
    void (*updateSlide)(CameraObject* camera, GameObject* target, f32 upperBound, f32 lowerBound);
    void (*getSettings)(f32* minDistance, f32* maxDistance, f32* lowerHeightOffset, f32* upperHeightOffset,
                        f32* targetHeight);
    void (*updateVerticalBounds)(CameraObject* camera, int flags, int collisionFlag, f32* upperBound, f32* lowerBound);
} CameraModeNormalDescriptor;

STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, metadata) == 0x00);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, reserved18) == 0x18);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, init) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, update) == 0x20);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, free) == 0x24);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, copyToCurrent) == 0x28);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, follow) == 0x2C);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, updatePitch) == 0x30);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, updateSlide) == 0x34);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, getSettings) == 0x38);
STATIC_ASSERT(offsetof(CameraModeNormalDescriptor, updateVerticalBounds) == 0x3C);
STATIC_ASSERT(sizeof(CameraModeNormalDescriptor) == 0x40);

extern CameraModeNormalState* gCameraModeNormalState;
extern CameraModeNormalDescriptor gCameraModeNormalDescriptor;

int camcontrol_traceMove(f32* fromPos, f32* toPos, f32* outPos, TrackHitResults* traceWork, char traceMode, u8 runTrace,
                         u8 runBbox, f32 radius);
u8 camcontrol_traceFromTarget(f32* fromPos, GameObject* target, f32* outPos, void* unused);
u8 camcontrol_getTargetPosition(CameraObject* camera, ObjAnimComponent* targetAnim, f32* outPos, s16* outRotY);
void camcontrol_onTargetTraceBlocked(int unused);
void CameraModeNormal_updateTargetAction(CameraObject* camera, GameObject* target);
int CameraModeNormal_chooseWallAvoidanceDirection(CameraObject* camera, f32* outA, f32* outB, int angle);
void CameraModeNormal_updateWallAvoidance(CameraObject* camera, GameObject* target);
void CameraModeNormal_updateSettings(CameraObject* camera);
void CameraModeNormal_updateVerticalBounds(CameraObject* camera, int flags, int collisionFlag, f32* upperBound,
                                           f32* lowerBound);
void CameraModeNormal_getSettings(f32* minDistance, f32* maxDistance, f32* lowerHeightOffset, f32* upperHeightOffset,
                                  f32* targetHeight);
void CameraModeNormal_updateSlide(CameraObject* camera, GameObject* target, f32 upperBound, f32 lowerBound);
void CameraModeNormal_updatePitch(f32 targetY, f32 distance, CameraObject* camera);
void CameraModeNormal_follow(CameraObject* camera, ObjAnimComponent* target);
void CameraModeNormal_copyToCurrent(CameraModeNormalActionSettings* settings);
void CameraModeNormal_free(CameraObject* camera);
void CameraModeNormal_update(CameraObject* camera);
void CameraModeNormal_init(CameraObject* camera, int mode, CameraModeNormalInitSettings* settings);
void CameraModeNormal_release(void);
void CameraModeNormal_initialise(void);

#endif /* MAIN_DLL_DLL_0042_CAMERAMODENORMAL_H_ */
