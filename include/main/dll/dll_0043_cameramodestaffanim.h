#ifndef MAIN_DLL_DLL_0043_CAMERAMODESTAFFANIM_H_
#define MAIN_DLL_DLL_0043_CAMERAMODESTAFFANIM_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/camera_object.h"
#include "main/curve.h"
#include "main/resource.h"

enum CameraModeStaffAnimResourceId {
    CAMERA_MODE_STAFF_ANIM_RESOURCE_ID = 0x43,
};

enum CameraModeStaffAnimPathCapacity {
    CAMERA_MODE_STAFF_ANIM_PATH_POINT_CAPACITY = 20,
};

typedef struct CameraModeStaffAnimSettings {
    s16 approachThresholdDegrees;
    u8 turnGate;
    u8 snapToTarget;
} CameraModeStaffAnimSettings;

STATIC_ASSERT(offsetof(CameraModeStaffAnimSettings, approachThresholdDegrees) == 0x00);
STATIC_ASSERT(offsetof(CameraModeStaffAnimSettings, turnGate) == 0x02);
STATIC_ASSERT(offsetof(CameraModeStaffAnimSettings, snapToTarget) == 0x03);
STATIC_ASSERT(sizeof(CameraModeStaffAnimSettings) == 0x04);

typedef struct CameraModeStaffAnimState {
    GameObject* localFrame;
    f32 minDistance;
    f32 maxDistance;
    f32 lowerHeightOffset;
    f32 targetHeight;
    f32 floorHeight;
    f32 ceilingHeight;
    f32 pointsX[CAMERA_MODE_STAFF_ANIM_PATH_POINT_CAPACITY];
    f32 pointsY[CAMERA_MODE_STAFF_ANIM_PATH_POINT_CAPACITY];
    f32 pointsZ[CAMERA_MODE_STAFF_ANIM_PATH_POINT_CAPACITY];
    f32 pathSpeedCurve[4];
    f32 collisionTime;
    Curve pathCurve;
    u8 pathNotNeeded;
    u8 pad1BD[3];
} CameraModeStaffAnimState;

STATIC_ASSERT(offsetof(CameraModeStaffAnimState, localFrame) == 0x000);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, minDistance) == 0x004);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, maxDistance) == 0x008);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, lowerHeightOffset) == 0x00C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, targetHeight) == 0x010);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, floorHeight) == 0x014);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, ceilingHeight) == 0x018);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pointsX) == 0x01C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pointsY) == 0x06C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pointsZ) == 0x0BC);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathSpeedCurve) == 0x10C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, collisionTime) == 0x11C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve) == 0x120);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve.dir) == 0x1A0);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve.px) == 0x1A4);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve.count) == 0x1B0);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve.eval) == 0x1B4);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathCurve.coeffFn) == 0x1B8);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pathNotNeeded) == 0x1BC);
STATIC_ASSERT(offsetof(CameraModeStaffAnimState, pad1BD) == 0x1BD);
STATIC_ASSERT(sizeof(CameraModeStaffAnimState) == 0x1C0);

typedef struct CameraModeStaffAnimDescriptor {
    u32 metadata[4];
    void (*initialise)(void);
    void (*release)(void);
    ResourceDescriptorCallback reserved18;
    void (*init)(CameraObject* camera, int unused, CameraModeStaffAnimSettings* settings);
    void (*update)(CameraObject* camera);
    void (*free)(void);
    void (*copyToCurrent)(void);
    ResourceDescriptorCallback reserved2C;
} CameraModeStaffAnimDescriptor;

STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, metadata) == 0x00);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, reserved18) == 0x18);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, init) == 0x1C);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, update) == 0x20);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, free) == 0x24);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, copyToCurrent) == 0x28);
STATIC_ASSERT(offsetof(CameraModeStaffAnimDescriptor, reserved2C) == 0x2C);
STATIC_ASSERT(sizeof(CameraModeStaffAnimDescriptor) == 0x30);

extern CameraModeStaffAnimState* gCameraModeStaffAnimState;
extern CameraModeStaffAnimDescriptor gCameraModeStaffAnimDescriptor;

int CameraModeStaffAnim_samplePath(f32* outX, f32* height, f32* outZ, GameObject* target, CameraObject* camera);
void CameraModeStaffAnim_subdividePathAngles(s16* outAngles, u16* outCount, s16 baseAngle, s16 deltaAngle, s16 limit);
void CameraModeStaffAnim_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 baseY, f32 targetZ, f32 targetY,
                                         s16 angleRange, s16 angleLimit, int* outPointCount);
void CameraModeStaffAnim_updateTargetAction(CameraObject* camera, GameObject* target);
void CameraModeStaffAnim_copyToCurrent(void);
void CameraModeStaffAnim_free(void);
void CameraModeStaffAnim_update(CameraObject* camera);
void CameraModeStaffAnim_init(CameraObject* camera, int unused, CameraModeStaffAnimSettings* settings);
void CameraModeStaffAnim_release(void);
void CameraModeStaffAnim_initialise(void);

#endif /* MAIN_DLL_DLL_0043_CAMERAMODESTAFFANIM_H_ */
