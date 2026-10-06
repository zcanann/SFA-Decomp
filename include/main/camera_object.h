#ifndef MAIN_CAMERA_OBJECT_H_
#define MAIN_CAMERA_OBJECT_H_

#include "game/objects/object_fwd.h"
#include "global.h"
#include "main/dll/DR/dr_types.h"
#include "main/objanim_internal.h"
#include "main/track_hit_results.h"

/* The shared transform prefix stops before camera-owned collision storage.
 * It is not an ObjAnimComponent: animation and model fields do not follow it. */
typedef struct CameraTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    union {
        struct {
            f32 localPosX;
            f32 localPosY;
            f32 localPosZ;
        };
        Vec3f localPos;
    };
    union {
        struct {
            f32 worldPosX;
            f32 worldPosY;
            f32 worldPosZ;
        };
        Vec3f worldPos;
    };
    u8 unknown24[0x0C];
    GameObject* parent;
} CameraTransform;

STATIC_ASSERT(sizeof(CameraTransform) == 0x34);
STATIC_ASSERT(offsetof(CameraTransform, localPos) == 0x0C);
STATIC_ASSERT(offsetof(CameraTransform, worldPos) == 0x18);
STATIC_ASSERT(offsetof(CameraTransform, parent) == 0x30);

/* Live and temporary camera state. Camera_initialise clears 0x144 bytes;
 * the normal/staff camera stack records independently establish this size.
 * GameObject shares only the transform prefix, not this record's tail. */
typedef struct CameraObject {
    union {
        CameraTransform anim;
        struct {
            s16 yaw;
            s16 pitch;
            s16 roll;
            s16 transformFlags;
            f32 scale;
            f32 localX;
            f32 localY;
            f32 localZ;
            union {
                struct {
                    f32 worldX;
                    f32 worldY;
                    f32 worldZ;
                };
                f32 worldPosition[3];
            };
            u8 unknown24[0x0C];
            GameObject* localFrameObj;
        };
    };
    TrackHitResults collisionResults;
    /* Camera control uses the animation component; modes use its owning object. */
    union {
        ObjAnimComponent* focusObj;
        GameObject* focusObject;
    };
    union {
        struct {
            f32 prevLocalX;
            f32 prevLocalY;
            f32 prevLocalZ;
        };
        Vec3f savedLocalPos;
    };
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
    f32 boundHitZLower;
    f32 boundHitZUpper;
    f32 targetDistance;
    u8 targetKind;
    u8 blendCurveMode;
    u8 pad13A;
    s8 letterboxTargetOffset;
    s8 letterboxStep;
    u8 overrideWorldPosPending;
    u8 unk13E;
    u8 queuedBlendFlags;
    u8 frameFlags;
    u8 targetFlags;
    u8 cameraCollisionActive;
    BitFlags8 smoothingFlags;
} CameraObject;

STATIC_ASSERT(sizeof(CameraObject) == 0x144);
STATIC_ASSERT(offsetof(CameraObject, yaw) == 0x00);
STATIC_ASSERT(offsetof(CameraObject, localX) == 0x0C);
STATIC_ASSERT(offsetof(CameraObject, worldX) == 0x18);
STATIC_ASSERT(offsetof(CameraObject, worldPosition) == 0x18);
STATIC_ASSERT(offsetof(CameraObject, localFrameObj) == 0x30);
STATIC_ASSERT(offsetof(CameraObject, focusObj) == 0xA4);
STATIC_ASSERT(offsetof(CameraObject, prevLocalX) == 0xA8);
STATIC_ASSERT(offsetof(CameraObject, fovY) == 0xB4);
STATIC_ASSERT(offsetof(CameraObject, prevWorldX) == 0xB8);
STATIC_ASSERT(offsetof(CameraObject, focusMoveAverage) == 0xC4);
STATIC_ASSERT(offsetof(CameraObject, focusMoveHistory) == 0xC8);
STATIC_ASSERT(offsetof(CameraObject, overrideWorldX) == 0xDC);
STATIC_ASSERT(offsetof(CameraObject, blendProgress) == 0xF4);
STATIC_ASSERT(offsetof(CameraObject, blendDeltaYaw) == 0x100);
STATIC_ASSERT(offsetof(CameraObject, blendStartYaw) == 0x106);
STATIC_ASSERT(offsetof(CameraObject, blendStartX) == 0x10C);
STATIC_ASSERT(offsetof(CameraObject, blendStartFovY) == 0x118);
STATIC_ASSERT(offsetof(CameraObject, overrideTarget) == 0x11C);
STATIC_ASSERT(offsetof(CameraObject, targetReticleOverride) == 0x120);
STATIC_ASSERT(offsetof(CameraObject, currentTarget) == 0x124);
STATIC_ASSERT(offsetof(CameraObject, targetReticleFocus) == 0x128);
STATIC_ASSERT(offsetof(CameraObject, targetDistance) == 0x134);
STATIC_ASSERT(offsetof(CameraObject, targetKind) == 0x138);
STATIC_ASSERT(offsetof(CameraObject, blendCurveMode) == 0x139);
STATIC_ASSERT(offsetof(CameraObject, letterboxTargetOffset) == 0x13B);
STATIC_ASSERT(offsetof(CameraObject, overrideWorldPosPending) == 0x13D);
STATIC_ASSERT(offsetof(CameraObject, queuedBlendFlags) == 0x13F);
STATIC_ASSERT(offsetof(CameraObject, frameFlags) == 0x140);
STATIC_ASSERT(offsetof(CameraObject, targetFlags) == 0x141);
STATIC_ASSERT(offsetof(CameraObject, smoothingFlags) == 0x143);

STATIC_ASSERT(offsetof(CameraObject, collisionResults) == 0x34);
STATIC_ASSERT(offsetof(CameraObject, collisionResults.radii) == 0x74);
STATIC_ASSERT(offsetof(CameraObject, collisionResults.surfaceTypes) == 0x84);
STATIC_ASSERT(offsetof(CameraObject, collisionResults.queryTypes) == 0x88);
STATIC_ASSERT(offsetof(CameraObject, collisionResults.hitCount) == 0xA0);
STATIC_ASSERT(offsetof(CameraObject, collisionResults.hitMask) == 0xA2);
STATIC_ASSERT(offsetof(CameraObject, focusObject) == 0xA4);
STATIC_ASSERT(offsetof(CameraObject, savedLocalPos) == 0xA8);
STATIC_ASSERT(offsetof(CameraObject, boundHitZLower) == 0x12C);
STATIC_ASSERT(offsetof(CameraObject, boundHitZUpper) == 0x130);
STATIC_ASSERT(offsetof(CameraObject, cameraCollisionActive) == 0x142);

#endif /* MAIN_CAMERA_OBJECT_H_ */
