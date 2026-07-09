#ifndef MAIN_CAMERA_OBJECT_H_
#define MAIN_CAMERA_OBJECT_H_

#include "global.h"
#include "main/objanim_internal.h"

/*
 * CameraObject - the camera's object record, passed around the CAM/
 * mode handlers as "cam" (short* / u8* / int spellings). It shares the
 * ObjAnimComponent head (0x00..0xAF) and the u16 word at 0xB0 with
 * GameObject, but it is a SIBLING of GameObject, NOT a view of it:
 * the tails DIVERGE at 0xB4. Never cast CameraObject* <-> GameObject*.
 *  - 0xB4: f32 fov here (11 CAM sites; dll_5B's zoom/fovTarget locals)
 *    vs s16 unkB4 on GameObject (anim.c/baddieControl/objseq).
 *  - 0xB8: f32 probePos[0] here - initialized from worldPosX
 *    (camcontrol.c:864) and passed as a float* vec3 into the
 *    swept-sphere queries (attention.c -> objBboxFn_800640cc /
 *    hitDetect_calcSweptSphereBounds) - vs the per-class extra-state
 *    POINTER on GameObject. Cameras carry no extra-state block.
 * Shared-head evidence: camera.c walks anim.parent (0x30), reads
 * rootMotionScale/localPos, and tests the 0xB0 u16 flags - identical
 * to GameObject through 0xB3.
 *
 * The camera's focus/track targets are REGULAR GameObjects: the
 * pointer at +0xA4 (inside the ObjAnimComponent pad - also seen on
 * baddieControl objects, so possibly an all-object field; kept raw
 * here pending an ObjAnimComponent field ruling) and the pointer at
 * +0x11C both load GameObject*.
 *
 * Field widths mirror the CAM/*.c deref census; unobserved ranges are
 * padded. The record extends at least to 0x14C; total size unverified -
 * do not take sizeof(CameraObject) or index arrays of it.
 */
typedef struct CameraObject {
    ObjAnimComponent anim;
    u16 objectFlags; /* 0xB0 GameObject flag word (camera.c tests bit 8 via GameObject cast) */
    u8 padB2[2];
    f32 fov;
    f32 probePosX; /* swept-collision anchor, seeded from anim.worldPos */
    f32 probePosY;
    f32 probePosZ;
    f32 unkC4;
    u8 padC8[0xE4 - 0xC8];
    u8 unkE4;
    u8 padE5[0xF4 - 0xE5];
    f32 blendProgress;
    u8 padF8[0x11C - 0xF8];
    void *targetObj; /* GameObject*: current focus/track target */
    u8 pad120[4];
    void *currentTarget;
    u8 pad128[4];
    f32 boundHitZLower; /* 0x12C: Z of the nearest below-camera vertical-bound collision hit (hits[i][2]); reset with boundHitZUpper */
    f32 boundHitZUpper; /* 0x130: Z of the nearest above-camera vertical-bound collision hit (hits[i][2]) */
    u8 pad134[0x13B - 0x134];
    s8 letterboxTargetOffset;
    s8 letterboxStep;
    u8 pad13D;
    u8 unk13E;
    u8 pad13F[2];
    u8 targetFlags;
    u8 cameraCollisionActive;
    u8 smoothingFlags;
    u8 pad144[0x148 - 0x144];
    int unk148;
} CameraObject;

STATIC_ASSERT(offsetof(CameraObject, fov) == 0xB4);
STATIC_ASSERT(offsetof(CameraObject, probePosX) == 0xB8);
STATIC_ASSERT(offsetof(CameraObject, blendProgress) == 0xF4);
STATIC_ASSERT(offsetof(CameraObject, targetObj) == 0x11C);
STATIC_ASSERT(offsetof(CameraObject, currentTarget) == 0x124);
STATIC_ASSERT(offsetof(CameraObject, letterboxTargetOffset) == 0x13B);
STATIC_ASSERT(offsetof(CameraObject, targetFlags) == 0x141);
STATIC_ASSERT(offsetof(CameraObject, cameraCollisionActive) == 0x142);
STATIC_ASSERT(offsetof(CameraObject, smoothingFlags) == 0x143);
STATIC_ASSERT(offsetof(CameraObject, unk148) == 0x148);

#endif /* MAIN_CAMERA_OBJECT_H_ */
