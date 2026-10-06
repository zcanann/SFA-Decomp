/*
 * DLL 66 / 0x42 - normal camera mode and shared camera trace helpers.
 */
#include "main/dll/dll_0042_cameramodenormal.h"

#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/os.h"
#include "dolphin/os/OSTime.h"
#include "dolphin/pad.h"
#include "main/camera_interface.h"
#include "main/curve.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0043_cameramodestaffanim.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/objseq_api.h"
#include "main/pad.h"
#include "string.h"

typedef struct CameraModeNormalSlideTransform {
    s16 angles[3];
    s16 pad06;
    f32 scale;
    Vec3f translation;
} CameraModeNormalSlideTransform;

STATIC_ASSERT(offsetof(CameraModeNormalSlideTransform, angles) == 0x00);
STATIC_ASSERT(offsetof(CameraModeNormalSlideTransform, pad06) == 0x06);
STATIC_ASSERT(offsetof(CameraModeNormalSlideTransform, scale) == 0x08);
STATIC_ASSERT(offsetof(CameraModeNormalSlideTransform, translation) == 0x0C);
STATIC_ASSERT(sizeof(CameraModeNormalSlideTransform) == 0x18);

int lbl_803DD534;
CameraModeNormalState* gCameraModeNormalState;
f32 gCameraModeNormalScaledTimeDelta;
u8 gCamcontrolTraceBboxBlocked;

int camcontrol_traceMove(f32* fromPos, f32* toPos, f32* outPos, TrackHitResults* traceWork, char traceMode, u8 runTrace,
                         u8 runBbox, f32 radius) {
    u8 blocked;
    int clear;
    f32 endTmp[3];
    TrackQueryBounds sweptBounds;

    if (outPos == NULL) {
        outPos = endTmp;
    }
    *outPos = *toPos;
    outPos[1] = toPos[1];
    outPos[2] = toPos[2];
    traceWork->radii[0] = radius;
    traceWork->surfaceTypes[0] = -1;
    traceWork->queryTypes[0] = traceMode;
    traceWork->hitCount = 0;
    blocked = 0;
    if (runBbox != 0) {
        blocked = trackGetLineIntersect(fromPos, outPos, radius, 1, NULL, NULL, 0x10, 0xffffffff, 0xff, 0);
    } else {
        blocked = 0;
    }
    gCamcontrolTraceBboxBlocked = blocked;
    if (runTrace != 0) {
        hitDetect_calcSweptSphereBounds(&sweptBounds, fromPos, outPos, traceWork->radii, 1);
        trackIntersectBroadphase(NULL, &sweptBounds, 0x240, 1);
    }
    trackGetIntersect(NULL, fromPos, outPos, 1, traceWork, 0);
    clear = 0;
    if ((gCamcontrolTraceBboxBlocked == 0) && (traceWork->hitCount == 0)) {
        clear = 1;
    }
    return clear;
}
void camcontrol_onTargetTraceBlocked(int unused) {
}

u8 camcontrol_traceFromTarget(float* fromPos, GameObject* target, float* outPos, void* unused) {
    float targetPos[3];
    TrackHitResults traceRec;

    if (target->anim.classId == 1) {
        cameraGetPrevPos2(target, &targetPos[0], &targetPos[1], &targetPos[2]);
    } else {
        targetPos[0] = target->anim.worldPosX;
        targetPos[1] = target->anim.worldPosY + gCameraModeNormalState->targetHeight;
        targetPos[2] = target->anim.worldPosZ;
    }
    camcontrol_traceMove(targetPos, fromPos, outPos, &traceRec, 3, '\x01', '\x01', (double)4.0f);
    return traceRec.hitMask;
}

u8 camcontrol_getTargetPosition(CameraObject* camera, ObjAnimComponent* targetAnim, f32* outPos, s16* outRotY) {
    TrackHitResults box;
    float prev[3];
    float pos[3];
    f32 d2;
    f32 a;
    f32 b;
    f32 c;
    f32 cosv;
    f32 sinv;
    u32 ang;
    int angleDelta;

    cosv = mathSinf((3.1415927f * targetAnim->rotX) / 32768.0f);
    sinv = mathCosf((3.1415927f * targetAnim->rotX) / 32768.0f);
    d2 = gCameraModeNormalState->maxDistance * gCameraModeNormalState->maxDistance -
         gCameraModeNormalState->lowerHeightOffset * gCameraModeNormalState->lowerHeightOffset;
    if (d2 < 5.0f) {
        d2 = 5.0f;
    }
    d2 = sqrtf(d2);
    pos[0] = cosv * d2 + targetAnim->worldPosX;
    pos[1] = gCameraModeNormalState->lowerHeightOffset + (targetAnim->worldPosY + gCameraModeNormalState->targetHeight);
    pos[2] = sinv * d2 + targetAnim->worldPosZ;
    if (targetAnim->classId == 1) {
        cameraGetPrevPos2((GameObject*)targetAnim, &prev[0], &prev[1], &prev[2]);
    } else {
        prev[0] = targetAnim->worldPosX;
        prev[1] = targetAnim->worldPosY + gCameraModeNormalState->targetHeight;
        prev[2] = targetAnim->worldPosZ;
    }
    camcontrol_traceMove(prev, pos, outPos, &box, 3, '\x01', '\x01', 4.0f);
    (*gCameraInterface)->getRelativePosition(camera, &a, &b, &c, &d2, gCameraModeNormalState->targetHeight, 0);
    b = camera->anim.worldPosY - (targetAnim->worldPosY + gCameraModeNormalState->targetHeight);
    ang = getAngle(b, d2);
    angleDelta = ang & 0xffff;
    angleDelta -= (u16)camera->anim.rotY;
    if (angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    if (outRotY != NULL) {
        *outRotY = camera->anim.rotY + angleDelta;
    }
    return box.hitMask;
}

void CameraModeNormal_updateTargetAction(CameraObject* camera, GameObject* target) {
    short classId;
    u16 buttons;
    int cond;
    CameraModeStaffAnimSettings staffAnimSettings;
    CameraModeViewfinderSettings viewfinderSettings;

    if (target->pendingParentObj == NULL) {
        buttons = getButtonsJustPressed(0);
        if (((camera->currentTarget != NULL) &&
             (((classId = ((GameObject*)camera->currentTarget)->anim.classId) == 0x1c) || (classId == 0x2a)) &&
             (target->anim.classId == 1) && ((cond = playerIsStaffActionPending(target)) != 0) &&
             ((cond = playerCanEnterStaffCombatCamera(target)) != 0)) ||
            ((camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) != 0)) {
            Camera_setBlendCurveMode(1);
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_COMBAT_RESOURCE_ID, 1, 0, sizeof(camera->currentTarget), &camera->currentTarget,
                          0x3c, 0xff);
        } else if ((((buttons & PAD_TRIGGER_Z) != 0) && (target->anim.classId == 1)) &&
                   (cond = playerIsInNormalControl(target), cond != 0)) {
            viewfinderSettings.radius = gCameraModeNormalState->minDistance;
            viewfinderSettings.yOffset = gCameraModeNormalState->lowerHeightOffset;
            viewfinderSettings.height = gCameraModeNormalState->targetHeight;
            Camera_setBlendCurveMode(0);
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 1, 0, sizeof(CameraModeViewfinderSettings),
                          &viewfinderSettings, 0xf, 0xfe);
        } else {
            cond = getCurSeqNo();
            if (((cond == 0) && (buttons = padGetTriggersPressed(0), (buttons & PAD_TRIGGER_L) != 0)) &&
                ((camera->anim.flags & 4) == 0)) {
                staffAnimSettings.approachThresholdDegrees = 5;
                staffAnimSettings.turnGate = 1;
                staffAnimSettings.snapToTarget = 1;
                (*gCameraInterface)
                    ->setMode(CAMERA_MODE_STAFF_ANIM_RESOURCE_ID, 1, 0, sizeof(CameraModeStaffAnimSettings),
                              &staffAnimSettings, 0, 0xff);
            }
        }
    }
}

int CameraModeNormal_chooseWallAvoidanceDirection(CameraObject* cam, f32* outA, f32* outB, int angle) {
    GameObject* initialTarget;
    CameraObject probeCamera;
    TrackHitResults traceWork;
    float positivePath[21];
    float negativePath[21];
    float prev[3];
    f32 distanceXZ;
    f32 relativeX;
    f32 relativeY;
    f32 relativeZ;
    GameObject* target;
    int positiveAngle;
    float* positivePoint;
    float* negativePoint;
    float* probePosition;
    float* positiveSegment;
    float* negativeSegment;
    int result;
    int degrees;
    int i;
    int positiveClearStep;
    int negativeClearStep;
    int dir;
    int d;
    f32 sinAngle;
    f32 rad;
    f32 offsetZ;
    f32 offsetX;
    f32 cosAngle;
    f32 rotatedX;
    f32 rotatedZ;

    OSGetTick(); /* timing probe; return value intentionally unused */
    result = 0;
    (*gCameraInterface)
        ->getRelativePosition(cam, &relativeX, &relativeY, &relativeZ, &distanceXZ,
                              gCameraModeNormalState->targetHeight, 0);
    initialTarget = cam->focusObject;
    probeCamera.focusObj = &initialTarget->anim;
    probeCamera.worldPosition[1] = cam->anim.worldPosY;
    positivePath[0] = cam->anim.worldPosX;
    positivePath[1] = cam->anim.worldPosY;
    positivePath[2] = cam->anim.worldPosZ;
    negativePath[0] = positivePath[0];
    negativePath[1] = positivePath[1];
    negativePath[2] = positivePath[2];
    if (initialTarget->anim.classId == 1) {
        cameraGetPrevPos2(initialTarget, &prev[0], &prev[1], &prev[2]);
    } else {
        prev[0] = initialTarget->anim.worldPosX;
        prev[1] = initialTarget->anim.worldPosY + gCameraModeNormalState->targetHeight;
        prev[2] = initialTarget->anim.worldPosZ;
    }
    degrees = 0xf;
    i = 0;
    positiveClearStep = -1;
    negativeClearStep = -1;
    positiveAngle = 0xaaa;
    positiveSegment = positivePath;
    positivePoint = positiveSegment;
    negativeSegment = negativePath;
    negativePoint = negativeSegment;
    probePosition = probeCamera.worldPosition;
    while ((s16)degrees <= 0x5a) {
        if (positiveClearStep == -1) {
            offsetZ = relativeZ;
            offsetX = relativeX;
            target = cam->focusObject;
            rad = (3.1415927f * (f32)(s16)positiveAngle) / 32768.0f;
            sinAngle = mathSinf(rad);
            cosAngle = mathCosf(rad);
            rotatedX = offsetX * cosAngle - offsetZ * sinAngle;
            rotatedZ = rotatedX * sinAngle + offsetZ * cosAngle;
            rotatedX += target->anim.worldPosX;
            probePosition[0] = rotatedX;
            rotatedZ += target->anim.worldPosZ;
            probePosition[2] = rotatedZ;
            positivePoint[3] = probePosition[0];
            positivePoint[4] = probePosition[1];
            positivePoint[5] = probePosition[2];
            if (camcontrol_traceMove(prev, probePosition, NULL, &traceWork, 7, '\0', '\0', 3.9f) != 0) {
                positiveClearStep = i;
            }
        }
        if (negativeClearStep == -1) {
            offsetZ = relativeZ;
            offsetX = relativeX;
            target = cam->focusObject;
            rad = (3.1415927f * (f32)(s16)(-degrees * 0xb6)) / 32768.0f;
            sinAngle = mathSinf(rad);
            cosAngle = mathCosf(rad);
            rotatedX = offsetX * cosAngle - offsetZ * sinAngle;
            rotatedZ = rotatedX * sinAngle + offsetZ * cosAngle;
            rotatedX += target->anim.worldPosX;
            probePosition[0] = rotatedX;
            rotatedZ += target->anim.worldPosZ;
            probePosition[2] = rotatedZ;
            negativePoint[3] = probePosition[0];
            negativePoint[4] = probePosition[1];
            negativePoint[5] = probePosition[2];
            if (camcontrol_traceMove(prev, probePosition, NULL, &traceWork, 7, '\0', '\0', 3.9f) != 0) {
                negativeClearStep = i;
            }
        }
        positivePoint += 3;
        negativePoint += 3;
        i++;
        positiveAngle += 0xaaa;
        degrees += 0xf;
    }
    if (positiveClearStep == -1) {
        positiveClearStep = 6;
    } else {
        for (i = 0; i <= positiveClearStep; i++) {
            if (camcontrol_traceMove(positiveSegment, positivePath + (i + 1) * 3, NULL, &traceWork, 7, '\0', '\0',
                                     3.9f) == 0) {
                positiveClearStep = 6;
                break;
            }
            positiveSegment += 3;
        }
    }
    if (negativeClearStep == -1) {
        negativeClearStep = 6;
    } else {
        for (i = 0; i <= negativeClearStep; i++) {
            if (camcontrol_traceMove(negativeSegment, negativePath + (i + 1) * 3, NULL, &traceWork, 7, '\0', '\0',
                                     3.9f) == 0) {
                negativeClearStep = 6;
                break;
            }
            negativeSegment += 3;
        }
    }
    dir = 0;
    if (positiveClearStep < negativeClearStep) {
        dir = 1;
    } else if (negativeClearStep < positiveClearStep) {
        dir = -1;
    } else if (positiveClearStep < 6) {
        dir = 1;
    }
    if (dir != 0) {
        f32 f;
        f32 g;
        d = (0x8000 - cam->anim.rotX) - (angle & 0xffff);
        if (d > 0x8000) {
            d -= 0xffff;
        }
        if (d < -0x8000) {
            d += 0xffff;
        }
        if (d < 0) {
            d = -d;
        }
        f = cam->focusMoveAverage * cam->focusMoveAverage;
        if (f < 1.0f) {
            f = 1.0f;
        }
        f *= 3.0f;
        g = 0.0f;
        g += f;
        g = g + d / 500.0f;
        if (g < 10.0f) {
            g = 10.0f;
        }
        if (g > 100.0f) {
            g = 100.0f;
        }
        if (dir == -1) {
            g = -g;
        }
        g = g * gCameraModeNormalScaledTimeDelta + gCameraModeNormalState->avoidanceYawOffset;
        if (g > 1000.0f) {
            g = 1000.0f;
        } else if (g < -1000.0f) {
            g = -1000.0f;
        }
        gCameraModeNormalState->avoidanceYawOffset = g;
        result = 1;
    }
    return result;
}

void CameraModeNormal_updateWallAvoidance(CameraObject* camera, GameObject* target) {
    float path[39];
    float endPts[13][3];
    TrackHitResults box;
    float radii[13];
    TrackQueryBounds bounds;
    float prev[3];
    f32 outB[2];
    f32 outA[2];
    int ang;
    float* p;
    int i;
    int j;
    f32 dx;
    f32 dz;
    f32 rad;
    f32 sinv;
    f32 cosv;
    f32 t;
    f32 z;
    u32 blocked;
    u8 trace;
    s16 spin;

    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY, camera->anim.localPosZ,
                                   &camera->anim.worldPosX, &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   camera->anim.parent);
    gCamcontrolTraceBboxBlocked = 0;
    if (target->anim.classId == 1) {
        cameraGetPrevPos2(target, &prev[0], &prev[1], &prev[2]);
    } else {
        prev[0] = target->anim.worldPosX;
        prev[1] = target->anim.worldPosY + gCameraModeNormalState->targetHeight;
        prev[2] = target->anim.worldPosZ;
    }
    path[0] = camera->anim.worldPosX;
    path[1] = camera->anim.worldPosY;
    path[2] = camera->anim.worldPosZ;
    dx = path[0] - prev[0];
    dz = path[2] - prev[2];
    i = 1;
    ang = 0xaaa;
    p = path + 3;
    while (i <= 0xc) {
        rad = (3.1415927f * (f32)(s16)ang) / 32768.0f;
        cosv = mathSinf(rad);
        sinv = mathCosf(rad);
        t = dx * sinv - dz * cosv;
        z = t * cosv + dz * sinv;
        z += target->anim.worldPosZ;
        p[0] = t + target->anim.worldPosX;
        p[1] = camera->anim.worldPosY;
        p[2] = z;
        rad = (3.1415927f * (f32)(s16)(-i * 0xaaa)) / 32768.0f;
        cosv = mathSinf(rad);
        sinv = mathCosf(rad);
        t = dx * sinv - dz * cosv;
        z = t * cosv + dz * sinv;
        z += target->anim.worldPosZ;
        p[3] = t + target->anim.worldPosX;
        p[4] = camera->anim.worldPosY;
        p[5] = z;
        ang += 0x1554;
        p += 6;
        i += 2;
    }
    for (j = 0; j <= 0xc; j++) {
        endPts[j][0] = prev[0];
        endPts[j][1] = prev[1];
        endPts[j][2] = prev[2];
        radii[j] = 3.9f;
    }
    hitDetect_calcSweptSphereBounds(&bounds, (float*)path, (float*)endPts, radii, 0xd);
    trackIntersectBroadphase(NULL, &bounds, 0x248, 1);
    trace = camcontrol_traceMove(prev, &camera->anim.worldPosX, NULL, &box, 7, '\0', '\0', 3.9f);
    blocked = 0;
    if (trace == 0) {
        blocked = 1;
    }
    trace = blocked; /* reused u8 temp: narrowed copy of the blocked flag */
    gCameraModeNormalState->collisionBlocked = trace;
    if (trace != 0) {
        gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        if (CameraModeNormal_chooseWallAvoidanceDirection(camera, outA, outB, target->anim.rotX) == 0) {
            gCameraModeNormalState->avoidanceYawOffset = 0.0f;
        }
    }
    if (gCameraModeNormalState->avoidanceYawOffset != 0.0f) {
        spin = (s16)(int)gCameraModeNormalState->avoidanceYawOffset;
        if ((spin < -0x1e) || (spin > 0x1e)) {
            f32 rad;

            rad = (3.1415927f * spin) / 32768.0f;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dx * sinv - dz * cosv;
            camera->anim.worldPosX = t + target->anim.worldPosX;
            z = t * cosv + dz * sinv;
            camera->anim.worldPosZ = z + target->anim.worldPosZ;
        }
        gCameraModeNormalState->avoidanceYawOffset *= 0.9f;
        if ((gCameraModeNormalState->avoidanceYawOffset < 0.5f) &&
            (gCameraModeNormalState->avoidanceYawOffset > -0.5f)) {
            gCameraModeNormalState->avoidanceYawOffset = 0.0f;
        }
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   camera->anim.parent);
}

void CameraModeNormal_updateSettings(CameraObject* camera) {
    f32 blend;
    f32 ratio;
    float curve[4];

    if (gCameraModeNormalState->transitionTimer != 0) {
        gCameraModeNormalState->transitionTimer -= framesThisStep;
        if (gCameraModeNormalState->transitionTimer < 0) {
            gCameraModeNormalState->transitionTimer = 0;
        }
        ratio = (f32)(gCameraModeNormalState->transitionDuration - gCameraModeNormalState->transitionTimer) /
                (f32)(s32)gCameraModeNormalState->transitionDuration;
        curve[0] = 0.0f;
        curve[1] = 1.0f;
        curve[2] = 0.0f;
        curve[3] = 0.0f;
        blend = Curve_EvalHermite(curve, ratio, NULL);
        gCameraModeNormalState->targetHeight =
            blend * (gCameraModeNormalState->targetTargetHeight - gCameraModeNormalState->savedTargetHeight) +
            gCameraModeNormalState->savedTargetHeight;
        gCameraModeNormalState->minDistance =
            blend * (gCameraModeNormalState->targetMinDistance - gCameraModeNormalState->savedMinDistance) +
            gCameraModeNormalState->savedMinDistance;
        gCameraModeNormalState->maxDistance =
            blend * (gCameraModeNormalState->targetMaxDistance - gCameraModeNormalState->savedMaxDistance) +
            gCameraModeNormalState->savedMaxDistance;
        gCameraModeNormalState->lowerHeightOffset =
            blend * (gCameraModeNormalState->targetLowerHeightOffset - gCameraModeNormalState->savedLowerHeightOffset) +
            gCameraModeNormalState->savedLowerHeightOffset;
        gCameraModeNormalState->upperHeightOffset =
            blend * (gCameraModeNormalState->targetUpperHeightOffset - gCameraModeNormalState->savedUpperHeightOffset) +
            gCameraModeNormalState->savedUpperHeightOffset;
        gCameraModeNormalState->distanceAdjustRate = blend * (gCameraModeNormalState->targetDistanceAdjustRate -
                                                              gCameraModeNormalState->savedDistanceAdjustRate) +
                                                     gCameraModeNormalState->savedDistanceAdjustRate;
        gCameraModeNormalState->heightAdjustRate =
            blend * (gCameraModeNormalState->targetHeightAdjustRate - gCameraModeNormalState->savedHeightAdjustRate) +
            gCameraModeNormalState->savedHeightAdjustRate;
        gCameraModeNormalState->slideRightAmount =
            blend * (gCameraModeNormalState->targetSlideRightAmount - gCameraModeNormalState->savedSlideRightAmount) +
            gCameraModeNormalState->savedSlideRightAmount;
        gCameraModeNormalState->slideLeftAmount =
            blend * (gCameraModeNormalState->targetSlideLeftAmount - gCameraModeNormalState->savedSlideLeftAmount) +
            gCameraModeNormalState->savedSlideLeftAmount;
        camera->fovY =
            blend * (gCameraModeNormalState->fov - gCameraModeNormalState->savedFov) + gCameraModeNormalState->savedFov;
    }
}

void CameraModeNormal_updateVerticalBounds(CameraObject* camera, int flags, int queryType, f32* floorHeight,
                                           f32* ceilingHeight) {
    f32 hitHeight;
    f32 cameraY;
    f32 distance;
    f32 bestFloorDistance;
    f32 bestCeilingDistance;
    f32 zero;
    f32 heightTolerance;
    int blocked;
    int hitCount;
    int ceilingIndex;
    int floorIndex;
    GameObject* focus;
    TrackQueryBounds queryBounds;
    f32 resolvedPosition[3];
    TrackGroundHit** heightHits;

    focus = camera->focusObject;
    if ((flags & 1) != 0) {
        f32 range = 4.0f;
        camera->collisionResults.radii[0] = range;
        camera->collisionResults.surfaceTypes[0] = -1;
        camera->collisionResults.queryTypes[0] = queryType;
        blocked = trackGetLineIntersect(&camera->prevWorldX, &camera->anim.worldPosX, range, 1, NULL, NULL, 0x10,
                                        0xffffffff, 0xff, 0);
        camera->cameraCollisionActive = blocked;
        resolvedPosition[0] = camera->anim.worldPosX;
        resolvedPosition[1] = camera->anim.worldPosY;
        resolvedPosition[2] = camera->anim.worldPosZ;
        hitDetect_calcSweptSphereBounds(&queryBounds, &camera->prevWorldX, resolvedPosition,
                                        camera->collisionResults.radii, 1);
        trackIntersectBroadphase(focus, &queryBounds, 0x240, 1);
        trackGetIntersect(focus, &camera->prevWorldX, resolvedPosition, 1, &camera->collisionResults, 0);
        camera->anim.worldPosX = resolvedPosition[0];
        camera->anim.worldPosY = resolvedPosition[1];
        camera->anim.worldPosZ = resolvedPosition[2];
    }
    if ((flags & 2) != 0) {
        hitCount = trackGetHeight(focus, camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                  &heightHits, 1, 0x40);
        *floorHeight = -100000.0f;
        *ceilingHeight = 100000.0f;
        bestFloorDistance = 100000.0f;
        bestCeilingDistance = 100000.0f;
        zero = 0.0f;
        for (ceilingIndex = 0; ceilingIndex < hitCount; ceilingIndex++) {
            heightTolerance = 10.0f;
            if (heightHits[ceilingIndex]->normalY < zero) {
                hitHeight = heightHits[ceilingIndex]->height;
                cameraY = camera->anim.worldPosY;
                if (hitHeight > cameraY - heightTolerance) {
                    distance = cameraY - hitHeight;
                    if (distance < zero) {
                        distance = -distance;
                    }
                    if (distance < bestCeilingDistance) {
                        *ceilingHeight = hitHeight;
                        camera->ceilingNormalY = heightHits[ceilingIndex]->normalY;
                        bestCeilingDistance = distance;
                    }
                }
            }
        }
        zero = 0.0f;
        for (floorIndex = 0; floorIndex < hitCount; floorIndex++) {
            heightTolerance = 10.0f;
            if (heightHits[floorIndex]->normalY > zero) {
                hitHeight = heightHits[floorIndex]->height;
                cameraY = camera->anim.worldPosY;
                if (hitHeight < heightTolerance + cameraY) {
                    distance = cameraY - hitHeight;
                    if (distance < zero) {
                        distance = -distance;
                    }
                    if (distance < bestFloorDistance) {
                        *floorHeight = hitHeight;
                        camera->floorNormalY = heightHits[floorIndex]->normalY;
                        bestFloorDistance = distance;
                    }
                }
            }
        }
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeNormal_getSettings(float* minDistanceOut, float* maxDistanceOut, float* lowerHeightOffsetOut,
                                  float* upperHeightOffsetOut, float* targetHeightOut) {
    *minDistanceOut = gCameraModeNormalState->minDistance;
    *maxDistanceOut = gCameraModeNormalState->maxDistance;
    if (lowerHeightOffsetOut != NULL) {
        *lowerHeightOffsetOut = gCameraModeNormalState->lowerHeightOffset;
    }
    if (upperHeightOffsetOut != NULL) {
        *upperHeightOffsetOut = gCameraModeNormalState->upperHeightOffset;
    }
    if (targetHeightOut != NULL) {
        *targetHeightOut = gCameraModeNormalState->targetHeight;
    }
}

void CameraModeNormal_updateSlide(CameraObject* camera, GameObject* target, f32 floorHeight, f32 ceilingHeight) {
    PlayerState* state;
    f32 minHeight;
    u32 angle;
    int slideAngleCur;
    f32 upperY;
    f32 lowerY;
    f32 minDistSpan;
    f32 slideOffset;
    f64 approach;
    f32 mtx[16];
    CameraModeNormalSlideTransform rot;
    f32 relX;
    f32 step;
    f32 relZ;
    f32 dist;
    f32 outX;
    f32 outY;
    f32 outZ;

    (*gCameraInterface)
        ->getRelativePosition(camera, &relX, &step, &relZ, &dist, gCameraModeNormalState->targetHeight, 0);
    dist = relZ * relZ + (relX * relX + step * step);
    if (dist > 0.0f) {
        dist = sqrtf(dist);
    }
    if (dist < 5.0f) {
        dist = 5.0f;
    }
    upperY =
        gCameraModeNormalState->upperHeightOffset + (target->anim.worldPosY + gCameraModeNormalState->targetHeight);
    lowerY =
        gCameraModeNormalState->lowerHeightOffset + (target->anim.worldPosY + gCameraModeNormalState->targetHeight);
    if (target->anim.classId == 1) {
        state = (PlayerState*)target->extra;
        angle = getAngle((f64)relX, relZ);
        rot.angles[0] = (s16)(0x8000 - angle);
        rot.angles[1] = 0;
        rot.angles[2] = 0;
        rot.scale = 1.0f;
        rot.translation.x = 0.0f;
        rot.translation.y = 0.0f;
        rot.translation.z = 0.0f;
        mtxRotateByVec3s(mtx, rot.angles);
        Matrix_TransformPoint(mtx, state->cameraSlideVector.x, state->cameraSlideVector.y, state->cameraSlideVector.z,
                              &outX, &outY, &outZ);
        angle = 0x4000 - (getAngle((f64)outY, outZ) & 0xffff);
        gCameraModeNormalState->slideAngle +=
            (int)(framesThisStep * ((int)angle - gCameraModeNormalState->slideAngle)) >> 5;
    } else {
        gCameraModeNormalState->slideAngle -= (int)(gCameraModeNormalState->slideAngle * framesThisStep) >> 5;
    }
    slideAngleCur = gCameraModeNormalState->slideAngle;
    if (slideAngleCur < 0) {
        slideOffset = gCameraModeNormalState->slideLeftAmount * mathSinf((3.1415927f * slideAngleCur) / 32768.0f);
    } else if (slideAngleCur > 0) {
        slideOffset = gCameraModeNormalState->slideRightAmount * mathSinf((3.1415927f * slideAngleCur) / 32768.0f);
    } else {
        slideOffset = 0.0f;
    }
    lowerY += slideOffset;
    upperY += slideOffset;
    minDistSpan = gCameraModeNormalState->minDistance - 25.0f;
    if (minDistSpan < 30.0f) {
        minDistSpan = 30.0f;
    }
    if (target->anim.classId == 1) {
        if (playerGetProbeHitDist((GameObject*)(target)) <= 30.0f) {
            step = 0.8f * gCameraModeNormalState->maxDistance - gCameraModeNormalState->lowerHeightOffset;
            step *= 0.05f;
            if (step > 10.0f) {
                step = 10.0f;
            }
            gCameraModeNormalState->lowerHeightOffset += step;
            if (gCameraModeNormalState->lowerHeightOffset > gCameraModeNormalState->maxDistance) {
                gCameraModeNormalState->lowerHeightOffset = gCameraModeNormalState->maxDistance;
            }
            step = 0.8f * gCameraModeNormalState->maxDistance - gCameraModeNormalState->upperHeightOffset;
            step *= 0.05f;
            if (step > 10.0f) {
                step = 10.0f;
            }
            gCameraModeNormalState->upperHeightOffset += step;
            if (gCameraModeNormalState->upperHeightOffset > gCameraModeNormalState->maxDistance) {
                gCameraModeNormalState->upperHeightOffset = gCameraModeNormalState->maxDistance;
            }
        } else {
            step = gCameraModeNormalState->baseLowerHeightOffset - gCameraModeNormalState->lowerHeightOffset;
            step *= 0.05f;
            if (step > -0.1f) {
                step = -0.1f;
            }
            if (step < -10.0f) {
                step = -10.0f;
            }
            gCameraModeNormalState->lowerHeightOffset += step;
            if (gCameraModeNormalState->lowerHeightOffset < gCameraModeNormalState->baseLowerHeightOffset) {
                gCameraModeNormalState->lowerHeightOffset = gCameraModeNormalState->baseLowerHeightOffset;
            }
            step = gCameraModeNormalState->baseUpperHeightOffset - gCameraModeNormalState->upperHeightOffset;
            step *= 0.05f;
            if (step > -0.1f) {
                step = -0.1f;
            }
            if (step < -10.0f) {
                step = -10.0f;
            }
            gCameraModeNormalState->upperHeightOffset += step;
            if (gCameraModeNormalState->upperHeightOffset < gCameraModeNormalState->baseUpperHeightOffset) {
                gCameraModeNormalState->upperHeightOffset = gCameraModeNormalState->baseUpperHeightOffset;
            }
            if (dist > 30.0f) {
                if (dist <= minDistSpan) {
                    f32 d = minDistSpan - 30.0f;
                    if (d > 0.0f) {
                        dist = (dist - 30.0f) / d;
                    }
                    if (dist < 0.0f) {
                        dist = 0.0f;
                    } else if (dist > 1.0f) {
                        dist = 1.0f;
                    }
                    lowerY =
                        dist * ((gCameraModeNormalState->targetHeight + gCameraModeNormalState->lowerHeightOffset) -
                                35.0f) +
                        (35.0f + target->anim.worldPosY);
                    upperY =
                        dist * ((gCameraModeNormalState->targetHeight + gCameraModeNormalState->upperHeightOffset) -
                                (minHeight = 35.0f)) +
                        (35.0f + target->anim.worldPosY);
                }
            } else {
                upperY = 0.8f * (30.0f - dist) + (35.0f + target->anim.worldPosY);
                lowerY = upperY;
            }
        }
    }
    if (camera->anim.worldPosY < lowerY) {
        step = lowerY - camera->anim.worldPosY;
    } else if (camera->anim.worldPosY > upperY) {
        step = upperY - camera->anim.worldPosY;
    } else {
        step = 0.0f;
    }
    approach = step = interpolate((f64)step, gCameraModeNormalState->heightAdjustRate, timeDelta);
    if ((f32)approach > -0.1f && (f32)approach < 0.1f) {
        step = 0.0f;
    }
    camera->anim.worldPosY += step;
    if (camera->anim.worldPosY > 100.0f + upperY) {
        camera->anim.worldPosY = 100.0f + upperY;
    }
    if (gCameraModeNormalState->upperHeightOffset > gCameraModeNormalState->baseUpperHeightOffset) {
        if (gCameraModeNormalState->clampFlags.heightLocked &&
            camera->anim.worldPosY > gCameraModeNormalState->heightLockLimit) {
            camera->anim.worldPosY = gCameraModeNormalState->heightLockLimit;
        }
        if (target->anim.velocityY > 0.0f) {
            gCameraModeNormalState->clampFlags.heightLocked = 0;
        }
    } else {
        gCameraModeNormalState->clampFlags.heightLocked = 0;
    }
}

void CameraModeNormal_updatePitch(f32 targetY, f32 dist, CameraObject* camera) {
    int pitchDelta;

    pitchDelta =
        getAngle((f64)(camera->anim.worldPosY - (targetY + gCameraModeNormalState->targetHeight)), dist) & 0xffff;
    pitchDelta -= camera->anim.rotY & 0xffff;
    if (pitchDelta > 0x8000) {
        pitchDelta -= 0xffff;
    }
    if (pitchDelta < -0x8000) {
        pitchDelta += 0xffff;
    }
    camera->anim.rotY =
        (s16)(camera->anim.rotY + (int)interpolate((f64)(f32)pitchDelta,
                                                   (f64)(1.0f / gCameraModeNormalState->yawResponseFrames), timeDelta));
}

void CameraModeNormal_follow(CameraObject* camera, ObjAnimComponent* target) {

    f32 dx;
    f32 dz;
    f32 dy;
    f32 dist;
    f32 clamped;
    f32 targetX;
    f32 targetZ;
    f32 ratio;
    f32 speed;

    (*gCameraInterface)->getRelativePosition(camera, &dx, &dz, &dy, &dist, gCameraModeNormalState->targetHeight, 1);
    dist = dy * dy + (dx * dx + dz * dz);
    if (dist > 0.0f) {
        dist = sqrtf(dist);
    }
    if (dist < 5.0f) {
        dist = 5.0f;
    }
    if (dist > 2.0f * gCameraModeNormalState->maxDistance) {
        camcontrol_getTargetPosition(camera, target, &camera->anim.worldPosX, &camera->anim.rotY);
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       camera->anim.parent);
        camera->prevWorldX = camera->anim.worldPosX;
        camera->prevWorldY = camera->anim.worldPosY;
        camera->prevWorldZ = camera->anim.worldPosZ;
        (*gCameraInterface)->getRelativePosition(camera, &dx, &dz, &dy, &dist, gCameraModeNormalState->targetHeight, 1);
        dist = dy * dy + (dx * dx + dz * dz);
        if (dist > 0.0f) {
            dist = sqrtf(dist);
        }
        if (dist < 5.0f) {
            dist = 5.0f;
        }
    }

    if (dist > gCameraModeNormalState->maxDistance) {
        clamped = gCameraModeNormalState->maxDistance;
        gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        gCameraModeNormalState->clampFlags.distanceClamped = 1;
    } else if (dist < gCameraModeNormalState->minDistance) {
        clamped = gCameraModeNormalState->minDistance;
        gCameraModeNormalState->clampFlags.distanceClamped = 0;
    } else {
        clamped = dist;
        gCameraModeNormalState->clampFlags.distanceClamped = 0;
    }

    targetX = camera->anim.localPosX;
    targetZ = camera->anim.localPosZ;
    if ((gCameraModeNormalState->wallAvoidanceFlags.active == 0) && (clamped != dist) &&
        (0.0f != gCameraModeNormalState->distanceAdjustRate)) {
        if (dist < 1.0f) {
            dist = 1.0f;
        }
        ratio = interpolate(dist - clamped, gCameraModeNormalState->distanceAdjustRate, timeDelta);
        ratio = (dist + ratio) / dist;
        if (ratio > 0.0f) {
            targetX = target->localPosX + dx / ratio;
            targetZ = target->localPosZ + dy / ratio;
        }
    }

    dx = targetX - camera->anim.localPosX;
    dy = targetZ - camera->anim.localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    if (dist > 0.0f) {
        dx /= dist;
        dy /= dist;
    }
    ratio = PSVECMag(&target->velocity);
    speed = 1.5f * timeDelta;
    speed = ratio * speed;
    if (speed < 1.0f) {
        speed = 1.0f;
    }
    dist = dist < 0.0f ? 0.0f : (dist > speed ? speed : dist);
    dist = dist < 0.0f ? 0.0f : (dist > 20.0f ? 20.0f : dist);
    camera->anim.localPosX = dx * dist + camera->anim.localPosX;
    camera->anim.localPosZ = dy * dist + camera->anim.localPosZ;

    if (gCameraModeNormalState->upperHeightOffset > gCameraModeNormalState->baseUpperHeightOffset) {
        dx = camera->anim.localPosX - target->localPosX;
        dy = camera->anim.localPosZ - target->localPosZ;
        dist = sqrtf(dx * dx + dy * dy);
        if (dist < 0.25f * gCameraModeNormalState->minDistance) {
            if (dist > 0.0f) {
                dx /= dist;
                dy /= dist;
            }
            dist = 0.25f * gCameraModeNormalState->minDistance;
            camera->anim.localPosX = dist * dx + target->localPosX;
            camera->anim.localPosZ = dist * dy + target->localPosZ;
        }
    }
}

void CameraModeNormal_copyToCurrent(CameraModeNormalActionSettings* settings) {
    float fval;
    CameraObject* camera;

    camera = (CameraObject*)(*gCameraInterface)->getCamera();
    gCameraModeNormalState->savedTargetHeight = gCameraModeNormalState->targetHeight;
    gCameraModeNormalState->savedLowerHeightOffset = gCameraModeNormalState->lowerHeightOffset;
    gCameraModeNormalState->savedUpperHeightOffset = gCameraModeNormalState->upperHeightOffset;
    gCameraModeNormalState->savedMinDistance = gCameraModeNormalState->minDistance;
    gCameraModeNormalState->savedMaxDistance = gCameraModeNormalState->maxDistance;
    gCameraModeNormalState->savedFov = camera->fovY;
    gCameraModeNormalState->savedSlideRightAmount = gCameraModeNormalState->slideRightAmount;
    gCameraModeNormalState->savedSlideLeftAmount = gCameraModeNormalState->slideLeftAmount;
    gCameraModeNormalState->savedHeightAdjustRate = gCameraModeNormalState->heightAdjustRate;
    gCameraModeNormalState->savedDistanceAdjustRate = gCameraModeNormalState->distanceAdjustRate;
    fval = settings->targetHeight;
    gCameraModeNormalState->targetHeight = fval;
    gCameraModeNormalState->targetTargetHeight = fval;
    fval = (f32)(u32)settings->lowerHeightOffset;
    gCameraModeNormalState->lowerHeightOffset = fval;
    gCameraModeNormalState->baseLowerHeightOffset = fval;
    gCameraModeNormalState->targetLowerHeightOffset = fval;
    fval = (f32)(u32)settings->upperHeightOffset;
    gCameraModeNormalState->upperHeightOffset = fval;
    gCameraModeNormalState->baseUpperHeightOffset = fval;
    gCameraModeNormalState->targetUpperHeightOffset = fval;
    fval = (f32)(u32)settings->minDistance;
    gCameraModeNormalState->minDistance = fval;
    gCameraModeNormalState->targetMinDistance = fval;
    fval = (f32)(u32)settings->maxDistance;
    gCameraModeNormalState->maxDistance = fval;
    gCameraModeNormalState->targetMaxDistance = fval;
    fval = settings->fov;
    camera->fovY = fval;
    gCameraModeNormalState->fov = fval;
    fval = (f32)(u32)settings->slideRightAmount;
    gCameraModeNormalState->slideRightAmount = fval;
    gCameraModeNormalState->targetSlideRightAmount = fval;
    fval = (f32)(u32)settings->slideLeftAmount;
    gCameraModeNormalState->slideLeftAmount = fval;
    gCameraModeNormalState->targetSlideLeftAmount = fval;
    if (settings->distanceAdjustRate != 0) {
        fval = (f32)(u32)settings->distanceAdjustRate / 255.0f;
        gCameraModeNormalState->distanceAdjustRate = fval;
        gCameraModeNormalState->targetDistanceAdjustRate = fval;
    } else {
        gCameraModeNormalState->targetDistanceAdjustRate = 0.09f;
    }
    if (settings->heightAdjustRate != 0) {
        fval = (f32)(u32)settings->heightAdjustRate / 255.0f;
        gCameraModeNormalState->heightAdjustRate = fval;
        gCameraModeNormalState->targetHeightAdjustRate = fval;
    } else {
        gCameraModeNormalState->targetHeightAdjustRate = 0.09f;
    }
    gCameraModeNormalState->transitionTimer = 0;
    gCameraModeNormalState->transitionDuration = 0;
}

void CameraModeNormal_free(CameraObject* camera) {
    gCameraModeNormalState->savedWorldX = camera->anim.worldPosX;
    gCameraModeNormalState->savedWorldY = camera->anim.worldPosY;
    gCameraModeNormalState->savedWorldZ = camera->anim.worldPosZ;
    gCameraModeNormalState->savedRotX = camera->anim.rotX;
    gCameraModeNormalState->savedRotY = camera->anim.rotY;
    gCameraModeNormalState->savedRotZ = camera->anim.rotZ;
    gCameraModeNormalState->wallAvoidanceFlags.savedActive = 0;
}

void CameraModeNormal_update(CameraObject* camera) {
    GameObject* target;
    float zero;
    int val;
    u32 angleDelta;
    int yaw;
    f32 wallOrigin[3];
    f32 probeOrigin[3];
    float relativeX;
    f32 relativeY;
    float relativeZ;
    float horizontalDistance;
    float targetTimeScale;
    TrackHitResults wallTrace;
    TrackHitResults probeTrace;

    target = camera->focusObject;
    if (target == NULL) {
        return;
    }
    if (target->anim.classId == 1) {
        playerGetTimeScale(target, &targetTimeScale);
        gCameraModeNormalScaledTimeDelta = timeDelta * targetTimeScale;
        val = EmissionController_IsLingering(target);
        switch (val) {
        case 1:
            gCameraModeNormalState->heightAdjustRate = 0.0f;
            gCameraModeNormalState->yawResponseFrames = 0xff;
            break;
        case 2:
            gCameraModeNormalState->heightAdjustRate = 0.008f;
            gCameraModeNormalState->yawResponseFrames = 0xc;
            break;
        case 4:
            gCameraModeNormalState->heightAdjustRate = 0.2f;
            gCameraModeNormalState->yawResponseFrames = 2;
            break;
        case 3:
            gCameraModeNormalState->heightAdjustRate = 0.055f;
            gCameraModeNormalState->yawResponseFrames = 8;
            break;
        default:
            gCameraModeNormalState->heightAdjustRate = gCameraModeNormalState->targetHeightAdjustRate;
            gCameraModeNormalState->yawResponseFrames = 8;
            break;
        }
    } else {
        gCameraModeNormalScaledTimeDelta = timeDelta;
    }
    camera->unk13E = 0;
    CameraModeNormal_updateSettings(camera);
    CameraModeNormal_updateWallAvoidance(camera, target);
    CameraModeNormal_follow(camera, &target->anim);
    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY, camera->anim.localPosZ,
                                   &camera->anim.worldPosX, &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   camera->anim.parent);
    CameraModeNormal_updateSlide(camera, target, gCameraModeNormalState->floorHeight,
                                 gCameraModeNormalState->ceilingHeight);
    CameraModeNormal_updateVerticalBounds(camera, 1, 8, &gCameraModeNormalState->floorHeight,
                                          &gCameraModeNormalState->ceilingHeight);
    if (gCameraModeNormalState->wallAvoidanceFlags.active == 0) {
        gCameraModeNormalState->collisionHitMask = camera->collisionResults.hitMask;
        if (((camera->cameraCollisionActive != 0) ||
             ((gCameraModeNormalState->collisionHitMask == 1 && (camera->collisionResults.planes[0][1] >= 0.0f)))) &&
            (gCameraModeNormalState->clampFlags.distanceClamped == 0)) {
            if (((camera->anim.worldPosY > 30.0f + target->anim.worldPosY) &&
                 (camera->anim.worldPosY < 70.0f + target->anim.worldPosY)) &&
                (camera->anim.parent == NULL)) {
                gCameraModeNormalState->wallAvoidanceFlags.active = 1;
            }
        }
        if ((((gCameraModeNormalState->collisionHitMask & 0x10) != 0) &&
             (camera->collisionResults.planes[0][1] < -0.707f)) &&
            (target->anim.velocityY <= 0.0f)) {
            gCameraModeNormalState->clampFlags.heightLocked = 1;
            gCameraModeNormalState->heightLockLimit = camera->anim.worldPosY;
        }
    } else {
        zero = 0.0f;
        camera->floorNormalY = zero;
        camera->ceilingNormalY = zero;
        if ((camera->collisionResults.hitMask == 1) && (camera->collisionResults.planes[0][1] < zero)) {
            gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        }
        if ((camera->anim.worldPosY > 75.0f + target->anim.worldPosY) ||
            (camera->anim.worldPosY < 20.0f + target->anim.worldPosY)) {
            gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        }
    }
    if (gCameraModeNormalState->clampFlags.distanceClamped != 0) {
        if ((gCameraModeNormalState->collisionHitMask == 1) || (camera->cameraCollisionActive != 0)) {
            gCameraModeNormalState->wallAvoidanceTimer += 1;
        } else {
            gCameraModeNormalState->wallAvoidanceTimer = 0;
        }
        if (gCameraModeNormalState->wallAvoidanceTimer > 10) {
            if (target->anim.classId == 1) {
                cameraGetPrevPos2(target, &wallOrigin[0], &wallOrigin[1], &wallOrigin[2]);
            } else {
                wallOrigin[0] = target->anim.worldPosX;
                wallOrigin[1] = target->anim.worldPosY + gCameraModeNormalState->targetHeight;
                wallOrigin[2] = target->anim.worldPosZ;
            }
            camcontrol_traceMove(&wallOrigin[0], &camera->anim.worldPosX, &camera->anim.worldPosX, &wallTrace, 3, 1, 1,
                                 4.0f);
            camera->prevWorldX = camera->anim.worldPosX;
            camera->prevWorldY = camera->anim.worldPosY;
            camera->prevWorldZ = camera->anim.worldPosZ;
            gCameraModeNormalState->wallAvoidanceTimer = 0;
        }
    }
    if (gCameraModeNormalState->wallAvoidanceFlags.active == 0) {
        if ((gCameraModeNormalState->collisionHitMask & 0x10) != 0) {
            gCameraModeNormalState->collisionProbeTimer += 1;
        } else {
            gCameraModeNormalState->collisionProbeTimer = 0;
        }
        if (gCameraModeNormalState->collisionProbeTimer > 5) {
            if (target->anim.classId == 1) {
                cameraGetPrevPos2(target, &probeOrigin[0], &probeOrigin[1], &probeOrigin[2]);
            } else {
                probeOrigin[0] = target->anim.worldPosX;
                probeOrigin[1] = target->anim.worldPosY + gCameraModeNormalState->targetHeight;
                probeOrigin[2] = target->anim.worldPosZ;
            }
            camcontrol_traceMove(&probeOrigin[0], &camera->anim.worldPosX, &camera->anim.worldPosX, &probeTrace, 3, 1,
                                 1, 4.0f);
            camera->prevWorldX = camera->anim.worldPosX;
            camera->prevWorldY = camera->anim.worldPosY;
            camera->prevWorldZ = camera->anim.worldPosZ;
            gCameraModeNormalState->collisionProbeTimer = 0;
        }
    }
    (*gCameraInterface)
        ->getRelativePosition(camera, &relativeX, &relativeY, &relativeZ, &horizontalDistance,
                              gCameraModeNormalState->targetHeight, 0);
    yaw = 0x8000 - (u16)getAngle(relativeX, relativeZ);
    gCameraModeNormalState->pitchOffset = 0;
    camera->anim.rotX = yaw - gCameraModeNormalState->pitchOffset;
    angleDelta =
        0xffffu & getAngle(camera->anim.worldPosY - (target->anim.worldPosY + gCameraModeNormalState->targetHeight),
                           horizontalDistance);
    angleDelta = angleDelta - ((int)camera->anim.rotY & 0xffffU);
    if ((int)angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if ((int)angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    val = interpolate((f32)(int)angleDelta, 1.0f / (f32)(u32)gCameraModeNormalState->yawResponseFrames, timeDelta);
    camera->anim.rotY += val;
    CameraModeNormal_updateTargetAction(camera, target);
    val = interpolate((f32)camera->anim.rotZ, 0.125f, timeDelta);
    camera->anim.rotZ -= val;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   camera->anim.parent);
}

void CameraModeNormal_init(CameraObject* cam, int mode, CameraModeNormalInitSettings* settings) {
    GameObject* target;
    f32 vOutA;
    f32 vOutB;
    f32 vOutC;
    f32 vOutD;
    f32 fVal;
    u32 uVal;
    CameraModeNormalInitSettings* p = settings;

    gCameraModeNormalState->wallAvoidanceFlags.active = 0;
    gCameraModeNormalState->collisionState = 0;
    gCameraModeNormalState->collisionProbeTimer = 0;
    gCameraModeNormalState->wallAvoidanceTimer = 0;
    gCameraModeNormalState->clampFlags.distanceClamped = 0;
    gCameraModeNormalState->yawResponseFrames = 8;
    target = (GameObject*)cam->focusObject;
    switch (mode) {
    case 0:
        memset(gCameraModeNormalState, 0, sizeof(CameraModeNormalState));
        if (settings != NULL) {
            fVal = (f32)(u32)p->minDistanceWide;
            gCameraModeNormalState->minDistance = fVal;
            gCameraModeNormalState->targetMinDistance = fVal;
            fVal = (f32)(u32)p->maxDistanceWide;
            gCameraModeNormalState->maxDistance = fVal;
            gCameraModeNormalState->targetMaxDistance = fVal;
            fVal = (f32)(u32)p->heightOffsetWide;
            gCameraModeNormalState->baseLowerHeightOffset = fVal;
            gCameraModeNormalState->lowerHeightOffset = fVal;
            gCameraModeNormalState->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)p->heightOffsetWide;
            gCameraModeNormalState->baseUpperHeightOffset = fVal;
            gCameraModeNormalState->upperHeightOffset = fVal;
            gCameraModeNormalState->targetUpperHeightOffset = fVal;
        }
        fVal = 35.0f;
        gCameraModeNormalState->targetHeight = fVal;
        gCameraModeNormalState->targetTargetHeight = fVal;
        fVal = 0.09f;
        gCameraModeNormalState->distanceAdjustRate = fVal;
        gCameraModeNormalState->targetDistanceAdjustRate = fVal;
        fVal = 0.04f;
        gCameraModeNormalState->savedHeightAdjustRate = fVal;
        gCameraModeNormalState->heightAdjustRate = fVal;
        gCameraModeNormalState->targetHeightAdjustRate = fVal;
        fVal = 50.0f;
        gCameraModeNormalState->slideRightAmount = fVal;
        gCameraModeNormalState->targetSlideRightAmount = fVal;
        fVal = 30.0f;
        gCameraModeNormalState->slideLeftAmount = fVal;
        gCameraModeNormalState->targetSlideLeftAmount = fVal;
        gCameraModeNormalState->unknown24 = -100000.0f;
        gCameraModeNormalState->unknown20 = 100000.0f;
        gCameraModeNormalState->initialized = 1;
        gCameraModeNormalState->fov = cam->fovY;
        camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
        fVal = cam->anim.worldPosX;
        cam->anim.localPosX = fVal;
        cam->prevWorldX = fVal;
        cam->savedLocalPos.x = fVal;
        fVal = cam->anim.worldPosY;
        cam->anim.localPosY = fVal;
        cam->prevWorldY = fVal;
        cam->savedLocalPos.y = fVal;
        fVal = cam->anim.worldPosZ;
        cam->anim.localPosZ = fVal;
        cam->prevWorldZ = fVal;
        cam->savedLocalPos.z = fVal;
        cam->anim.rotX = 0;
        cam->anim.rotZ = 0;
        if (settings != NULL) {
            cam->fovY = (f32)(u32)p->fovWide;
        }
        break;
    case 4:
        camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       (GameObject*)cam->anim.parent);
        (*gCameraInterface)
            ->getRelativePosition(cam, &vOutA, &vOutB, &vOutC, &vOutD, gCameraModeNormalState->targetHeight, 0);
        vOutB = cam->anim.localPosY - (target->anim.localPosY + gCameraModeNormalState->targetHeight);
        cam->anim.rotY = getAngle(vOutB, vOutD);
        cam->anim.rotZ = 0;
        cam->prevWorldX = cam->anim.worldPosX;
        cam->prevWorldY = cam->anim.worldPosY;
        cam->prevWorldZ = cam->anim.worldPosZ;
        cam->savedLocalPos.x = cam->anim.localPosX;
        cam->savedLocalPos.y = cam->anim.localPosY;
        cam->savedLocalPos.z = cam->anim.localPosZ;
        cam->fovY = gCameraModeNormalState->fov;
        gCameraModeNormalState->transitionTimer = 0;
        break;
    case 2:
        if (settings != NULL) {
            gCameraModeNormalState->targetTargetHeight = 35.0f;
            fVal = (f32)(u32)p->lowerHeightOffset;
            gCameraModeNormalState->baseLowerHeightOffset = fVal;
            gCameraModeNormalState->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)p->upperHeightOffset;
            gCameraModeNormalState->baseUpperHeightOffset = fVal;
            gCameraModeNormalState->targetUpperHeightOffset = fVal;
            gCameraModeNormalState->targetMinDistance = (f32)(u32)p->minDistance;
            gCameraModeNormalState->targetMaxDistance = (f32)(u32)p->maxDistance;
            gCameraModeNormalState->fov = p->fov;
            gCameraModeNormalState->targetSlideRightAmount = (f32)(u32)p->slideRightAmount;
            gCameraModeNormalState->targetSlideLeftAmount = (f32)(u32)p->slideLeftAmount;
            uVal = p->distanceAdjustRate;
            if (uVal != 0) {
                gCameraModeNormalState->targetDistanceAdjustRate = uVal / 255.0f;
            } else {
                gCameraModeNormalState->targetDistanceAdjustRate = 0.09f;
            }
            uVal = p->heightAdjustRate;
            if (uVal != 0) {
                gCameraModeNormalState->targetHeightAdjustRate = uVal / 255.0f;
            } else {
                gCameraModeNormalState->targetHeightAdjustRate = 0.09f;
            }
            gCameraModeNormalState->transitionTimer = (s16)p->transitionFrames;
            gCameraModeNormalState->transitionDuration = (s16)p->transitionFrames;
            *(u8*)&cam->letterboxTargetOffset = p->letterboxOffset;
        } else {
            gCameraModeNormalState->targetTargetHeight = gCameraModeNormalState->savedTargetHeight;
            fVal = gCameraModeNormalState->savedLowerHeightOffset;
            gCameraModeNormalState->baseLowerHeightOffset = fVal;
            gCameraModeNormalState->targetLowerHeightOffset = fVal;
            fVal = gCameraModeNormalState->savedUpperHeightOffset;
            gCameraModeNormalState->baseUpperHeightOffset = fVal;
            gCameraModeNormalState->targetUpperHeightOffset = fVal;
            gCameraModeNormalState->targetMinDistance = gCameraModeNormalState->savedMinDistance;
            gCameraModeNormalState->targetMaxDistance = gCameraModeNormalState->savedMaxDistance;
            gCameraModeNormalState->fov = gCameraModeNormalState->savedFov;
            gCameraModeNormalState->targetSlideRightAmount = gCameraModeNormalState->savedSlideRightAmount;
            gCameraModeNormalState->targetSlideLeftAmount = gCameraModeNormalState->savedSlideLeftAmount;
            gCameraModeNormalState->targetDistanceAdjustRate = gCameraModeNormalState->savedDistanceAdjustRate;
            gCameraModeNormalState->targetHeightAdjustRate = gCameraModeNormalState->savedHeightAdjustRate;
            gCameraModeNormalState->transitionTimer = 0x3c;
            gCameraModeNormalState->transitionDuration = 0x3c;
        }
        gCameraModeNormalState->savedTargetHeight = gCameraModeNormalState->targetHeight;
        gCameraModeNormalState->savedLowerHeightOffset = gCameraModeNormalState->lowerHeightOffset;
        gCameraModeNormalState->savedUpperHeightOffset = gCameraModeNormalState->upperHeightOffset;
        gCameraModeNormalState->savedMinDistance = gCameraModeNormalState->minDistance;
        gCameraModeNormalState->savedMaxDistance = gCameraModeNormalState->maxDistance;
        gCameraModeNormalState->savedFov = cam->fovY;
        gCameraModeNormalState->savedSlideRightAmount = gCameraModeNormalState->slideRightAmount;
        gCameraModeNormalState->savedSlideLeftAmount = gCameraModeNormalState->slideLeftAmount;
        gCameraModeNormalState->savedDistanceAdjustRate = gCameraModeNormalState->distanceAdjustRate;
        gCameraModeNormalState->savedHeightAdjustRate = gCameraModeNormalState->heightAdjustRate;
        if ((settings != NULL) && (p->snapToTarget != 0)) {
            camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
            Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                           &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                           (GameObject*)cam->anim.parent);
            gCameraModeNormalState->transitionTimer = 0;
        }
        break;
    case 3:
        cam->fovY = gCameraModeNormalState->fov;
        cam->anim.worldPosX = gCameraModeNormalState->savedWorldX;
        cam->anim.worldPosY = gCameraModeNormalState->savedWorldY;
        cam->anim.worldPosZ = gCameraModeNormalState->savedWorldZ;
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       (GameObject*)cam->anim.parent);
        cam->anim.rotX = gCameraModeNormalState->savedRotX;
        cam->anim.rotY = gCameraModeNormalState->savedRotY;
        cam->anim.rotZ = gCameraModeNormalState->savedRotZ;
        cam->savedLocalPos.x = cam->anim.localPosX;
        cam->savedLocalPos.y = cam->anim.localPosY;
        cam->savedLocalPos.z = cam->anim.localPosZ;
        cam->prevWorldX = cam->anim.worldPosX;
        cam->prevWorldY = cam->anim.worldPosY;
        cam->prevWorldZ = cam->anim.worldPosZ;
        gCameraModeNormalState->transitionTimer = 0;
        break;
    case 1:
        cam->fovY = gCameraModeNormalState->fov;
        gCameraModeNormalState->wallAvoidanceFlags.active = gCameraModeNormalState->wallAvoidanceFlags.savedActive;
        break;
    }
    gCameraModeNormalState->wallAvoidanceFlags.savedActive = 0;
    cam->unk13E = 1;
}

void CameraModeNormal_release(void) {
    mm_free(gCameraModeNormalState);
    gCameraModeNormalState = 0;
}

void CameraModeNormal_initialise(void) {
    gCameraModeNormalState = (CameraModeNormalState*)mmAlloc(sizeof(CameraModeNormalState), 0xf, 0);
    memset(gCameraModeNormalState, 0, sizeof(CameraModeNormalState));
}

CameraModeNormalDescriptor gCameraModeNormalDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x000b0000},
    CameraModeNormal_initialise,
    CameraModeNormal_release,
    NULL,
    CameraModeNormal_init,
    CameraModeNormal_update,
    CameraModeNormal_free,
    CameraModeNormal_copyToCurrent,
    CameraModeNormal_follow,
    CameraModeNormal_updatePitch,
    CameraModeNormal_updateSlide,
    CameraModeNormal_getSettings,
    CameraModeNormal_updateVerticalBounds,
};
