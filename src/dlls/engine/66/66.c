/*
 * DLL 66 / 0x42 - normal camera mode and shared camera trace helpers.
 */
#include "main/dll/dll_0042_cameramodenormal.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
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

int camcontrol_traceMove(f32* fromPos, f32* toPos, f32* outPos, u8* traceWork, char traceMode, u8 runTrace, u8 runBbox,
                         f32 radius) {
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
    ((CamcontrolTraceWork*)traceWork)->radius = radius;
    ((CamcontrolTraceWork*)traceWork)->bboxHit = -1;
    ((CamcontrolTraceWork*)traceWork)->mode = traceMode;
    ((CamcontrolTraceWork*)traceWork)->hitCount = 0;
    blocked = 0;
    if (runBbox != 0) {
        blocked = trackGetLineIntersect(fromPos, outPos, radius, 1, NULL, NULL, 0x10, 0xffffffff, 0xff, 0);
    } else {
        blocked = 0;
    }
    gCamcontrolTraceBboxBlocked = blocked;
    if (runTrace != 0) {
        hitDetect_calcSweptSphereBounds(&sweptBounds, fromPos, outPos,
                                        (f32*)(traceWork + offsetof(CamcontrolTraceWork, radius)), 1);
        trackIntersectBroadphase(NULL, &sweptBounds, 0x240, 1);
    }
    trackGetIntersect(NULL, fromPos, outPos, 1, traceWork, 0);
    clear = 0;
    if ((gCamcontrolTraceBboxBlocked == 0) && (((CamcontrolTraceWork*)traceWork)->hitCount == 0)) {
        clear = 1;
    }
    return clear;
}
void camcontrol_onTargetTraceBlocked(int unused) {
}

u8 camcontrol_traceFromTarget(float* fromPos, GameObject* target, float* outPos, void* unused) {
    float targetPos[3];
    u8 traceRec[111];

    if (target->anim.classId == 1) {
        cameraGetPrevPos2(target, &targetPos[0], &targetPos[1], &targetPos[2]);
    } else {
        targetPos[0] = target->anim.worldPosX;
        targetPos[1] = target->anim.worldPosY + gCameraModeNormalState->targetHeight;
        targetPos[2] = target->anim.worldPosZ;
    }
    camcontrol_traceMove(targetPos, fromPos, outPos, traceRec, 3, '\x01', '\x01', (double)4.0f);
    return ((CamcontrolTraceWork*)traceRec)->blocked;
}

u8 camcontrol_getTargetPosition(CameraObject* camera, ObjAnimComponent* targetAnim, f32* outPos, s16* outRotY) {
    u8 box[112];
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
    camcontrol_traceMove(prev, pos, outPos, box, 3, '\x01', '\x01', 4.0f);
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
    return ((CamcontrolTraceWork*)box)->blocked;
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
    GameObject* tgt0;
    float probe[75];
    u8 box[136];
    float pathA[21];
    float pathB[21];
    float prev[3];
    f32 spinA;
    f32 spinB;
    f32 spinC;
    f32 spinD;
    GameObject* tgt;
    int ang;
    float* pA;
    float* pB;
    float* pp;
    float* pA0;
    float* pB0;
    int result;
    int s;
    int i;
    int found1;
    int found2;
    int dir;
    int d;
    f32 cosv;
    f32 rad;
    f32 dx;
    f32 dz;
    f32 sinv;
    f32 t;
    f32 v;

    OSGetTick(); /* timing probe; return value intentionally unused */
    result = 0;
    (*gCameraInterface)
        ->getRelativePosition(cam, &spinB, &spinC, &spinD, &spinA, gCameraModeNormalState->targetHeight, 0);
    tgt0 = cam->anim.targetObj;
    *(int*)&probe[35] = (int)tgt0;
    probe[1] = cam->anim.worldPosY;
    pathA[0] = cam->anim.worldPosX;
    pathA[1] = cam->anim.worldPosY;
    pathA[2] = cam->anim.worldPosZ;
    pathB[0] = pathA[0];
    pathB[1] = pathA[1];
    pathB[2] = pathA[2];
    if (tgt0->anim.classId == 1) {
        cameraGetPrevPos2(tgt0, &prev[0], &prev[1], &prev[2]);
    } else {
        prev[0] = tgt0->anim.worldPosX;
        prev[1] = tgt0->anim.worldPosY + gCameraModeNormalState->targetHeight;
        prev[2] = tgt0->anim.worldPosZ;
    }
    s = 0xf;
    i = 0;
    found1 = -1;
    found2 = -1;
    ang = 0xaaa;
    pA0 = pathA;
    pA = pA0;
    pB0 = pathB;
    pB = pB0;
    pp = probe;
    while ((s16)s <= 0x5a) {
        if (found1 == -1) {
            dx = spinD;
            dz = spinB;
            tgt = (GameObject*)cam->anim.targetObj;
            rad = (3.1415927f * (f32)(s16)ang) / 32768.0f;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dz * sinv - dx * cosv;
            v = t * cosv + dx * sinv;
            t += tgt->anim.worldPosX;
            probe[0] = t;
            v += tgt->anim.worldPosZ;
            probe[2] = v;
            pA[3] = probe[0];
            pA[4] = probe[1];
            pA[5] = probe[2];
            if (camcontrol_traceMove(prev, pp, NULL, box, 7, '\0', '\0', 3.9f) != 0) {
                found1 = i;
            }
        }
        if (found2 == -1) {
            dx = spinD;
            dz = spinB;
            tgt = (GameObject*)cam->anim.targetObj;
            rad = (3.1415927f * (f32)(s16)(-s * 0xb6)) / 32768.0f;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dz * sinv - dx * cosv;
            v = t * cosv + dx * sinv;
            t += tgt->anim.worldPosX;
            probe[0] = t;
            v += tgt->anim.worldPosZ;
            probe[2] = v;
            pB[3] = probe[0];
            pB[4] = probe[1];
            pB[5] = probe[2];
            if (camcontrol_traceMove(prev, pp, NULL, box, 7, '\0', '\0', 3.9f) != 0) {
                found2 = i;
            }
        }
        pA += 3;
        pB += 3;
        i++;
        ang += 0xaaa;
        s += 0xf;
    }
    if (found1 == -1) {
        found1 = 6;
    } else {
        for (i = 0; i <= found1; i++) {
            if (camcontrol_traceMove(pA0, pathA + (i + 1) * 3, NULL, box, 7, '\0', '\0', 3.9f) == 0) {
                found1 = 6;
                break;
            }
            pA0 += 3;
        }
    }
    if (found2 == -1) {
        found2 = 6;
    } else {
        for (i = 0; i <= found2; i++) {
            if (camcontrol_traceMove(pB0, pathB + (i + 1) * 3, NULL, box, 7, '\0', '\0', 3.9f) == 0) {
                found2 = 6;
                break;
            }
            pB0 += 3;
        }
    }
    dir = 0;
    if (found1 < found2) {
        dir = 1;
    } else if (found2 < found1) {
        dir = -1;
    } else if (found1 < 6) {
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
        f = cam->unkC4 * cam->unkC4;
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
    u8 box[112];
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
    trace = camcontrol_traceMove(prev, &camera->anim.worldPosX, NULL, box, 7, '\0', '\0', 3.9f);
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
        camera->fov =
            blend * (gCameraModeNormalState->fov - gCameraModeNormalState->savedFov) + gCameraModeNormalState->savedFov;
    }
}

void CameraModeNormal_updateVerticalBounds(CameraObject* camera, int flags, int collisionFlag, float* upperBound,
                                           float* lowerBound) {
    float pt0;
    float wy;
    float diff;
    float bestUpper;
    float bestLower;
    float zLim;
    float zB;
    int res;
    int count;
    int i;
    int j;
    GameObject* camObj;
    int cameraAddr;
    TrackQueryBounds bounds;
    f32 pos[3];
    TrackGroundHit** hits;

    cameraAddr = (int)camera;
    camObj = (GameObject*)((int)camera->anim.targetObj);
    if ((flags & 1) != 0) {
        float range = 4.0f;
        *(f32*)(cameraAddr + (int)offsetof(CameraObject, anim.hitVolumeTransforms)) = range;
        *(s8*)(cameraAddr + (int)offsetof(CameraObject, anim.previousLocalPosY)) = -1;
        *(s8*)(cameraAddr + (int)offsetof(CameraObject, anim.previousLocalPosZ)) = collisionFlag;
        res = trackGetLineIntersect(&camera->probePosX, &camera->anim.worldPosX, range, 1, NULL, NULL, 0x10, 0xffffffff,
                                    0xff, 0);
        camera->cameraCollisionActive = res;
        pos[0] = camera->anim.worldPosX;
        pos[1] = camera->anim.worldPosY;
        pos[2] = camera->anim.worldPosZ;
        hitDetect_calcSweptSphereBounds(&bounds, &camera->probePosX, pos,
                                        (f32*)(cameraAddr + (int)offsetof(CameraObject, anim.hitVolumeTransforms)), 1);
        trackIntersectBroadphase(camObj, &bounds, 0x240, 1);
        trackGetIntersect(camObj, &camera->probePosX, pos, 1, &camera->anim.hostedMapSlot, 0);
        camera->anim.worldPosX = pos[0];
        camera->anim.worldPosY = pos[1];
        camera->anim.worldPosZ = pos[2];
    }
    if ((flags & 2) != 0) {
        count = trackGetHeight(camObj, camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ, &hits, 1,
                               0x40);
        *upperBound = -100000.0f;
        *lowerBound = 100000.0f;
        bestUpper = 100000.0f;
        bestLower = 100000.0f;
        zLim = 0.0f;
        for (i = 0; i < count; i++) {
            zB = 10.0f;
            if (hits[i]->normalY < zLim) {
                pt0 = hits[i]->height;
                wy = camera->anim.worldPosY;
                if (pt0 > wy - zB) {
                    diff = wy - pt0;
                    if (diff < zLim) {
                        diff = -diff;
                    }
                    if (diff < bestLower) {
                        *lowerBound = pt0;
                        camera->boundHitZLower = hits[i]->normalY;
                        bestLower = diff;
                    }
                }
            }
        }
        zLim = 0.0f;
        for (j = 0; j < count; j++) {
            zB = 10.0f;
            if (hits[j]->normalY > zLim) {
                pt0 = hits[j]->height;
                wy = camera->anim.worldPosY;
                if (pt0 < zB + wy) {
                    diff = wy - pt0;
                    if (diff < zLim) {
                        diff = -diff;
                    }
                    if (diff < bestUpper) {
                        *upperBound = pt0;
                        camera->boundHitZUpper = hits[j]->normalY;
                        bestUpper = diff;
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

void CameraModeNormal_updateSlide(CameraObject* camera, GameObject* target, f32 upperBound, f32 lowerBound) {
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
        camera->probePosX = camera->anim.worldPosX;
        camera->probePosY = camera->anim.worldPosY;
        camera->probePosZ = camera->anim.worldPosZ;
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
    gCameraModeNormalState->savedFov = camera->fov;
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
    camera->fov = fval;
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
    GameObject* target[1];
    float fa;
    int val;
    u32 angleDelta;
    int yaw;
    float aimZ2;
    float aimY2;
    float aimX2;
    float aimZ;
    float aimY;
    float aimX;
    float dx2;
    u8 relPosScratch[4];
    float dz;
    float dy;
    float dx;
    u8 wallTraceScratch[116];
    u8 probeTraceScratch[112];

    target[0] = (GameObject*)camera->anim.targetObj;
    if (target[0] == NULL) {
        return;
    }
    if (target[0]->anim.classId == 1) {
        playerGetTimeScale((GameObject*)target[0], &dx);
        gCameraModeNormalScaledTimeDelta = timeDelta * dx;
        val = EmissionController_IsLingering((GameObject*)target[0]);
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
    CameraModeNormal_updateWallAvoidance(camera, target[0]);
    CameraModeNormal_follow(camera, &target[0]->anim);
    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY, camera->anim.localPosZ,
                                   &camera->anim.worldPosX, &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   camera->anim.parent);
    CameraModeNormal_updateSlide(camera, target[0], gCameraModeNormalState->verticalUpperBound,
                                 gCameraModeNormalState->verticalLowerBound);
    CameraModeNormal_updateVerticalBounds(camera, 1, 8, &gCameraModeNormalState->verticalUpperBound,
                                          &gCameraModeNormalState->verticalLowerBound);
    if (gCameraModeNormalState->wallAvoidanceFlags.active == 0) {
        gCameraModeNormalState->targetActionFlags = *(u8*)((u8*)camera + offsetof(CameraObject, anim.activeMove));
        if (((camera->cameraCollisionActive != 0) ||
             ((gCameraModeNormalState->targetActionFlags == 1 &&
               (*(f32*)((u8*)camera + offsetof(CameraObject, anim.next)) >= 0.0f)))) &&
            (gCameraModeNormalState->clampFlags.distanceClamped == 0)) {
            if (((camera->anim.worldPosY > 30.0f + target[0]->anim.worldPosY) &&
                 (camera->anim.worldPosY < 70.0f + target[0]->anim.worldPosY)) &&
                (camera->anim.parent == NULL)) {
                gCameraModeNormalState->wallAvoidanceFlags.active = 1;
            }
        }
        if ((((gCameraModeNormalState->targetActionFlags & 0x10) != 0) &&
             (*(f32*)((u8*)camera + offsetof(CameraObject, anim.next)) < -0.707f)) &&
            (target[0]->anim.velocityY <= 0.0f)) {
            gCameraModeNormalState->clampFlags.heightLocked = 1;
            gCameraModeNormalState->heightLockLimit = camera->anim.worldPosY;
        }
    } else {
        fa = 0.0f;
        camera->boundHitZUpper = fa;
        camera->boundHitZLower = fa;
        if ((*(u8*)((u8*)camera + offsetof(CameraObject, anim.activeMove)) == 1) &&
            (*(f32*)((u8*)camera + offsetof(CameraObject, anim.next)) < fa)) {
            gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        }
        if ((camera->anim.worldPosY > 75.0f + target[0]->anim.worldPosY) ||
            (camera->anim.worldPosY < 20.0f + target[0]->anim.worldPosY)) {
            gCameraModeNormalState->wallAvoidanceFlags.active = 0;
        }
    }
    if (gCameraModeNormalState->clampFlags.distanceClamped != 0) {
        if ((gCameraModeNormalState->targetActionFlags == 1) || (camera->cameraCollisionActive != 0)) {
            gCameraModeNormalState->wallAvoidanceTimer += 1;
        } else {
            gCameraModeNormalState->wallAvoidanceTimer = 0;
        }
        if (gCameraModeNormalState->wallAvoidanceTimer > 10) {
            if (target[0]->anim.classId == 1) {
                cameraGetPrevPos2(target[0], &aimX2, &aimY2, &aimZ2);
            } else {
                aimX2 = target[0]->anim.worldPosX;
                aimY2 = target[0]->anim.worldPosY + gCameraModeNormalState->targetHeight;
                aimZ2 = target[0]->anim.worldPosZ;
            }
            camcontrol_traceMove(&aimX2, &camera->anim.worldPosX, &camera->anim.worldPosX, wallTraceScratch, 3, 1, 1,
                                 4.0f);
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            gCameraModeNormalState->wallAvoidanceTimer = 0;
        }
    }
    if (gCameraModeNormalState->wallAvoidanceFlags.active == 0) {
        if ((gCameraModeNormalState->targetActionFlags & 0x10) != 0) {
            gCameraModeNormalState->collisionProbeTimer += 1;
        } else {
            gCameraModeNormalState->collisionProbeTimer = 0;
        }
        if (gCameraModeNormalState->collisionProbeTimer > 5) {
            if (target[0]->anim.classId == 1) {
                cameraGetPrevPos2(target[0], &aimX, &aimY, &aimZ);
            } else {
                aimX = target[0]->anim.worldPosX;
                aimY = target[0]->anim.worldPosY + gCameraModeNormalState->targetHeight;
                aimZ = target[0]->anim.worldPosZ;
            }
            camcontrol_traceMove(&aimX, &camera->anim.worldPosX, &camera->anim.worldPosX, probeTraceScratch, 3, 1, 1,
                                 4.0f);
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            gCameraModeNormalState->collisionProbeTimer = 0;
        }
    }
    (*gCameraInterface)
        ->getRelativePosition(camera, &dx2, (f32*)relPosScratch, &dz, &dy, gCameraModeNormalState->targetHeight, 0);
    yaw = 0x8000 - (u16)getAngle(dx2, dz);
    gCameraModeNormalState->pitchOffset = 0;
    camera->anim.rotX = yaw - gCameraModeNormalState->pitchOffset;
    angleDelta =
        0xffffu &
        getAngle(camera->anim.worldPosY - (target[0]->anim.worldPosY + gCameraModeNormalState->targetHeight), dy);
    angleDelta = angleDelta - ((int)camera->anim.rotY & 0xffffU);
    if ((int)angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if ((int)angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }
    val = interpolate((f32)(int)angleDelta, 1.0f / (f32)(u32)gCameraModeNormalState->yawResponseFrames, timeDelta);
    camera->anim.rotY += val;
    CameraModeNormal_updateTargetAction(camera, target[0]);
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
    target = (GameObject*)cam->anim.targetObj;
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
        gCameraModeNormalState->fov = cam->fov;
        camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
        fVal = cam->anim.worldPosX;
        cam->anim.localPosX = fVal;
        cam->probePosX = fVal;
        cam->savedLocalPos.x = fVal;
        fVal = cam->anim.worldPosY;
        cam->anim.localPosY = fVal;
        cam->probePosY = fVal;
        cam->savedLocalPos.y = fVal;
        fVal = cam->anim.worldPosZ;
        cam->anim.localPosZ = fVal;
        cam->probePosZ = fVal;
        cam->savedLocalPos.z = fVal;
        cam->anim.rotX = 0;
        cam->anim.rotZ = 0;
        if (settings != NULL) {
            cam->fov = (f32)(u32)p->fovWide;
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
        cam->probePosX = cam->anim.worldPosX;
        cam->probePosY = cam->anim.worldPosY;
        cam->probePosZ = cam->anim.worldPosZ;
        cam->savedLocalPos.x = cam->anim.localPosX;
        cam->savedLocalPos.y = cam->anim.localPosY;
        cam->savedLocalPos.z = cam->anim.localPosZ;
        cam->fov = gCameraModeNormalState->fov;
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
        gCameraModeNormalState->savedFov = cam->fov;
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
        cam->fov = gCameraModeNormalState->fov;
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
        cam->probePosX = cam->anim.worldPosX;
        cam->probePosY = cam->anim.worldPosY;
        cam->probePosZ = cam->anim.worldPosZ;
        gCameraModeNormalState->transitionTimer = 0;
        break;
    case 1:
        cam->fov = gCameraModeNormalState->fov;
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
