/*
 * DLL 67 / 0x43 - staff-animation camera mode.
 */
#include "main/dll/dll_0043_cameramodestaffanim.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "string.h"
#include "types.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/pad.h"

CameraModeStaffAnimState* gCameraModeStaffAnimState;

typedef void (*CameraModeStaffAnimBoundsCallback)(CameraObject* camera, GameObject* target, f32 min, f32 max);

u8 CameraModeStaffAnim_samplePath(f32* outX, f32* height, f32* outZ, GameObject* target, CameraObject* camera) {
    CamcontrolCameraState work;
    int handler;
    int i;
    f32 pathT;

    memset(&work, 0, sizeof(work));
    work.localFrameObj = (GameObject*)camera->anim.parent;
    work.localX = gCameraModeStaffAnimState->pointsX[gCameraModeStaffAnimState->pathCurve.count - 2];
    work.localY = *height;
    work.localZ = gCameraModeStaffAnimState->pointsZ[gCameraModeStaffAnimState->pathCurve.count - 2];
    work.prevLocalX = work.localX;
    work.prevLocalY = work.localY;
    work.prevLocalZ = work.localZ;
    Obj_TransformLocalPointToWorld((double)work.prevLocalX, (double)work.prevLocalY, (double)work.prevLocalZ,
                                   &work.prevWorldX, &work.prevWorldY, &work.prevWorldZ, work.localFrameObj);
    work.focusObj = &target->anim;
    handler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    (*(VtableFn*)(**(int**)(handler + 4) + 0x14))(&work, target);
    Obj_TransformLocalPointToWorld(work.localX, work.localY, work.localZ, &work.worldX, &work.worldY, &work.worldZ,
                                   work.localFrameObj);
    (*(VtableFn*)(**(int**)(handler + 4) + 0x24))(&work, 1, 3, &gCameraModeStaffAnimState->curveMin,
                                                  &gCameraModeStaffAnimState->curveMax);
    i = gCameraModeStaffAnimState->pathCurve.count + -3;
    for (; i < gCameraModeStaffAnimState->pathCurve.count; i = i + 1) {
        gCameraModeStaffAnimState->pointsX[i] = work.localX;
        gCameraModeStaffAnimState->pointsZ[i] = work.localZ;
    }
    if (gCameraModeStaffAnimState->pathCurve.pathLength != 0.0f) {
        pathT = gCameraModeStaffAnimState->pathCurve.pathDistance / gCameraModeStaffAnimState->pathCurve.pathLength;
    } else {
        pathT = 0.0f;
    }
    if (pathT > 1.0f) {
        pathT = 1.0f;
    } else if (pathT < 0.0f) {
        pathT = 0.0f;
    }
    pathT = Curve_EvalHermite(gCameraModeStaffAnimState->initialiseCurve, pathT, NULL);
    if (pathT < 0.2f) {
        pathT = 0.2f;
    }
    Curve_AdvanceAlongPath(&gCameraModeStaffAnimState->pathCurve, pathT);
    *outX = gCameraModeStaffAnimState->pathCurve.sample[0];
    *outZ = gCameraModeStaffAnimState->pathCurve.sample[2];
    return;
}

void CameraModeStaffAnim_subdividePathAngles(s16* outAngles, u16* outCount, s16 baseAngle, s16 deltaAngle, s16 limit) {
    if (deltaAngle >= limit) {
        CameraModeStaffAnim_subdividePathAngles(outAngles, outCount, baseAngle, deltaAngle >> 1, limit);
        CameraModeStaffAnim_subdividePathAngles(outAngles, outCount, baseAngle + (deltaAngle >> 1), deltaAngle >> 1,
                                                limit);
    } else {
        outAngles[(*outCount)++] = baseAngle;
    }
}

void CameraModeStaffAnim_buildPathPoints(f32 baseX, f32 baseZ, f32 targetX, f32 baseY, f32 targetZ, f32 targetY,
                                         s16 angleRange, s16 angleLimit, int* outPointCount) {
    u16 angleCount;
    s16 rot[3];
    f32 vec[3];
    s16 pathAngles[CAMERA_MODE_STAFF_ANIM_PATH_POINT_CAPACITY];
    s16 absAngleRange;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    int i;
    int pointCount;

    if (angleRange < 0) {
        absAngleRange = -angleRange;
    } else {
        absAngleRange = angleRange;
    }

    angleCount = 0;
    CameraModeStaffAnim_subdividePathAngles(pathAngles, &angleCount, 0, absAngleRange, angleLimit);

    deltaX = targetX - baseX;
    deltaY = targetY - baseY;
    deltaZ = targetZ - baseZ;
    i = 1;
    pointCount = 3;

    while (i < angleCount) {
        vec[0] = deltaX;
        vec[1] = deltaY;
        vec[2] = deltaZ;

        rot[0] = angleRange < 0 ? pathAngles[i] : -pathAngles[i];
        rot[1] = 0;
        rot[2] = 0;
        vecRotateZXY(rot, vec);

        gCameraModeStaffAnimState->pointsX[pointCount] = baseX + vec[0];
        gCameraModeStaffAnimState->pointsY[pointCount] = baseY + (deltaY * ((f32)pathAngles[i] / absAngleRange));
        gCameraModeStaffAnimState->pointsZ[pointCount] = baseZ + vec[2];

        i++;
        pointCount++;
    }

    *outPointCount = pointCount;
}

void CameraModeStaffAnim_updateTargetAction(CameraObject* camera, GameObject* target) {
    u16 buttons;
    GameObject* targetObj;
    CameraModeStaffAnimState* state;
    CameraInterface* cam;
    s16 targetClass;
    int zPressed;
    int canView;
    void* lockSlot;
    void* pendingParent;
    CameraModeViewfinderSettings viewfinderSettings;

    pendingParent = target->pendingParentObj;
    if (pendingParent != NULL) {
        return;
    }
    buttons = getButtonsJustPressed(0);
    targetObj = (GameObject*)camera->currentTarget;
    if ((targetObj != NULL && (targetObj->anim.classId == 0x1c || targetObj->anim.classId == 0x2a) &&
         target->anim.classId == 1 && playerIsStaffActionPending(target) != 0) ||
        (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) != 0) {
        lockSlot = &camera->currentTarget;
        cam = *gCameraInterface;
        cam->setMode(CAMERA_MODE_COMBAT_RESOURCE_ID, 1, 0, sizeof(GameObject*), lockSlot, 0x3c, 0xff);
        return;
    }
    zPressed = buttons & PAD_TRIGGER_Z;
    if (zPressed == 0) {
        return;
    }
    targetClass = target->anim.classId;
    if (targetClass != 1) {
        return;
    }
    canView = playerIsInNormalControl(target);
    if (canView == 0) {
        return;
    }
    state = gCameraModeStaffAnimState;
    viewfinderSettings.radius = state->actionParamX;
    viewfinderSettings.yOffset = state->actionParamZ;
    viewfinderSettings.height = state->actionParamY;
    cam = *gCameraInterface;
    cam->setMode(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 1, 0, sizeof(CameraModeViewfinderSettings), &viewfinderSettings, 0,
                 0xff);
}

void CameraModeStaffAnim_copyToCurrent(void) {
}

void CameraModeStaffAnim_free(void) {
    mm_free(gCameraModeStaffAnimState);
    gCameraModeStaffAnimState = NULL;
}

void CameraModeStaffAnim_update(CameraObject* camera) {
    u8 needsReset;
    u32 angle;
    int defaultHandler;
    int yawDelta;
    GameObject* target;
    int pointIndex;
    f32 localPosZ[4];
    f32 localPosY;
    f32 localPosX;
    f32 relX;
    f32 relY;
    f32 relZ;
    f32 relDistXZ;
    f32* pYaddr;

    if (gCameraModeStaffAnimState->pathNotNeeded != 0) {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
    } else {
        if (gCameraModeStaffAnimState->localFrame != (GameObject*)camera->anim.parent) {
            for (pointIndex = 0; pointIndex < gCameraModeStaffAnimState->pathCurve.count; pointIndex++) {
                Obj_TransformLocalPointToWorld(
                    gCameraModeStaffAnimState->pointsX[pointIndex], gCameraModeStaffAnimState->pointsY[pointIndex],
                    gCameraModeStaffAnimState->pointsZ[pointIndex], &gCameraModeStaffAnimState->pointsX[pointIndex],
                    &gCameraModeStaffAnimState->pointsY[pointIndex], &gCameraModeStaffAnimState->pointsZ[pointIndex],
                    gCameraModeStaffAnimState->localFrame);
            }
            for (pointIndex = 0; pointIndex < gCameraModeStaffAnimState->pathCurve.count; pointIndex++) {
                Obj_TransformWorldPointToLocal(
                    gCameraModeStaffAnimState->pointsX[pointIndex], gCameraModeStaffAnimState->pointsY[pointIndex],
                    gCameraModeStaffAnimState->pointsZ[pointIndex], &gCameraModeStaffAnimState->pointsX[pointIndex],
                    &gCameraModeStaffAnimState->pointsY[pointIndex], &gCameraModeStaffAnimState->pointsZ[pointIndex],
                    (GameObject*)camera->anim.parent);
            }
            gCameraModeStaffAnimState->localFrame = (GameObject*)camera->anim.parent;
        }
        target = (GameObject*)camera->anim.targetObj;
        *(pYaddr = &localPosY) = camera->anim.localPosY;
        needsReset = (u8)CameraModeStaffAnim_samplePath(&localPosX, pYaddr, localPosZ, target, camera);
        camera->anim.localPosX = localPosX;
        camera->anim.localPosZ = localPosZ[0];
        defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY, camera->anim.localPosZ,
                                       &camera->anim.worldPosX, &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                       (GameObject*)camera->anim.parentAddress);
        (*(CameraModeStaffAnimBoundsCallback*)(**(int**)(defaultHandler + 4) + 0x1c))(camera, target, -100000.0f,
                                                                                      100000.0f);
        (*(VtableFn*)(**(int**)(defaultHandler + 4) + 0x24))(camera, 1, 3, &gCameraModeStaffAnimState->curveMin,
                                                             &gCameraModeStaffAnimState->curveMax);
        if ((camera->anim.currentMove != 0) || (camera->cameraCollisionActive != 0)) {
            gCameraModeStaffAnimState->initialiseCurve[4] = gCameraModeStaffAnimState->initialiseCurve[4] + timeDelta;
        }
        if (gCameraModeStaffAnimState->initialiseCurve[4] > 0.0f) {
            needsReset =
                camcontrol_getTargetPosition(camera, &target->anim, &camera->anim.worldPosX, &camera->anim.rotY);
            if (needsReset == 1) {
                camcontrol_onTargetTraceBlocked(1);
            }
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            needsReset = 1;
        }
        (*gCameraInterface)->getRelativePosition(camera, &relX, &relY, &relZ, &relDistXZ, 0.0f, 0);
        angle = getAngle((double)relX, (double)relZ);
        yawDelta = 0x8000 - (angle & 0xffff);
        yawDelta = yawDelta - (u32)(u16)camera->anim.rotX;
        if (yawDelta > 0x8000) {
            yawDelta = yawDelta + -0xffff;
        }
        if (yawDelta < -0x8000) {
            yawDelta = yawDelta + 0xffff;
        }
        camera->anim.rotX += yawDelta;
        (*(VtableFn*)(**(int**)(defaultHandler + 4) + 0x18))(camera, (double)target->anim.worldPosY, (double)relDistXZ);
        if (needsReset != 0) {
            (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
        }
        CameraModeStaffAnim_updateTargetAction(camera, target);
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (GameObject*)camera->anim.parent);
    }
    return;
}

static inline f32 CameraModeStaffAnim_angleToRadians(int angle) {
    return (3.1415927f * angle) / 32768.0f;
}

void CameraModeStaffAnim_init(CameraObject* camera, int unused, CameraModeStaffAnimSettings* settings) {
    GameObject* target;
    int view;
    f32 sinFacing;
    f32 cosFacing;
    f32 relAngleRad;
    f32 relSin;
    f32 relCos;
    int facingDelta;
    s16 approachAngle;
    s16 turnAmount;
    s16 absTurn;
    s16 pathAngle;
    s16 threshold;
    f32 pathRadius;
    f32 pathScale;
    f32 baseX;
    f32 baseZ;
    f32 dx;
    f32 dz;
    f32 localPos[3];
    int pointCount;
    int i;

    settings->snapToTarget = 1;
    target = (GameObject*)camera->anim.targetObj;

    if (gCameraModeStaffAnimState == NULL) {
        gCameraModeStaffAnimState = mmAlloc(sizeof(CameraModeStaffAnimState), 0xf, 0);
    }
    memset(gCameraModeStaffAnimState, 0, sizeof(CameraModeStaffAnimState));

    view = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    (*(void (**)(f32*, f32*, f32*, int, f32*))(**(int**)(view + 4) + 0x20))(
        &gCameraModeStaffAnimState->actionParamX, &gCameraModeStaffAnimState->unknown08,
        &gCameraModeStaffAnimState->actionParamZ, 0, &gCameraModeStaffAnimState->actionParamY);

    gCameraModeStaffAnimState->pathNotNeeded = 0;
    gCameraModeStaffAnimState->localFrame = (GameObject*)camera->anim.parent;

    sinFacing = mathSinf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));
    cosFacing = mathCosf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));

    if (gCameraModeStaffAnimState->localFrame != NULL) {
        facingDelta = target->anim.rotX - gCameraModeStaffAnimState->localFrame->anim.rotX;
    } else {
        facingDelta = target->anim.rotX;
    }

    relAngleRad = CameraModeStaffAnim_angleToRadians(facingDelta);
    relSin = mathSinf(relAngleRad);
    relCos = mathCosf(relAngleRad);

    approachAngle = target->anim.rotX - (u16)getAngle(camera->anim.worldPosX - target->anim.worldPosX,
                                                      camera->anim.worldPosZ - target->anim.worldPosZ);
    if (approachAngle > 0x8000) {
        approachAngle = approachAngle - 0xffff;
    }
    if (approachAngle < -0x8000) {
        approachAngle = approachAngle + 0xffff;
    }
    if (approachAngle < 0) {
        approachAngle = -approachAngle;
    }

    threshold = (s16)(182.04445f * (f32)settings->approachThresholdDegrees);
    if (approachAngle < threshold) {
        gCameraModeStaffAnimState->pathNotNeeded = 1;
    } else {
        pathRadius = gCameraModeStaffAnimState->actionParamX * gCameraModeStaffAnimState->actionParamX -
                     gCameraModeStaffAnimState->actionParamZ * gCameraModeStaffAnimState->actionParamZ;
        if (pathRadius < 5.0f) {
            pathRadius = 5.0f;
        }
        pathRadius = sqrtf(pathRadius);

        localPos[0] = (sinFacing * pathRadius) + target->anim.worldPosX;
        localPos[1] = gCameraModeStaffAnimState->actionParamZ +
                      (target->anim.worldPosY + gCameraModeStaffAnimState->actionParamY);
        localPos[2] = (cosFacing * pathRadius) + target->anim.worldPosZ;

        if (settings->snapToTarget != 0) {
            camcontrol_getTargetPosition(camera, &target->anim, localPos, NULL);
        }

        Obj_TransformWorldPointToLocal(localPos[0], localPos[1], localPos[2], &localPos[0], &localPos[1], &localPos[2],
                                       (GameObject*)camera->anim.parent);

        for (pointCount = 0; pointCount < 3; pointCount++) {
            gCameraModeStaffAnimState->pointsX[pointCount] = camera->anim.localPosX;
            gCameraModeStaffAnimState->pointsY[pointCount] = camera->anim.localPosY;
            gCameraModeStaffAnimState->pointsZ[pointCount] = camera->anim.localPosZ;
        }

        dx = camera->anim.localPosX - localPos[0];
        dz = camera->anim.localPosZ - localPos[2];
        pathRadius = 0.5f * sqrtf(dx * dx + dz * dz);
        turnAmount = getAngle(-relSin, -relCos) - (u16)getAngle(dx, dz);

        if (turnAmount > 0x8000) {
            turnAmount = turnAmount - 0xffff;
        }
        if (turnAmount < -0x8000) {
            turnAmount = turnAmount + 0xffff;
        }

        pathAngle = turnAmount;
        if (turnAmount < 0) {
            turnAmount = -turnAmount;
        }

        if (turnAmount > 0x4000) {
            absTurn = 0;
        } else {
            absTurn = 0x4000 - turnAmount;
        }

        if (pathAngle < 0) {
            pathAngle = -(absTurn << 1);
        } else {
            pathAngle = absTurn << 1;
        }

        if (absTurn != 0) {
            pathScale = pathRadius / mathSinf(CameraModeStaffAnim_angleToRadians(absTurn));
        } else {
            pathScale = 0.0f;
        }

        baseX = localPos[0] - (relSin * pathScale);
        baseZ = localPos[2] - (relCos * pathScale);
        gCameraModeStaffAnimState->pathCurve.px = gCameraModeStaffAnimState->pointsX;
        gCameraModeStaffAnimState->pathCurve.py = gCameraModeStaffAnimState->pointsY;
        gCameraModeStaffAnimState->pathCurve.pz = gCameraModeStaffAnimState->pointsZ;
        gCameraModeStaffAnimState->pathCurve.eval = Curve_EvalBSpline;
        gCameraModeStaffAnimState->pathCurve.coeffFn = Curve_BuildBSplineCoeffs;

        CameraModeStaffAnim_buildPathPoints(baseX, baseZ, camera->anim.localPosX, camera->anim.localPosY,
                                            camera->anim.localPosZ, localPos[1], pathAngle, 0x1555, &pointCount);

        i = pointCount;
        for (; i < pointCount + 3; i++) {
            gCameraModeStaffAnimState->pointsX[i] = localPos[0];
            gCameraModeStaffAnimState->pointsY[i] = localPos[1];
            gCameraModeStaffAnimState->pointsZ[i] = localPos[2];
        }

        gCameraModeStaffAnimState->pathCurve.count = i;
        gCameraModeStaffAnimState->pathCurve.dir = 0;
        curvesMove(&gCameraModeStaffAnimState->pathCurve);

        if (pathAngle < 0) {
            pathAngle = -pathAngle;
        }
        if ((pathAngle > 0x2000) && (settings->turnGate != 0)) {
            Sfx_PlayFromObject(0, SFXTRIG_mv_totem_stop);
        }

        pathScale = gCameraModeStaffAnimState->pathCurve.pathLength;
        (*gCameraInterface)
            ->initialise(pathScale, &gCameraModeStaffAnimState->initialiseCurve[0], 20.0f, 0.5f, 1.0f, -10.0f);

        gCameraModeStaffAnimState->curveMin = -100000.0f;
        gCameraModeStaffAnimState->curveMax = 100000.0f;
    }
}

void CameraModeStaffAnim_release(void) {
}

void CameraModeStaffAnim_initialise(void) {
}

CameraModeStaffAnimDescriptor gCameraModeStaffAnimDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeStaffAnim_initialise,
    CameraModeStaffAnim_release,
    NULL,
    CameraModeStaffAnim_init,
    CameraModeStaffAnim_update,
    CameraModeStaffAnim_free,
    CameraModeStaffAnim_copyToCurrent,
    NULL,
};
