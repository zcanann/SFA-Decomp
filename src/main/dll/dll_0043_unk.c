/*
 * DLL 0x43 - climb/path camera control.
 *
 * Drives the camera while the player climbs along a B-spline path:
 *   camclimb_update      - per-frame: transforms the path points into the
 *                          camera parent's local frame, samples the path
 *                          state, tracks yaw toward the target and triggers
 *                          a fallback to camera mode 0x42 on reset.
 *   CameraModeStaffAnim_init - builds the B-spline path (allocating the
 *                          shared gCamcontrolPathState), choosing an active
 *                          fast path or constructing curve points; plays a
 *                          snort sfx on a large turn.
 *   camcontrol_updatePathTargetAction - reads the pad and switches to
 *                          camera mode 0x49 (follow) or 0x44 (action).
 *
 * All path geometry lives in the singleton gCamcontrolPathState.
 */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/dll/CAM/camlockon.h"
#include "main/dll/CAM/cutCam.h"
#include "main/pad.h"
#include "main/object_transform.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/dll/modgfx.h"

#define PAD_TRIGGER_Z 0x10

extern int objFn_802962b4(int obj);
extern int objFn_80296700(int obj);
extern f32 timeDelta;
extern void memset(void* ptr, int value, int size);
extern f32 sqrtf(f32 value);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 gCamStaffAnimCurveMin;
extern f32 gCamStaffAnimCurveMax;
extern f32 gCamStaffAnimPi;
extern f32 gCamStaffAnimHalfCircleBams;
extern f32 gCamStaffAnimDegToBams;
extern f32 lbl_803E176C;
extern f32 lbl_803E1770;
extern f32 lbl_803E1774;
extern f32 lbl_803E1778;

#pragma dont_inline on
void camcontrol_updatePathTargetAction(CameraObject* camera, GameObject* target)
{
    short targetClassId;
    u16 buttons;
    GameObject* targetObj;
    struct
    {
        f32 x;
        f32 z;
        s16 y;
    } actionPayload;

    if (*(u32*)&target->pendingParentObj == 0)
    {
        buttons = getButtonsJustPressed(0);
        targetObj = (GameObject*)camera->currentTarget;
        if (targetObj != NULL)
        {
            targetClassId = targetObj->anim.classId;
            if (targetClassId == 0x1c)
            {
                goto checkActiveTarget;
            }
            if (targetClassId != 0x2a)
            {
                goto checkOverrideFlag;
            }
        checkActiveTarget:
            if (target->anim.classId != 1)
            {
                goto checkOverrideFlag;
            }
            if (objFn_80296700((int)target) != 0)
            {
                goto sendFollowAction;
            }
        }
    checkOverrideFlag:
        if ((camera->targetFlags & 2) != 0)
        {
        sendFollowAction:
            (*gCameraInterface)->setMode(0x49, 1, 0, 4, &camera->currentTarget, 0x3c, 0xff);
            goto done;
        }
        if ((((buttons & PAD_TRIGGER_Z) != 0) && (target->anim.classId == 1)) &&
            (objFn_802962b4((int)target) != 0))
        {
            actionPayload.x = gCamcontrolPathState->actionParamX;
            actionPayload.z = gCamcontrolPathState->actionParamZ;
            actionPayload.y = gCamcontrolPathState->actionParamY;
            (*gCameraInterface)->setMode(0x44, 1, 0, 0xc, &actionPayload, 0, 0xff);
        }
    }
done:
    return;
}
#pragma dont_inline reset

void camcontrol_releasePathState(void)
{
    FUN_80017814(gCamcontrolPathState);
    gCamcontrolPathState = NULL;
}

void CameraModeStaffAnim_copyToCurrent_nop(void)
{
}

#pragma dont_inline on
void camclimb_update(CameraObject* cam)
{
    extern int getAngle(float y, float x);
    extern int camcontrol_samplePathState();
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
    f32 *pYaddr;

    if (gCamcontrolPathState->active != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        if ((u32)gCamcontrolPathState->localFrameObj != *(u32*)&cam->anim.parent)
        {
            for (pointIndex = 0; pointIndex < gCamcontrolPathState->pathCurve.count; pointIndex++)
            {
                Obj_TransformLocalPointToWorld(gCamcontrolPathState->pointsX[pointIndex],
                                               gCamcontrolPathState->pointsY[pointIndex], gCamcontrolPathState->pointsZ[pointIndex],
                                               &gCamcontrolPathState->pointsX[pointIndex], &gCamcontrolPathState->pointsY[pointIndex],
                                               &gCamcontrolPathState->pointsZ[pointIndex], gCamcontrolPathState->localFrameObj);
            }
            for (pointIndex = 0; pointIndex < gCamcontrolPathState->pathCurve.count; pointIndex++)
            {
                Obj_TransformWorldPointToLocal(gCamcontrolPathState->pointsX[pointIndex],
                                               gCamcontrolPathState->pointsY[pointIndex], gCamcontrolPathState->pointsZ[pointIndex],
                                               &gCamcontrolPathState->pointsX[pointIndex], &gCamcontrolPathState->pointsY[pointIndex],
                                               &gCamcontrolPathState->pointsZ[pointIndex], *(int*)&cam->anim.parent);
            }
            gCamcontrolPathState->localFrameObj = *(int*)&cam->anim.parent;
        }
        target = (GameObject*)cam->anim.targetObj;
        *(pYaddr = &localPosY) = cam->anim.localPosY;
        needsReset = camcontrol_samplePathState(&localPosX, pYaddr, localPosZ, target, cam);
        cam->anim.localPosX = localPosX;
        cam->anim.localPosZ = localPosZ[0];
        defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        Obj_TransformLocalPointToWorld(cam->anim.localPosX, cam->anim.localPosY,
                                       cam->anim.localPosZ, &cam->anim.worldPosX, &cam->anim.worldPosY,
                                       &cam->anim.worldPosZ, *(int*)&cam->anim.parent);
        (*(VtableFn*)(**(int**)(defaultHandler + 4) + 0x1c))
            (cam, target, (double)gCamStaffAnimCurveMin, (double)gCamStaffAnimCurveMax);
        (*(VtableFn*)(**(int**)(defaultHandler + 4) + 0x24))(cam, 1, 3,
                                                         &gCamcontrolPathState->curveMin,
                                                         &gCamcontrolPathState->curveMax);
        if ((cam->anim.currentMove != 0) || (cam->cameraCollisionActive != 0))
        {
            gCamcontrolPathState->initialiseCurve[4] = gCamcontrolPathState->initialiseCurve[4] + timeDelta;
        }
        if (gCamcontrolPathState->initialiseCurve[4] > lbl_803E1740)
        {
            needsReset = camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
            if (needsReset == 1)
            {
                doNothing_80103660(1);
            }
            cam->probePosX = cam->anim.worldPosX;
            cam->probePosY = cam->anim.worldPosY;
            cam->probePosZ = cam->anim.worldPosZ;
            needsReset = 1;
        }
        ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
            (int)cam, &relX, &relY, &relZ, &relDistXZ, lbl_803E1740, 0);
        angle = getAngle((double)relX, (double)relZ);
        yawDelta = 0x8000 - (angle & 0xffff);
        yawDelta = yawDelta - (u32)(u16)cam->anim.rotX;
        if (0x8000 < yawDelta)
        {
            yawDelta = yawDelta + -0xffff;
        }
        if (yawDelta < -0x8000)
        {
            yawDelta = yawDelta + 0xffff;
        }
        cam->anim.rotX += yawDelta;
        (*(VtableFn*)(**(int**)(defaultHandler + 4) + 0x18))
            (cam, (double)target->anim.worldPosY, (double)relDistXZ);
        if (needsReset != 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
        }
        camcontrol_updatePathTargetAction(cam, target);
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY,
                                       cam->anim.worldPosZ, &cam->anim.localPosX, &cam->anim.localPosY,
                                       &cam->anim.localPosZ, *(int*)&cam->anim.parent);
    }
    return;
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
static f32 CameraModeStaffAnim_angleToRadians(int angle)
{
    return (gCamStaffAnimPi * angle) / gCamStaffAnimHalfCircleBams;
}

#pragma scheduling off
#pragma peephole off
void CameraModeStaffAnim_init(CameraObject* camera, int unused, u8* settings)
{
    extern int getAngle(float y, float x);
    GameObject* target;
    int view;
    f32 sinFacing;
    f32 cosFacing;
    f32 relAngleRad;
    f32 relCos;
    f32 relSin;
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

    settings[3] = 1;
    target = (GameObject*)camera->anim.targetObj;

    if (gCamcontrolPathState == NULL)
    {
        gCamcontrolPathState = mmAlloc(sizeof(CamcontrolPathState), 0xf, 0);
    }
    memset(gCamcontrolPathState, 0, sizeof(CamcontrolPathState));

    view = (int)(*gCameraInterface)->getDefaultHandlerEntry();
    (*(void (**)(f32*, f32*, f32*, int, f32*))(**(int**)(view + 4) + 0x20))
    (&gCamcontrolPathState->actionParamX, &gCamcontrolPathState->pad08,
     &gCamcontrolPathState->actionParamZ, 0, &gCamcontrolPathState->actionParamY);

    gCamcontrolPathState->active = 0;
    gCamcontrolPathState->localFrameObj = *(int*)&camera->anim.parent;

    sinFacing = mathSinf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));
    cosFacing = mathCosf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));

    if ((void*)gCamcontrolPathState->localFrameObj != NULL)
    {
        facingDelta = target->anim.rotX - ((s16*)gCamcontrolPathState->localFrameObj)[0];
    }
    else
    {
        facingDelta = target->anim.rotX;
    }

    relAngleRad = CameraModeStaffAnim_angleToRadians(facingDelta);
    relCos = mathSinf(relAngleRad);
    relSin = mathCosf(relAngleRad);

    approachAngle = target->anim.rotX - (u16)getAngle(camera->anim.worldPosX - target->anim.worldPosX,
                                                      camera->anim.worldPosZ - target->anim.worldPosZ);
    if (approachAngle > 0x8000)
    {
        approachAngle = approachAngle - 0xffff;
    }
    if (approachAngle < -0x8000)
    {
        approachAngle = approachAngle + 0xffff;
    }
    if (approachAngle < 0)
    {
        approachAngle = -approachAngle;
    }

    threshold = (s16)(gCamStaffAnimDegToBams * (f32)(*(s16*)settings));
    if (approachAngle < threshold)
    {
        gCamcontrolPathState->active = 1;
    }
    else
    {
        pathRadius = gCamcontrolPathState->actionParamX * gCamcontrolPathState->actionParamX -
            gCamcontrolPathState->actionParamZ * gCamcontrolPathState->actionParamZ;
        if (pathRadius < lbl_803E176C)
        {
            pathRadius = lbl_803E176C;
        }
        pathRadius = sqrtf(pathRadius);

        localPos[0] = (sinFacing * pathRadius) + target->anim.worldPosX;
        localPos[1] = gCamcontrolPathState->actionParamZ +
            (target->anim.worldPosY + gCamcontrolPathState->actionParamY);
        localPos[2] = (cosFacing * pathRadius) + target->anim.worldPosZ;

        if (settings[3] != 0)
        {
            camcontrol_getTargetPosition(camera, &target->anim, localPos, NULL);
        }

        Obj_TransformWorldPointToLocal(localPos[0], localPos[1], localPos[2], &localPos[0],
                                       &localPos[1], &localPos[2], *(int*)&camera->anim.parent);

        for (pointCount = 0; pointCount < 3; pointCount++)
        {
            gCamcontrolPathState->pointsX[pointCount] = camera->anim.localPosX;
            gCamcontrolPathState->pointsY[pointCount] = camera->anim.localPosY;
            gCamcontrolPathState->pointsZ[pointCount] = camera->anim.localPosZ;
        }

        dx = camera->anim.localPosX - localPos[0];
        dz = camera->anim.localPosZ - localPos[2];
        pathRadius = lbl_803E1770 * sqrtf(dx * dx + dz * dz);
        turnAmount = getAngle(-relCos, -relSin) - (u16)getAngle(dx, dz);

        if (turnAmount > 0x8000)
        {
            turnAmount = turnAmount - 0xffff;
        }
        if (turnAmount < -0x8000)
        {
            turnAmount = turnAmount + 0xffff;
        }

        pathAngle = turnAmount;
        if (turnAmount < 0)
        {
            turnAmount = -turnAmount;
        }

        if (turnAmount > 0x4000)
        {
            absTurn = 0;
        }
        else
        {
            absTurn = 0x4000 - turnAmount;
        }

        if (pathAngle < 0)
        {
            pathAngle = -(absTurn << 1);
        }
        else
        {
            pathAngle = absTurn << 1;
        }

        if (absTurn != 0)
        {
            pathScale = pathRadius / mathSinf(CameraModeStaffAnim_angleToRadians(absTurn));
        }
        else
        {
            pathScale = lbl_803E1740;
        }

        baseX = localPos[0] - (relCos * pathScale);
        baseZ = localPos[2] - (relSin * pathScale);
        gCamcontrolPathState->pathCurve.px = gCamcontrolPathState->pointsX;
        gCamcontrolPathState->pathCurve.py = gCamcontrolPathState->pointsY;
        gCamcontrolPathState->pathCurve.pz = gCamcontrolPathState->pointsZ;
        gCamcontrolPathState->pathCurve.eval = Curve_EvalBSpline;
        gCamcontrolPathState->pathCurve.coeffFn = Curve_BuildBSplineCoeffs;

        camcontrol_buildPathPoints(baseX, baseZ,
                                   camera->anim.localPosX, camera->anim.localPosY, camera->anim.localPosZ,
                                   localPos[1], pathAngle, 0x1555, &pointCount);

        i = pointCount;
        for (; i < pointCount + 3; i++)
        {
            gCamcontrolPathState->pointsX[i] = localPos[0];
            gCamcontrolPathState->pointsY[i] = localPos[1];
            gCamcontrolPathState->pointsZ[i] = localPos[2];
        }

        gCamcontrolPathState->pathCurve.count = i;
        gCamcontrolPathState->pathCurve.dir = 0;
        curvesMove(&gCamcontrolPathState->pathCurve);

        if (pathAngle < 0)
        {
            pathAngle = -pathAngle;
        }
        if ((pathAngle > 0x2000) && (settings[2] != 0))
        {
            Sfx_PlayFromObject(0, SFXsc_snort03);
        }

        pathScale = gCamcontrolPathState->pathCurve.pathLength;
        (*gCameraInterface)->initialise(pathScale,
                                        &gCamcontrolPathState->initialiseCurve[0],
                                        lbl_803E1774, lbl_803E1770, lbl_803E1744,
                                        lbl_803E1778);

        gCamcontrolPathState->curveMin = gCamStaffAnimCurveMin;
        gCamcontrolPathState->curveMax = gCamStaffAnimCurveMax;
    }
}

void CameraModeStaffAnim_release(void)
{
}

void CameraModeStaffAnim_initialise(void)
{
}
