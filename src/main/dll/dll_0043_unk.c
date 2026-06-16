/* DLL 0x43 - camera path/climb control [80106F78-801070FC) */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/dll/CAM/camlockon.h"
#include "main/dll/CAM/cutCam.h"
#include "main/dll/CAM/pathcam.h"
#include "main/pad.h"
#include "main/object_transform.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/mm.h"

extern undefined4 FUN_80017814();
extern int objFn_802962b4(int obj);
extern int objFn_80296700(int obj);

extern f32 timeDelta;
extern f32 lbl_803E1740;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;
extern void memset(void* ptr, int value, int size);
extern f32 sqrtf(f32 value);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern f32 lbl_803E1744;
extern f32 lbl_803E1760;
extern f32 lbl_803E1764;
extern f32 lbl_803E1768;
extern f32 lbl_803E176C;
extern f32 lbl_803E1770;
extern f32 lbl_803E1774;
extern f32 lbl_803E1778;

#pragma dont_inline on
void camcontrol_updatePathTargetAction(CameraObject* camera, GameObject* target)
{
    short sVar1;
    u16 buttons;
    GameObject* targetObj;
    struct
    {
        f32 x;
        f32 z;
        s16 y;
    } local_28;

    if (*(u32*)&target->pendingParentObj == 0)
    {
        buttons = getButtonsJustPressed(0);
        targetObj = (GameObject*)camera->currentTarget;
        if (targetObj != NULL)
        {
            sVar1 = targetObj->anim.classId;
            if (sVar1 == 0x1c)
            {
                goto checkActiveTarget;
            }
            if (sVar1 != 0x2a)
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
        if ((((buttons & 0x10) != 0) && (target->anim.classId == 1)) &&
            (objFn_802962b4((int)target) != 0))
        {
            local_28.x = gCamcontrolPathState->actionParamX;
            local_28.z = gCamcontrolPathState->actionParamZ;
            local_28.y = (s16)gCamcontrolPathState->actionParamY;
            (*gCameraInterface)->setMode(0x44, 1, 0, 0xc, &local_28, 0, 0xff);
        }
    }
done:
    return;
}
#pragma dont_inline reset

void camcontrol_releasePathState(void)
{
    FUN_80017814(gCamcontrolPathState);
    gCamcontrolPathState = 0;
    return;
}

void CameraModeStaffAnim_copyToCurrent_nop(void)
{
}

#pragma dont_inline on
void camclimb_update(CameraObject* cam)
{
    extern uint getAngle();
    extern int camcontrol_samplePathState();
    byte needsReset;
    uint angle;
    int defaultHandler;
    int yawDelta;
    GameObject* target;
    int pointIndex;
    float localPosZ[4];
    float localPosY;
    float localPosX;
    float relX;
    undefined relY[4];
    float relZ;
    float relDistXZ;

    if (gCamcontrolPathState->active != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        if ((u32)gCamcontrolPathState->localFrameObj != *(u32*)&cam->anim.parent)
        {
            for (pointIndex = 0; pointIndex < gCamcontrolPathState->pathCurve.count; pointIndex = pointIndex + 1)
            {
                Obj_TransformLocalPointToWorld(gCamcontrolPathState->pointsX[pointIndex],
                                               gCamcontrolPathState->pointsY[pointIndex], gCamcontrolPathState->pointsZ[pointIndex],
                                               &gCamcontrolPathState->pointsX[pointIndex], &gCamcontrolPathState->pointsY[pointIndex],
                                               &gCamcontrolPathState->pointsZ[pointIndex], gCamcontrolPathState->localFrameObj);
            }
            for (pointIndex = 0; pointIndex < gCamcontrolPathState->pathCurve.count; pointIndex = pointIndex + 1)
            {
                Obj_TransformWorldPointToLocal(gCamcontrolPathState->pointsX[pointIndex],
                                               gCamcontrolPathState->pointsY[pointIndex], gCamcontrolPathState->pointsZ[pointIndex],
                                               &gCamcontrolPathState->pointsX[pointIndex], &gCamcontrolPathState->pointsY[pointIndex],
                                               &gCamcontrolPathState->pointsZ[pointIndex], *(int*)&cam->anim.parent);
            }
            gCamcontrolPathState->localFrameObj = *(int*)&cam->anim.parent;
        }
        target = (GameObject*)cam->anim.targetObj;
        localPosY = cam->anim.localPosY;
        needsReset = camcontrol_samplePathState(&localPosX, &localPosY, localPosZ, target, cam);
        cam->anim.localPosX = localPosX;
        cam->anim.localPosZ = localPosZ[0];
        defaultHandler = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        Obj_TransformLocalPointToWorld(cam->anim.localPosX, cam->anim.localPosY,
                                       cam->anim.localPosZ, &cam->anim.worldPosX, &cam->anim.worldPosY,
                                       &cam->anim.worldPosZ, *(int*)&cam->anim.parent);
        (*(code*)(**(int**)(defaultHandler + 4) + 0x1c))
            ((double)lbl_803E1758, (double)lbl_803E175C, cam, target);
        (*(code*)(**(int**)(defaultHandler + 4) + 0x24))(cam, 1, 3,
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
        (*gCameraInterface)->getRelativePosition(lbl_803E1740, (int)cam, &relX,
                                                 (f32*)relY, &relZ, &relDistXZ, 0);
        angle = getAngle((double)relX, (double)relZ);
        yawDelta = 0x8000 - (angle & 0xffff);
        yawDelta = yawDelta - (uint)(u16)
        cam->anim.rotX;
        if (0x8000 < yawDelta)
        {
            yawDelta = yawDelta + -0xffff;
        }
        if (yawDelta < -0x8000)
        {
            yawDelta = yawDelta + 0xffff;
        }
        cam->anim.rotX = (s16)(cam->anim.rotX + yawDelta);
        (*(code*)(**(int**)(defaultHandler + 4) + 0x18))
            ((double)target->anim.worldPosY, (double)relDistXZ, cam);
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
    return (lbl_803E1760 * (f32)angle) / lbl_803E1764;
}

#pragma scheduling off
#pragma peephole off
void CameraModeStaffAnim_init(CameraObject* camera, undefined4 param_2, u8* settings)
{
    extern int getAngle(f32 dx, f32 dz);
    GameObject* target;
    int view;
    f32 cosFacing;
    f32 sinFacing;
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

    cosFacing = mathSinf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));
    sinFacing = mathCosf(CameraModeStaffAnim_angleToRadians(target->anim.rotX));

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

    threshold = (s16)(lbl_803E1768 * (f32)(*(s16*)settings));
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

        localPos[0] = (cosFacing * pathRadius) + target->anim.worldPosX;
        localPos[1] = gCamcontrolPathState->actionParamZ +
            (target->anim.worldPosY + gCamcontrolPathState->actionParamY);
        localPos[2] = (sinFacing * pathRadius) + target->anim.worldPosZ;

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

        (*gCameraInterface)->initialise(&gCamcontrolPathState->initialiseCurve[0],
                                        gCamcontrolPathState->pathCurve.pathLength,
                                        lbl_803E1774, lbl_803E1770, lbl_803E1744,
                                        lbl_803E1778);

        gCamcontrolPathState->curveMin = lbl_803E1758;
        gCamcontrolPathState->curveMax = lbl_803E175C;
    }
}

void CameraModeStaffAnim_release(void)
{
}

void CameraModeStaffAnim_initialise(void)
{
}
