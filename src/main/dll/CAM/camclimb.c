#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_path_state.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern uint getAngle();
extern undefined4 doNothing_80103660();
extern char camcontrol_getTargetPosition();
extern char camcontrol_samplePathState();
extern undefined4 camcontrol_updatePathTargetAction();

extern f32 timeDelta;
extern f32 lbl_803E1740;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;

/*
 * --INFO--
 *
 * Function: camclimb_update
 * EN v1.0 Address: 0x801070FC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x80107398
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camclimb_update(CameraObject* cam)
{
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
        if (gCamcontrolPathState->localFrameObj != *(int*)&cam->anim.parent)
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
        if ((cam->anim.currentMove != 0) || (cam->unk142 != 0))
        {
            gCamcontrolPathState->initialiseCurve[4] = gCamcontrolPathState->initialiseCurve[4] + timeDelta;
        }
        if (gCamcontrolPathState->initialiseCurve[4] > lbl_803E1740)
        {
            needsReset = camcontrol_getTargetPosition(cam, target, &cam->anim.worldPosX, &cam->anim.rotY);
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
