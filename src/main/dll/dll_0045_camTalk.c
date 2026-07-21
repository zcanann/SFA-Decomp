/* DLL 0x0045 - camera talk / NPC-speak mode [80107AEC-8010847C) */
#include "main/dll/CAM/cambike_state.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/mm.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/cutCam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/object_transform.h"
#include "string.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/player_api.h"
#include "main/dll/DB/DBprotection.h"
#include "main/dll/SB/dll_01E8_sbgalleon.h"

CameraModeBikeState* gCamTalkBikeState;
extern const f32 lbl_803E17B4;
extern const f32 lbl_803E17A8;
extern ViewfinderState* lbl_803DD548;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;

void CameraModeBike_copyToCurrent(f32* inputs)
{
    gCamTalkBikeState->turnInput = inputs[0];
    gCamTalkBikeState->heightInput = inputs[1];
    gCamTalkBikeState->rollInput = inputs[2];
    gCamTalkBikeState->pitchTarget = inputs[3];
}

void CameraModeBike_free(void)
{
    mm_free(gCamTalkBikeState);
    gCamTalkBikeState = 0;
}

void CameraModeBike_update(CameraObject* camera)
{
    float rollStep;
    int targetAngle;
    float followDist;
    float heightT;
    float kFollowB;
    float kFollowA;
    short angleDelta;
    GameObject* target;
    CameraModeBikeState* st;
    float sinYaw;
    float cosYaw;
    float sinPitch;
    float cosPitch;
    float pivotX;
    float pivotY;
    float pivotZ;
    MatrixTransform xformIn;
    float mtxBuf[17];

    (*gCameraInterface)->getDefaultHandlerEntry();
    target = camera->anim.targetObj;
    if (target != NULL)
    {
        camera->fov = (85.0f);
        xformIn.x = target->anim.worldPosX;
        xformIn.y = target->anim.worldPosY;
        xformIn.z = target->anim.worldPosZ;
        xformIn.scale = (1.0f);
        xformIn.rotX = target->anim.rotX;
        xformIn.rotY = gCamTalkBikeState->pitchTarget;
        xformIn.rotZ = 0;
        setMatrixFromObjectPos(mtxBuf, &xformIn);
        Matrix_TransformPoint(mtxBuf, (0.0f), (2e+01f), (0.0f), &pivotX, &pivotY, &pivotZ);
        angleDelta = 0x8000 - target->anim.rotX;
        camera->anim.rotX = angleDelta;
        st = gCamTalkBikeState;
        st->smoothedYawOffset += (0.1f) * ((f32)((12.0f) * st->turnInput) - st->smoothedYawOffset);
        camera->anim.rotX = camera->anim.rotX + gCamTalkBikeState->smoothedYawOffset;
        targetAngle = (int)((3072.0f) - gCamTalkBikeState->pitchTarget);
        angleDelta = targetAngle - (u16)camera->anim.rotY;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        camera->anim.rotY += (angleDelta >> 3);
        sinYaw = mathSinf((3.1415927f) * (camera->anim.rotX - 0x4000) / (32768.0f));
        cosYaw = mathCosf((3.1415927f) * (camera->anim.rotX - 0x4000) / (32768.0f));
        cosPitch = mathCosf((3.1415927f) * camera->anim.rotY / (32768.0f));
        sinPitch = mathSinf((3.1415927f) * camera->anim.rotY / (32768.0f));
        st = gCamTalkBikeState;
        heightT = -st->heightInput / (6.0f);
        kFollowA = lbl_803E17A8;
        kFollowB = (25.0f);
        heightT =
            (heightT < (0.0f)) ? (0.0f) : ((heightT > (1.0f)) ? (1.0f) : heightT);
        st->followDistance += kFollowA * ((kFollowB * heightT + (5e+01f)) - st->followDistance);
        followDist = gCamTalkBikeState->followDistance;
        kFollowA = followDist * sinPitch;
        kFollowB = followDist * cosPitch;
        cosYaw = kFollowB * cosYaw;
        kFollowB = kFollowB * sinYaw;
        camera->anim.worldPosX = pivotX + cosYaw;
        camera->anim.worldPosY = pivotY + kFollowA;
        camera->anim.worldPosZ = pivotZ + kFollowB;
        targetAngle = (int)(lbl_803E17A8 * gCamTalkBikeState->rollInput);
        angleDelta = targetAngle - (u16)camera->anim.rotZ;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        rollStep = angleDelta * timeDelta;
        camera->anim.rotZ += rollStep * lbl_803E17B4;
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (u32)camera->anim.parent);
    }
    return;
}

void CameraModeBike_init(CameraObject* camera)
{

    if (gCamTalkBikeState == 0)
    {
        gCamTalkBikeState = (CameraModeBikeState*)mmAlloc(sizeof(CameraModeBikeState), 0xf, 0);
    }
    memset(gCamTalkBikeState, 0, sizeof(CameraModeBikeState));
    gCamTalkBikeState->entryFov = camera->fov;
    gCamTalkBikeState->defaultFov = (85.0f);
    gCamTalkBikeState->defaultScale = (1.0f);
    gCamTalkBikeState->followDistance = (5e+01f);
}

void CameraModeBike_release(void)
{
}

void CameraModeBike_initialise(void)
{
}

void firstPersonPlaceCamera(GameObject* focus, int resetClamp)
{
    register GameObject* self = focus;
    GameObject* galleon;
    int galleonState;
    float prevPosZ;
    float prevPosY;
    float prevPosX;
    float localOffset[3];

    if (self->anim.classId == 1)
    {
        cameraGetPrevPos2(self, &prevPosX, &prevPosY, &prevPosZ);
        if (((resetClamp != 0) || (lbl_803DD548->camPosX != prevPosX)) || (lbl_803DD548->camPosZ != prevPosZ))
        {
            lbl_803DD548->clampedPosY = prevPosY;
        }
        lbl_803DD548->camPosX = prevPosX;
        lbl_803DD548->camPosY = prevPosY;
        lbl_803DD548->camPosZ = prevPosZ;
    }
    else
    {
        lbl_803DD548->camPosX = self->anim.worldPosX;
        lbl_803DD548->camPosY = lbl_803E17C0 + self->anim.worldPosY;
        lbl_803DD548->camPosZ = self->anim.worldPosZ;
        lbl_803DD548->clampedPosY = lbl_803DD548->camPosY;
    }
    galleon = getSbGalleon();
    if (galleon != NULL)
    {
        galleonState = DBprotection_getCameraState(galleon);
        if (galleonState == 2)
        {
            localOffset[0] = self->anim.worldPosX - galleon->anim.worldPosX;
            localOffset[1] = (lbl_803E17C0 + self->anim.worldPosY) - galleon->anim.worldPosY;
            localOffset[2] = self->anim.worldPosZ - galleon->anim.worldPosZ;
            vecRotateZXY(&galleon->anim.rotX, localOffset);
            lbl_803DD548->camPosX = galleon->anim.worldPosX + localOffset[0];
            lbl_803DD548->camPosY = galleon->anim.worldPosY + localOffset[1];
            lbl_803DD548->camPosZ = galleon->anim.worldPosZ + localOffset[2];
        }
    }
    return;
}

void firstPersonExit(CameraObject* camera)
{
    register CameraObject* self = camera;
    GameObject* target;
    CameraModeBikeState* st;
    float tangent;
    float dx;
    float dz;
    int targetYaw;
    float targetPos[3];
    u8 unusedAngle[4];

    target = (GameObject*)self->anim.targetObj;
    lbl_803DD548->posXCurve.start = self->anim.worldPosX;
    tangent = lbl_803E17C4;
    lbl_803DD548->posXCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->posXCurve.endTangent = tangent;
    lbl_803DD548->posYCurve.start = self->anim.worldPosY;
    lbl_803DD548->posYCurve.startTangent = tangent;
    lbl_803DD548->posYCurve.endTangent = tangent;
    lbl_803DD548->posZCurve.start = self->anim.worldPosZ;
    lbl_803DD548->posZCurve.startTangent = tangent;
    lbl_803DD548->posZCurve.endTangent = tangent;
    camcontrol_getTargetPosition(self, &target->anim, targetPos, (s16*)unusedAngle);
    lbl_803DD548->posXCurve.end = targetPos[0];
    lbl_803DD548->posYCurve.end = targetPos[1];
    lbl_803DD548->posZCurve.end = targetPos[2];
    dx = lbl_803DD548->posXCurve.end - lbl_803DD548->posXCurve.start;
    dz = lbl_803DD548->posZCurve.end - lbl_803DD548->posZCurve.start;
    lbl_803DD548->exitDistance = sqrtf(dx * dx + dz * dz);
    lbl_803DD548->viewCurve.px = &lbl_803DD548->yawCurve.start;
    lbl_803DD548->viewCurve.py = &lbl_803DD548->pitchCurve.start;
    lbl_803DD548->viewCurve.pz = NULL;
    lbl_803DD548->viewCurve.count = 4;
    lbl_803DD548->viewCurve.dir = 0;
    lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
    lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
    lbl_803DD548->yawCurve.start = (float)(int)self->anim.rotX;
    targetYaw = getAngle((double)(lbl_803DD548->posXCurve.end - target->anim.worldPosX),
                         (double)(lbl_803DD548->posZCurve.end - target->anim.worldPosZ));
    lbl_803DD548->yawCurve.end = (float)(int)(short)(0x8000 - targetYaw);
    tangent = lbl_803E17C4;
    lbl_803DD548->yawCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->yawCurve.endTangent = tangent;
    if (((lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end) > lbl_803E17C8) ||
        ((lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end) < lbl_803E17CC))
    {
        if (lbl_803DD548->yawCurve.start < lbl_803E17C4)
        {
            lbl_803DD548->yawCurve.start = *(f32*)&lbl_803DD548->yawCurve.start + lbl_803E17D0;
        }
        else
        {
            if (lbl_803DD548->yawCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->yawCurve.end = *(f32*)&lbl_803DD548->yawCurve.end + lbl_803E17D0;
            }
        }
    }
    lbl_803DD548->pitchCurve.start = (float)(int)self->anim.rotY;
    tangent = lbl_803E17C4;
    lbl_803DD548->pitchCurve.end = lbl_803E17C4;
    lbl_803DD548->pitchCurve.startTangent = tangent;
    lbl_803DD548->pitchCurve.endTangent = tangent;
    if (((lbl_803DD548->pitchCurve.start - lbl_803DD548->pitchCurve.end) > lbl_803E17C8) ||
        ((lbl_803DD548->pitchCurve.start - lbl_803DD548->pitchCurve.end) < lbl_803E17CC))
    {
        if (lbl_803DD548->pitchCurve.start < lbl_803E17C4)
        {
            lbl_803DD548->pitchCurve.start = *(f32*)&lbl_803DD548->pitchCurve.start + lbl_803E17D0;
        }
        else
        {
            if (lbl_803DD548->pitchCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->pitchCurve.end = *(f32*)&lbl_803DD548->pitchCurve.end + lbl_803E17D0;
            }
        }
    }
    curvesMove(&lbl_803DD548->viewCurve);
}
