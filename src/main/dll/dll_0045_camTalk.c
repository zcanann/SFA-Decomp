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

CameraModeBikeState* gCamTalkBikeState;
extern ViewfinderState* lbl_803DD548;
extern f32 lbl_803E1780;
extern const f32 gCamTalkDefaultFov;
extern const f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern const f32 lbl_803E1790;
extern const f32 lbl_803E1794;
extern const f32 lbl_803E1798;
extern const f32 gCamTalkPi;
extern const f32 gCamTalkAngleUnitScale;
extern const f32 lbl_803E17A4;
extern const f32 lbl_803E17A8;
extern const f32 gCamTalkDefaultFollowDist;
extern const f32 lbl_803E17B0;
extern const f32 lbl_803E17B4;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern GameObject* getSbGalleon(void);
extern int DBprotection_getCameraState(GameObject* obj);
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

#pragma opt_propagation off
#pragma opt_common_subs off
void CameraModeBike_update(CameraObject* camera)
{
    float rollStep;
    int rotVal;
    float followDist;
    float clampedHeight;
    float kFollowB;
    float kFollowA;
    short angleDelta;
    GameObject* target;
    CameraModeBikeState* st;
    float sinYaw;
    float cosYaw;
    float sinPitch;
    float cosPitch;
    float posZ;
    float posY;
    float posX;
    MatrixTransform xformIn;
    float mtxBuf[17];

    (*gCameraInterface)->getDefaultHandlerEntry();
    target = (GameObject*)camera->anim.targetObj;
    if (target != NULL)
    {
        camera->fov = gCamTalkDefaultFov;
        xformIn.x = target->anim.worldPosX;
        xformIn.y = target->anim.worldPosY;
        xformIn.z = target->anim.worldPosZ;
        xformIn.scale = lbl_803E1788;
        xformIn.rotX = target->anim.rotX;
        xformIn.rotY = gCamTalkBikeState->pitchTarget;
        xformIn.rotZ = 0;
        setMatrixFromObjectPos(mtxBuf, &xformIn);
        Matrix_TransformPoint(mtxBuf, lbl_803E1780, lbl_803E178C, lbl_803E1780, &posZ, &posY, &posX);
        angleDelta = 0x8000 - target->anim.rotX;
        camera->anim.rotX = angleDelta;
        st = gCamTalkBikeState;
        st->smoothedYawOffset += lbl_803E1790 * ((f32)(lbl_803E1794 * st->turnInput) - st->smoothedYawOffset);
        camera->anim.rotX = (f32)(s32)camera->anim.rotX + gCamTalkBikeState->smoothedYawOffset;
        rotVal = (int)(lbl_803E1798 - gCamTalkBikeState->pitchTarget);
        angleDelta = rotVal - (u16)camera->anim.rotY;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        camera->anim.rotY += (angleDelta >> 3);
        sinYaw = mathSinf(gCamTalkPi * (f32)(s32)((int)camera->anim.rotX - 0x4000) / gCamTalkAngleUnitScale);
        cosYaw = mathCosf(gCamTalkPi * (f32)(s32)((int)camera->anim.rotX - 0x4000) / gCamTalkAngleUnitScale);
        cosPitch = mathCosf(gCamTalkPi * (f32)(s32)camera->anim.rotY / gCamTalkAngleUnitScale);
        sinPitch = mathSinf(gCamTalkPi * (f32)(s32)camera->anim.rotY / gCamTalkAngleUnitScale);
        st = gCamTalkBikeState;
        clampedHeight = -st->heightInput / lbl_803E17A4;
        kFollowA = lbl_803E17A8;
        kFollowB = lbl_803E17B0;
        clampedHeight =
            (clampedHeight < lbl_803E1780) ? lbl_803E1780 : ((clampedHeight > lbl_803E1788) ? lbl_803E1788 : clampedHeight);
        st->followDistance += kFollowA * ((kFollowB * clampedHeight + gCamTalkDefaultFollowDist) - st->followDistance);
        followDist = gCamTalkBikeState->followDistance;
        kFollowA = followDist * sinPitch;
        kFollowB = followDist * cosPitch;
        cosYaw = kFollowB * cosYaw;
        kFollowB = kFollowB * sinYaw;
        camera->anim.worldPosX = posZ + cosYaw;
        camera->anim.worldPosY = posY + kFollowA;
        camera->anim.worldPosZ = posX + kFollowB;
        rotVal = (int)(lbl_803E17A8 * gCamTalkBikeState->rollInput);
        angleDelta = rotVal - (u16)camera->anim.rotZ;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        rollStep = (f32)(s32)angleDelta * timeDelta;
        camera->anim.rotZ = rollStep * lbl_803E17B4 + (f32)(s32) * (s16*)((char*)&camera->anim.rotZ);
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       (u32)camera->anim.parent);
    }
    return;
}
#pragma opt_propagation reset
#pragma opt_common_subs reset

#pragma peephole off
void CameraModeBike_init(CameraObject* camera)
{

    if (gCamTalkBikeState == 0)
    {
        gCamTalkBikeState = (CameraModeBikeState*)mmAlloc(sizeof(CameraModeBikeState), 0xf, 0);
    }
    memset(gCamTalkBikeState, 0, sizeof(CameraModeBikeState));
    gCamTalkBikeState->entryFov = camera->fov;
    gCamTalkBikeState->defaultFov = gCamTalkDefaultFov;
    gCamTalkBikeState->defaultScale = lbl_803E1788;
    gCamTalkBikeState->followDistance = gCamTalkDefaultFollowDist;
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

void CameraModeBike_release(void)
{
}

void CameraModeBike_initialise(void)
{
}
