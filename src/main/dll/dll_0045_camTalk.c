/* DLL 0x0045 - camera talk / NPC-speak mode [80107AEC-80107B4C) */
#include "main/dll/CAM/cambike_state.h"
#include "main/mm.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/cutCam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/object_transform.h"
#include "string.h"
#include "main/dll/DR/dll_80209FE0_shared.h"


extern float mathSinf(float x);
extern float mathCosf(float x);
extern CameraModeBikeState* lbl_803DD540;

static f32 CameraModeStaffAnim_angleToRadians(int angle);

extern void vecRotateZXY(void* param_1, void* outVec);
extern u32 setMatrixFromObjectPos();
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern GameObject* getSbGalleon(void);
extern int DBprotection_getCameraState(GameObject * obj);
extern void cameraGetPrevPos2(int obj, f32* x, f32* y, f32* z);
extern ViewfinderState* lbl_803DD548;
extern f32 timeDelta;
extern f32 lbl_803E1780;
extern const f32 lbl_803E1784;
extern const f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern const f32 lbl_803E1790;
extern const f32 lbl_803E1794;
extern const f32 lbl_803E1798;
extern const f32 lbl_803E179C;
extern const f32 lbl_803E17A0;
extern const f32 lbl_803E17A4;
extern const f32 lbl_803E17A8;
extern const f32 lbl_803E17AC;
extern const f32 lbl_803E17B0;
extern const f32 lbl_803E17B4;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;

void CameraModeBike_copyToCurrent(f32* param_1)
{
    lbl_803DD540->turnInput = param_1[0];
    lbl_803DD540->heightInput = param_1[1];
    lbl_803DD540->rollInput = param_1[2];
    lbl_803DD540->pitchTarget = param_1[3];
}

void CameraModeBike_free(void)
{
    mm_free(lbl_803DD540);
    lbl_803DD540 = 0;
}

#pragma peephole on
void CameraModeBike_update(CameraObject* camera)
{
    int rotVal;
    float followDist;
    float clampedHeight;
    short angleDelta;
    GameObject* target;
    float sinYaw;
    float cosYaw;
    float cosPitch;
    float sinPitch;
    float posZ;
    float posY;
    float posX;
    CamTalkTransformInput xformIn;
    float mtxBuf[17];
    s64 local_a0;
    u32 local_98;
    u32 uStack_94;
    s64 local_90;
    s64 local_88;
    u32 local_80;
    u32 uStack_7c;
    u32 local_78;
    u32 uStack_74;
    u32 local_70;
    u32 uStack_6c;
    u32 local_68;
    u32 uStack_64;
    s64 local_60;
    u32 local_58;
    u32 uStack_54;
    u32 local_50;
    u32 uStack_4c;
    s64 local_48;

    (*gCameraInterface)->getDefaultHandlerEntry();
    target = (GameObject*)camera->anim.targetObj;
    if (target != NULL)
    {
        camera->fov = lbl_803E1784;
        xformIn.x = target->anim.worldPosX;
        xformIn.y = target->anim.worldPosY;
        xformIn.z = target->anim.worldPosZ;
        xformIn.scale = lbl_803E1788;
        xformIn.yaw = target->anim.rotX;
        local_a0 = (s64)(int)
        lbl_803DD540->pitchTarget;
        xformIn.pitch = (u16)(int)
        lbl_803DD540->pitchTarget;
        xformIn.roll = 0;
        setMatrixFromObjectPos(mtxBuf, &xformIn);
        Matrix_TransformPoint(mtxBuf, lbl_803E1780, lbl_803E178C, lbl_803E1780,
                              &posZ, &posY, &posX);
        camera->anim.rotX = 0x8000 - target->anim.rotX;
        lbl_803DD540->smoothedYawOffset =
            lbl_803E1790 *
            (lbl_803E1794 * lbl_803DD540->turnInput - lbl_803DD540->smoothedYawOffset) +
            lbl_803DD540->smoothedYawOffset;
        rotVal = (int)
        ((f32)(s32)
        camera->anim.rotX + lbl_803DD540->smoothedYawOffset
        )
        ;
        camera->anim.rotX = rotVal;
        rotVal = (int)(lbl_803E1798 - lbl_803DD540->pitchTarget);
        angleDelta = (short)rotVal - camera->anim.rotY;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        camera->anim.rotY = camera->anim.rotY + (angleDelta >> 3);
        sinYaw = mathSinf(lbl_803E179C * (f32)(s32)((int)camera->anim.rotX - 0x4000) / lbl_803E17A0);
        cosYaw = mathCosf(lbl_803E179C * (f32)(s32)((int)camera->anim.rotX - 0x4000) / lbl_803E17A0);
        cosPitch = mathCosf(lbl_803E179C * (f32)(s32)camera->anim.rotY / lbl_803E17A0);
        sinPitch = mathSinf(lbl_803E179C * (f32)(s32)camera->anim.rotY / lbl_803E17A0);
        followDist = -lbl_803DD540->heightInput / lbl_803E17A4;
        clampedHeight = (followDist < lbl_803E1780) ? lbl_803E1780 : ((followDist > lbl_803E1788) ? lbl_803E1788 : followDist);
        lbl_803DD540->followDistance =
            lbl_803E17A8 *
            ((lbl_803E17B0 * clampedHeight + lbl_803E17AC) - lbl_803DD540->followDistance) +
            lbl_803DD540->followDistance;
        followDist = lbl_803DD540->followDistance;
        cosPitch = followDist * cosPitch;
        camera->anim.worldPosX = posZ + cosPitch * cosYaw;
        camera->anim.worldPosY = posY + followDist * sinPitch;
        camera->anim.worldPosZ = posX + cosPitch * sinYaw;
        rotVal = (int)(lbl_803E17A8 * lbl_803DD540->rollInput);
        local_60 = (s64)rotVal;
        angleDelta = (short)rotVal - camera->anim.rotZ;
        if (0x8000 < angleDelta)
        {
            angleDelta = angleDelta - 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta = angleDelta + 0xFFFF;
        }
        rotVal = (int)
        ((f32)(s32)
        angleDelta * timeDelta * lbl_803E17B4 + (f32)(s32)
        camera->anim.rotZ
        )
        ;
        camera->anim.rotZ = rotVal;
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                       camera->anim.worldPosZ, &camera->anim.localPosX, &camera->anim.localPosY,
                                       &camera->anim.localPosZ, (u32)camera->anim.parent);
    }
    return;
}

#pragma peephole off
void CameraModeBike_init(CameraObject* camera)
{

    if (lbl_803DD540 == 0)
    {
        lbl_803DD540 = (CameraModeBikeState*)mmAlloc(sizeof(CameraModeBikeState), 0xf, 0);
    }
    memset(lbl_803DD540, 0, sizeof(CameraModeBikeState));
    lbl_803DD540->entryFov = camera->fov;
    lbl_803DD540->defaultFov = lbl_803E1784;
    lbl_803DD540->defaultScale = lbl_803E1788;
    lbl_803DD540->followDistance = lbl_803E17AC;
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
        cameraGetPrevPos2((int)self, &prevPosX, &prevPosY, &prevPosZ);
        if (((resetClamp != 0) || (lbl_803DD548->camPosX != prevPosX)) ||
            (lbl_803DD548->camPosZ != prevPosZ))
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
            vecRotateZXY(galleon, localOffset);
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
    float fVar1;
    float dz;
    int targetYaw;
    float targetPos[3];
    u8 auStack_28[4];

    target = (GameObject*)self->anim.targetObj;
    lbl_803DD548->posXCurve.start = self->anim.worldPosX;
    fVar1 = lbl_803E17C4;
    lbl_803DD548->posXCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->posXCurve.endTangent = fVar1;
    lbl_803DD548->posYCurve.start = self->anim.worldPosY;
    lbl_803DD548->posYCurve.startTangent = fVar1;
    lbl_803DD548->posYCurve.endTangent = fVar1;
    lbl_803DD548->posZCurve.start = self->anim.worldPosZ;
    lbl_803DD548->posZCurve.startTangent = fVar1;
    lbl_803DD548->posZCurve.endTangent = fVar1;
    camcontrol_getTargetPosition(self, &target->anim, targetPos, (s16*)auStack_28);
    lbl_803DD548->posXCurve.end = targetPos[0];
    lbl_803DD548->posYCurve.end = targetPos[1];
    lbl_803DD548->posZCurve.end = targetPos[2];
    fVar1 = lbl_803DD548->posXCurve.end - lbl_803DD548->posXCurve.start;
    dz = lbl_803DD548->posZCurve.end - lbl_803DD548->posZCurve.start;
    lbl_803DD548->exitDistance = sqrtf(fVar1 * fVar1 + dz * dz);
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
    fVar1 = lbl_803E17C4;
    lbl_803DD548->yawCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->yawCurve.endTangent = fVar1;
    fVar1 = lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end;
    if ((fVar1 > lbl_803E17C8) || (fVar1 < lbl_803E17CC))
    {
        if (lbl_803DD548->yawCurve.start < lbl_803E17C4)
        {
            lbl_803DD548->yawCurve.start = lbl_803DD548->yawCurve.start + lbl_803E17D0;
        }
        else
        {
            if (lbl_803DD548->yawCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->yawCurve.end = lbl_803DD548->yawCurve.end + lbl_803E17D0;
            }
        }
    }
    lbl_803DD548->pitchCurve.start = (float)(int)self->anim.rotY;
    fVar1 = lbl_803E17C4;
    lbl_803DD548->pitchCurve.end = lbl_803E17C4;
    lbl_803DD548->pitchCurve.startTangent = fVar1;
    lbl_803DD548->pitchCurve.endTangent = fVar1;
    fVar1 = lbl_803DD548->pitchCurve.start - lbl_803DD548->pitchCurve.end;
    if ((fVar1 > lbl_803E17C8) || (fVar1 < lbl_803E17CC))
    {
        if (lbl_803DD548->pitchCurve.start < lbl_803E17C4)
        {
            lbl_803DD548->pitchCurve.start = lbl_803DD548->pitchCurve.start + lbl_803E17D0;
        }
        else
        {
            if (lbl_803DD548->pitchCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->pitchCurve.end = lbl_803DD548->pitchCurve.end + lbl_803E17D0;
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
