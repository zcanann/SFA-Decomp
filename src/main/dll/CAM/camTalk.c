#include "main/dll/CAM/camTalk.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/cambike_state.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"

extern void* memset(void* dst, int val, u32 n);
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern int FUN_80017730();
extern void vecRotateZXY(void* param_1, void* outVec);
extern undefined4 setMatrixFromObjectPos();
extern void Matrix_TransformPoint(void* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition(int param_1, int param_2, float* outPos, void* outAngle);
extern int getAngle(f32 dx, f32 dz);
extern GameObject* getSbGalleon(void);
extern int DBprotection_getCameraState(GameObject * obj);
extern double FUN_80293900();
extern f32 mathSinf(f32);
extern f32 sqrtf(f32 value);
extern f32 mathCosf(f32);
extern void cameraGetPrevPos2(int obj, float* x, float* y, float* z);

extern CameraModeBikeState* lbl_803DD540;
extern ViewfinderState* lbl_803DD548;
extern f64 lbl_803E17B8;
extern f64 DOUBLE_803e2458;
extern f32 timeDelta;
extern f32 lbl_803E1780;
extern f32 lbl_803E1784;
extern f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern f32 lbl_803E1790;
extern f32 lbl_803E1794;
extern f32 lbl_803E1798;
extern f32 lbl_803E179C;
extern f32 lbl_803E17A0;
extern f32 lbl_803E17A4;
extern f32 lbl_803E17A8;
extern f32 lbl_803E17AC;
extern f32 lbl_803E17B0;
extern f32 lbl_803E17B4;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f64 lbl_803E17D8;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2448;
extern f32 lbl_803E244C;
extern f32 lbl_803E2450;

/* FUN_80107b4c removed: in v1.0 this address is the start of CameraModeBike_update. */

/*
 * --INFO--
 *
 * Function: CameraModeBike_update
 * EN v1.0 Address: 0x80107B78
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80107DE8
 * EN v1.1 Size: 1076b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on
void CameraModeBike_update(CameraObject* camera)
{
    int ref;
    float fa;
    float fb;
    short angle;
    GameObject* target;
    float fc;
    float fd;
    float fe;
    float ff;
    float posX;
    float posY;
    float posZ;
    CamTalkTransformInput xformIn;
    float mtxBuf[17];
    longlong tmp;
    undefined4 tmp3;
    uint convLo;
    longlong tmp4;
    longlong tmp5;
    undefined4 tmp6;
    uint convLo2;
    undefined4 tmp7;
    uint convLo3;
    undefined4 tmp8;
    uint convLo4;
    undefined4 tmp9;
    uint convLo5;
    longlong tmp2;
    undefined4 tmp10;
    uint convLo6;
    undefined4 tmp11;
    uint convLo7;
    longlong tmp12;

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
        tmp = (longlong)(int)
        lbl_803DD540->pitchTarget;
        xformIn.pitch = (undefined2)(int)
        lbl_803DD540->pitchTarget;
        xformIn.roll = 0;
        setMatrixFromObjectPos(mtxBuf, &xformIn);
        Matrix_TransformPoint(mtxBuf, lbl_803E1780, lbl_803E178C, lbl_803E1780,
                              &posZ, &posY, &posX);
        camera->anim.rotX = -0x8000 - target->anim.rotX;
        lbl_803DD540->smoothedYawOffset =
            lbl_803E1790 *
            (lbl_803E1794 * lbl_803DD540->turnInput - lbl_803DD540->smoothedYawOffset) +
            lbl_803DD540->smoothedYawOffset;
        ref = (int)
        ((f32)(s32)
        camera->anim.rotX + lbl_803DD540->smoothedYawOffset
        )
        ;
        camera->anim.rotX = (short)ref;
        ref = (int)(lbl_803E1798 - lbl_803DD540->pitchTarget);
        angle = (short)ref - camera->anim.rotY;
        if (0x8000 < angle)
        {
            angle = angle + 1;
        }
        if (angle < -0x8000)
        {
            angle = angle + -1;
        }
        camera->anim.rotY = camera->anim.rotY + (angle >> 3);
        fc = mathSinf(lbl_803E179C * (f32)(s32)((int)camera->anim.rotX - 0x4000) / lbl_803E17A0);
        fd = mathCosf(lbl_803E179C * (f32)(s32)((int)camera->anim.rotX - 0x4000) / lbl_803E17A0);
        fe = mathCosf(lbl_803E179C * (f32)(s32)camera->anim.rotY / lbl_803E17A0);
        ff = mathSinf(lbl_803E179C * (f32)(s32)camera->anim.rotY / lbl_803E17A0);
        fa = -lbl_803DD540->heightInput / lbl_803E17A4;
        fb = (fa < lbl_803E1780) ? lbl_803E1780 : ((fa > lbl_803E1788) ? lbl_803E1788 : fa);
        lbl_803DD540->followDistance =
            lbl_803E17A8 *
            ((lbl_803E17B0 * fb + lbl_803E17AC) - lbl_803DD540->followDistance) +
            lbl_803DD540->followDistance;
        fa = lbl_803DD540->followDistance;
        fe = fa * fe;
        camera->anim.worldPosX = posZ + fe * fd;
        camera->anim.worldPosY = posY + fa * ff;
        camera->anim.worldPosZ = posX + fe * fc;
        ref = (int)(lbl_803E17A8 * lbl_803DD540->rollInput);
        tmp2 = (longlong)ref;
        angle = (short)ref - camera->anim.rotZ;
        if (0x8000 < angle)
        {
            angle = angle + 1;
        }
        if (angle < -0x8000)
        {
            angle = angle + -1;
        }
        ref = (int)
        ((f32)(s32)
        angle * timeDelta * lbl_803E17B4 + (f32)(s32)
        camera->anim.rotZ
        )
        ;
        camera->anim.rotZ = (short)ref;
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                       camera->anim.worldPosZ, &camera->anim.localPosX, &camera->anim.localPosY,
                                       &camera->anim.localPosZ, (u32)camera->anim.parent);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: CameraModeBike_init
 * EN v1.0 Address: 0x80107EE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010821C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: firstPersonPlaceCamera
 * EN v1.0 Address: 0x80107EE4
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801082AC
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstPersonPlaceCamera(GameObject* focus, int resetClamp)
{
    register GameObject* self = focus;
    GameObject* galleon;
    int val;
    float tmp2;
    float tmp3;
    float tmp4;
    float tmp[3];

    if (self->anim.classId == 1)
    {
        cameraGetPrevPos2((int)self, &tmp4, &tmp3, &tmp2);
        if (((resetClamp != 0) || (lbl_803DD548->camPosX != tmp4)) ||
            (lbl_803DD548->camPosZ != tmp2))
        {
            lbl_803DD548->clampedPosY = tmp3;
        }
        lbl_803DD548->camPosX = tmp4;
        lbl_803DD548->camPosY = tmp3;
        lbl_803DD548->camPosZ = tmp2;
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
        val = DBprotection_getCameraState(galleon);
        if (val == 2)
        {
            tmp[0] = self->anim.worldPosX - galleon->anim.worldPosX;
            tmp[1] = (lbl_803E17C0 + self->anim.worldPosY) - galleon->anim.worldPosY;
            tmp[2] = self->anim.worldPosZ - galleon->anim.worldPosZ;
            vecRotateZXY(galleon, tmp);
            lbl_803DD548->camPosX = galleon->anim.worldPosX + tmp[0];
            lbl_803DD548->camPosY = galleon->anim.worldPosY + tmp[1];
            lbl_803DD548->camPosZ = galleon->anim.worldPosZ + tmp[2];
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: firstPersonExit
 * EN v1.0 Address: 0x80108074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108430
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstPersonExit(CameraObject* camera)
{
    register CameraObject* self = camera;
    GameObject* target;
    float fa;
    float fb;
    int sval;
    float tmp[3];
    undefined buf[4];

    target = (GameObject*)self->anim.targetObj;
    lbl_803DD548->posXCurve.start = self->anim.worldPosX;
    fa = lbl_803E17C4;
    lbl_803DD548->posXCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->posXCurve.endTangent = fa;
    lbl_803DD548->posYCurve.start = self->anim.worldPosY;
    lbl_803DD548->posYCurve.startTangent = fa;
    lbl_803DD548->posYCurve.endTangent = fa;
    lbl_803DD548->posZCurve.start = self->anim.worldPosZ;
    lbl_803DD548->posZCurve.startTangent = fa;
    lbl_803DD548->posZCurve.endTangent = fa;
    camcontrol_getTargetPosition((int)self, (int)target, tmp, buf);
    lbl_803DD548->posXCurve.end = tmp[0];
    lbl_803DD548->posYCurve.end = tmp[1];
    lbl_803DD548->posZCurve.end = tmp[2];
    fa = lbl_803DD548->posXCurve.end - lbl_803DD548->posXCurve.start;
    fb = lbl_803DD548->posZCurve.end - lbl_803DD548->posZCurve.start;
    lbl_803DD548->exitDistance = sqrtf(fa * fa + fb * fb);
    lbl_803DD548->viewCurve.px = &lbl_803DD548->yawCurve.start;
    lbl_803DD548->viewCurve.py = &lbl_803DD548->pitchCurve.start;
    lbl_803DD548->viewCurve.pz = NULL;
    lbl_803DD548->viewCurve.count = 4;
    lbl_803DD548->viewCurve.dir = 0;
    lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
    lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
    lbl_803DD548->yawCurve.start = (float)(int)self->anim.rotX;
    sval = getAngle((double)(lbl_803DD548->posXCurve.end - target->anim.worldPosX),
                     (double)(lbl_803DD548->posZCurve.end - target->anim.worldPosZ));
    lbl_803DD548->yawCurve.end = (float)(int)(short)(0x8000 - sval);
    fa = lbl_803E17C4;
    lbl_803DD548->yawCurve.startTangent = lbl_803E17C4;
    lbl_803DD548->yawCurve.endTangent = fa;
    fa = lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end;
    if ((fa > lbl_803E17C8) || (fa < lbl_803E17CC))
    {
        if (lbl_803E17C4 <= lbl_803DD548->yawCurve.start)
        {
            if (lbl_803DD548->yawCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->yawCurve.end = lbl_803DD548->yawCurve.end + lbl_803E17D0;
            }
        }
        else
        {
            lbl_803DD548->yawCurve.start = lbl_803DD548->yawCurve.start + lbl_803E17D0;
        }
    }
    lbl_803DD548->pitchCurve.start = (float)(int)self->anim.rotY;
    fa = lbl_803E17C4;
    lbl_803DD548->pitchCurve.end = lbl_803E17C4;
    lbl_803DD548->pitchCurve.startTangent = fa;
    lbl_803DD548->pitchCurve.endTangent = fa;
    fa = lbl_803DD548->pitchCurve.start - lbl_803DD548->pitchCurve.end;
    if ((fa > lbl_803E17C8) || (fa < lbl_803E17CC))
    {
        if (lbl_803E17C4 <= lbl_803DD548->pitchCurve.start)
        {
            if (lbl_803DD548->pitchCurve.end < lbl_803E17C4)
            {
                lbl_803DD548->pitchCurve.end = lbl_803DD548->pitchCurve.end + lbl_803E17D0;
            }
        }
        else
        {
            lbl_803DD548->pitchCurve.start = lbl_803DD548->pitchCurve.start + lbl_803E17D0;
        }
    }
    curvesMove(&lbl_803DD548->viewCurve);
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeBike_release(void)
{
}

void CameraModeBike_initialise(void)
{
}
