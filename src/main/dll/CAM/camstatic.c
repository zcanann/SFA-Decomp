#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/attention.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/dll/CAM/camslide.h"
#include "main/dll/CAM/firstperson.h"
#include "main/object_transform.h"

extern void camcontrol_traceMove(f32 radius, f32* from, void* to, f32* out, void* work, int a,
                                 int b, int c);
extern void camcontrol_updateTargetAction(int camera, int obj);
extern void camMoveFn_80104040(int camera, int obj);
extern void camcontrol_updateModeSettings(int camera);
extern int EmissionController_IsLingering(int obj);
extern void fn_8029656C(int obj, float* out);
extern void cameraGetPrevPos2(int obj, float* x, float* y, float* z);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 interpolate(f32 cur, f32 target, f32 t);

extern f64 lbl_803E1698;
extern f64 lbl_803E16F8;
extern f32 lbl_803DD52C;
extern f32 lbl_803E1688;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16DC;
extern f32 lbl_803E1708;
extern f32 lbl_803E1718;
extern f32 lbl_803E171C;
extern f32 lbl_803E1720;
extern f32 lbl_803E1724;
extern f32 lbl_803E1728;
extern f32 lbl_803E172C;
extern f32 lbl_803E1730;
extern f32 timeDelta;

#define gCamcontrolModeSettings cameraMtxVar57

/*
 * --INFO--
 *
 * Function: camstatic_update
 * EN v1.0 Address: 0x80105810
 * EN v1.0 Size: 1644b
 * EN v1.1 Address: 0x80105AAC
 * EN v1.1 Size: 1644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camstatic_update(CameraObject* camera)
{
    GameObject* target;
    float fa;
    int val;
    uint angleDelta;
    short yaw;
    float dx;
    float dy;
    float dz;
    undefined auStack_13c[4];
    float dx2;
    float aimX;
    float aimY;
    float aimZ;
    float aimX2;
    float aimY2;
    float aimZ2;
    undefined auStack_11c[112];
    undefined auStack_ac[116];

    target = (GameObject*)camera->anim.targetObj;
    if (target == NULL)
    {
        return;
    }
    if (target->anim.classId == 1)
    {
        fn_8029656C((int)target, &dx);
        lbl_803DD52C = timeDelta * dx;
        val = EmissionController_IsLingering((int)target);
        switch (val)
        {
        case 1:
            gCamcontrolModeSettings->heightAdjustRate = lbl_803E16AC;
            gCamcontrolModeSettings->yawResponseFrames = 0xff;
            break;
        case 2:
            gCamcontrolModeSettings->heightAdjustRate = lbl_803E1718;
            gCamcontrolModeSettings->yawResponseFrames = 0xc;
            break;
        case 4:
            gCamcontrolModeSettings->heightAdjustRate = lbl_803E171C;
            gCamcontrolModeSettings->yawResponseFrames = 2;
            break;
        case 3:
            gCamcontrolModeSettings->heightAdjustRate = lbl_803E1720;
            gCamcontrolModeSettings->yawResponseFrames = 8;
            break;
        default:
            gCamcontrolModeSettings->heightAdjustRate =
                gCamcontrolModeSettings->targetHeightAdjustRate;
            gCamcontrolModeSettings->yawResponseFrames = 8;
            break;
        }
    }
    else
    {
        lbl_803DD52C = timeDelta;
    }
    camera->unk13E = 0;
    camcontrol_updateModeSettings((int)camera);
    camMoveFn_80104040((int)camera, (int)target);
    firstperson_updatePosition(camera, &target->anim);
    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY,
                                   camera->anim.localPosZ, &camera->anim.worldPosX,
                                   &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   (u32)camera->anim.parent);
    camslide_update(camera, target);
    camcontrol_updateVerticalBounds(camera, 1, 8, &gCamcontrolModeSettings->verticalLowerBound,
                                    &gCamcontrolModeSettings->verticalUpperBound);
    if (gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0)
    {
        gCamcontrolModeSettings->targetActionFlags = *(u8*)((int)camera + 0xa2);
        if (((camera->unk142 != 0) ||
                ((gCamcontrolModeSettings->targetActionFlags == 1 &&
                    (*(f32*)((u8*)camera + 0x38) >= lbl_803E16AC)))) &&
            (gCamcontrolModeSettings->clampFlags.b7 == 0))
        {
            if (((camera->anim.worldPosY > lbl_803E16DC + target->anim.worldPosY) &&
                    (camera->anim.worldPosY < lbl_803E1724 + target->anim.worldPosY)) &&
                (camera->anim.parent == NULL))
            {
                gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 1;
            }
        }
        if ((((gCamcontrolModeSettings->targetActionFlags & 0x10) != 0) &&
                (*(f32*)((u8*)camera + 0x38) < lbl_803E1728)) &&
            (target->anim.localPosZ <= lbl_803E16AC))
        {
            gCamcontrolModeSettings->clampFlags.b6 = 1;
            gCamcontrolModeSettings->heightLockLimit = camera->anim.worldPosY;
        }
    }
    else
    {
        fa = lbl_803E16AC;
        camera->unk130 = fa;
        camera->unk12C = fa;
        if ((*(u8*)((int)camera + 0xa2) == 1) && (*(f32*)((u8*)camera + 0x38) < fa))
        {
            gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
        }
        if ((camera->anim.worldPosY > lbl_803E172C + target->anim.worldPosY) ||
            (camera->anim.worldPosY < lbl_803E1708 + target->anim.worldPosY))
        {
            gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
        }
    }
    if (gCamcontrolModeSettings->clampFlags.b7 != 0)
    {
        if ((gCamcontrolModeSettings->targetActionFlags == 1) || (camera->unk142 != 0))
        {
            gCamcontrolModeSettings->wallAvoidanceTimer += 1;
        }
        else
        {
            gCamcontrolModeSettings->wallAvoidanceTimer = 0;
        }
        if (10 < gCamcontrolModeSettings->wallAvoidanceTimer)
        {
            if (target->anim.classId == 1)
            {
                cameraGetPrevPos2((int)target, &aimX2, &aimY2, &aimZ2);
            }
            else
            {
                aimX2 = target->anim.worldPosX;
                aimY2 = target->anim.worldPosY + gCamcontrolModeSettings->targetHeight;
                aimZ2 = target->anim.worldPosZ;
            }
            camcontrol_traceMove(lbl_803E1688, &aimX2, &camera->anim.worldPosX,
                                 &camera->anim.worldPosX, auStack_ac, 3, 1, 1);
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            gCamcontrolModeSettings->wallAvoidanceTimer = 0;
        }
    }
    if (gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0)
    {
        if ((gCamcontrolModeSettings->targetActionFlags & 0x10) != 0)
        {
            gCamcontrolModeSettings->collisionProbeTimer += 1;
        }
        else
        {
            gCamcontrolModeSettings->collisionProbeTimer = 0;
        }
        if (5 < gCamcontrolModeSettings->collisionProbeTimer)
        {
            if (target->anim.classId == 1)
            {
                cameraGetPrevPos2((int)target, &aimX, &aimY, &aimZ);
            }
            else
            {
                aimX = target->anim.worldPosX;
                aimY = target->anim.worldPosY + gCamcontrolModeSettings->targetHeight;
                aimZ = target->anim.worldPosZ;
            }
            camcontrol_traceMove(lbl_803E1688, &aimX, &camera->anim.worldPosX,
                                 &camera->anim.worldPosX, auStack_11c, 3, 1, 1);
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            gCamcontrolModeSettings->collisionProbeTimer = 0;
        }
    }
    ((void (*)(int, f32*, f32*, f32*, f32*, int, f32))(*gCameraInterface)->getRelativePosition)(
        (int)camera, &dx2, (f32*)auStack_13c, &dz, &dy, 0, gCamcontrolModeSettings->targetHeight);
    yaw = getAngle(dx2, dz);
    gCamcontrolModeSettings->pitchOffset = 0;
    camera->anim.rotX = (-0x8000 - yaw) - gCamcontrolModeSettings->pitchOffset;
    angleDelta = getAngle(camera->anim.worldPosY -
                     (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight),
                     dy);
    angleDelta = (angleDelta & 0xffff) - ((int)camera->anim.rotY & 0xffffU);
    if (0x8000 < (int)angleDelta)
    {
        angleDelta = angleDelta - 0xffff;
    }
    if ((int)angleDelta < -0x8000)
    {
        angleDelta = angleDelta + 0xffff;
    }
    val = (int)interpolate((f32)(int)angleDelta,
                             lbl_803E16A4 /
                             (f32)(u32)gCamcontrolModeSettings->yawResponseFrames, timeDelta);
    camera->anim.rotY = camera->anim.rotY + (short)val;
    camcontrol_updateTargetAction((int)camera, (int)target);
    val = (int)interpolate((f32)camera->anim.rotZ, lbl_803E1730, timeDelta);
    camera->anim.rotZ = camera->anim.rotZ - (short)val;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                   camera->anim.worldPosZ, &camera->anim.localPosX,
                                   &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (u32)camera->anim.parent);
}
