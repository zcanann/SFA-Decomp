/* DLL 0x47 - CameraModeTestStrength [8010AEA8-8010B424) */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcannon_state.h"
#include "main/camera_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/dll/CAM/dll_5B.h"
#include "main/dll/fx_800944A0_shared.h"
extern f32 Curve_EvalLinear(float* values, f32 t, float* outTangent);
extern f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent);

extern CamCannonState* lbl_803DD560;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E18AC;
extern f32 lbl_803E18B0;
extern f32 lbl_803E18B4;
extern f32 lbl_803E18B8;
extern f32 Curve_EvalCatmullRom(f32* samples, f32 t, f32* out);
extern f32 Curve_EvalBSpline(f32* samples, f32 t, f32* out);
extern void pathcam_buildWindowSamples(int* window, f32* x, f32* y, f32* z, f32* pitch, f32* yaw, f32* roll, f32* fov);
extern void pathcam_findTaggedNodeWindow(int node, int* window, int p3);
extern f32 fn_8010AC48(f32 x, f32 y, f32 z, int* window);
extern int getAngle(float y, float x);


extern f32 lbl_803E18BC;

u32 fn_8010AEA8(CameraObject* camera, u32 flagsIn)
{
    u8 flags;
    f32 speed;
    f32 t;

    lbl_803DD560->posXEnd = camera->anim.localPosX;
    lbl_803DD560->posYEnd = camera->anim.localPosY;
    lbl_803DD560->posZEnd = camera->anim.localPosZ;
    lbl_803DD560->rotXEnd = camera->anim.rotX;
    lbl_803DD560->rotYEnd = camera->anim.rotY;
    lbl_803DD560->rotZEnd = camera->anim.rotZ;
    lbl_803DD560->fovEnd = camera->fov;

    if (lbl_803E1888 != lbl_803DD560->duration)
    {
        speed = lbl_803DD560->elapsed / lbl_803DD560->duration;
    }
    else
    {
        speed = lbl_803E1888;
    }
    if (speed > lbl_803E188C)
    {
        speed = lbl_803E188C;
    }
    speed = Curve_EvalHermite(speed, lbl_803DD560->speedCurve, 0x0);
    if (speed < lbl_803E18AC)
    {
        speed = lbl_803E18AC;
    }
    lbl_803DD560->elapsed += speed * timeDelta;

    t = *(f32*)&lbl_803E1888;
    if (t != lbl_803DD560->duration)
    {
        t = lbl_803DD560->elapsed / lbl_803DD560->duration;
    }
    if (t > lbl_803E188C)
    {
        t = lbl_803E188C;
    }
    camera->anim.localPosX = Curve_EvalLinear(&lbl_803DD560->posXStart, t, 0x0);
    camera->anim.localPosY = Curve_EvalLinear(&lbl_803DD560->posYStart, t, 0x0);
    camera->anim.localPosZ = Curve_EvalLinear(&lbl_803DD560->posZStart, t, 0x0);
    camera->fov = Curve_EvalLinear(&lbl_803DD560->fovStart, t, 0x0);

    if (((lbl_803DD560->rotXStart - lbl_803DD560->rotXEnd) > lbl_803E1890) || ((lbl_803DD560->rotXStart - lbl_803DD560->rotXEnd) < lbl_803E1894))
    {
        if (lbl_803DD560->rotXStart < lbl_803E1888)
        {
            lbl_803DD560->rotXStart = *(f32*)&lbl_803DD560->rotXStart + lbl_803E1898;
        }
        else if (lbl_803DD560->rotXEnd < lbl_803E1888)
        {
            lbl_803DD560->rotXEnd = *(f32*)&lbl_803DD560->rotXEnd + lbl_803E1898;
        }
    }
    if (((lbl_803DD560->rotYStart - lbl_803DD560->rotYEnd) > lbl_803E1890) || ((lbl_803DD560->rotYStart - lbl_803DD560->rotYEnd) < lbl_803E1894))
    {
        if (lbl_803DD560->rotYStart < lbl_803E1888)
        {
            lbl_803DD560->rotYStart = *(f32*)&lbl_803DD560->rotYStart + lbl_803E1898;
        }
        else if (lbl_803DD560->rotYEnd < lbl_803E1888)
        {
            lbl_803DD560->rotYEnd = *(f32*)&lbl_803DD560->rotYEnd + lbl_803E1898;
        }
    }
    if (((lbl_803DD560->rotZStart - lbl_803DD560->rotZEnd) > lbl_803E1890) || ((lbl_803DD560->rotZStart - lbl_803DD560->rotZEnd) < lbl_803E1894))
    {
        if (lbl_803DD560->rotZStart < lbl_803E1888)
        {
            lbl_803DD560->rotZStart = *(f32*)&lbl_803DD560->rotZStart + lbl_803E1898;
        }
        else if (lbl_803DD560->rotZEnd < lbl_803E1888)
        {
            lbl_803DD560->rotZEnd = *(f32*)&lbl_803DD560->rotZEnd + lbl_803E1898;
        }
    }

    flags = flagsIn;
    if ((flags & 1) == 0)
    {
        *(s16*)&camera->anim.rotX =
        Curve_EvalLinear(&lbl_803DD560->rotXStart, t, 0x0);
    }
    if ((flags & 2) == 0)
    {
        *(s16*)&camera->anim.rotY =
        Curve_EvalLinear(&lbl_803DD560->rotYStart, t, 0x0);
    }
    if ((flags & 4) == 0)
    {
        *(s16*)&camera->anim.rotZ =
        Curve_EvalLinear(&lbl_803DD560->rotZStart, t, 0x0);
    }
    return t >= lbl_803E188C;
}

void cameraModeTestStrengthFn_8010b238(f32 fovEnd, CameraObject* camera, f32* posEnd,
                                       s32 rotXEnd, s32 rotYEnd, s32 rotZEnd)
{
    f32 dx;
    f32 dy;
    f32 dz;

    lbl_803DD560->transitionComplete = 0;
    lbl_803DD560->posXStart = camera->anim.localPosX;
    lbl_803DD560->posYStart = camera->anim.localPosY;
    lbl_803DD560->posZStart = camera->anim.localPosZ;
    lbl_803DD560->rotXStart = (f32)(s32)
    camera->anim.rotX;
    lbl_803DD560->rotYStart = (f32)(s32)
    camera->anim.rotY;
    lbl_803DD560->rotZStart = (f32)(s32)
    camera->anim.rotZ;
    lbl_803DD560->fovStart = camera->fov;
    lbl_803DD560->posXEnd = posEnd[0];
    lbl_803DD560->posYEnd = posEnd[1];
    lbl_803DD560->posZEnd = posEnd[2];
    lbl_803DD560->rotXEnd = rotXEnd;
    lbl_803DD560->rotYEnd = rotYEnd;
    lbl_803DD560->rotZEnd = rotZEnd;
    lbl_803DD560->fovEnd = fovEnd;
    lbl_803DD560->elapsed = lbl_803E1888;
    dx = lbl_803DD560->posXEnd - lbl_803DD560->posXStart;
    dy = lbl_803DD560->posYEnd - lbl_803DD560->posYStart;
    dz = lbl_803DD560->posZEnd - lbl_803DD560->posZStart;
    lbl_803DD560->duration = sqrtf(dx * dx + dy * dy + dz * dz);
    (*gCameraInterface)->initialise(lbl_803DD560->duration, lbl_803DD560->speedCurve,
                                    lbl_803E18B0, (f64)lbl_803E18B4,
                                    (f64)*(f32*)&lbl_803E18B4, lbl_803E18B8);
}

void CameraModeTestStrength_copyToCurrent_nop(void)
{
}

void CameraModeTestStrength_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD560);
    lbl_803DD560 = 0;
}

void CameraModeTestStrength_update(short* cam)
{
    extern int fn_8010AEA8(short* cam, int flags); /* #57 */
    int lockRoll;
    int obj;
    int lockPitch;
    int lockYaw;
    int node;
    int flags;
    f32 t;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 param;
    int yaw;
    int node2;
    int nextWindow[4];
    int prevWindow[4];
    f32 x[4];
    f32 y[4];
    f32 z[4];
    f32 pitchS[4];
    f32 yawS[4];
    f32 rollS[4];
    f32 fov[4];

    if (lbl_803DD560->pathFailed != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        obj = *(int*)&((CameraObject*)cam)->anim.targetObj;
        getButtonsJustPressed(0);
        node = (int)(*gRomCurveInterface)->getById(lbl_803DD560->nextNodeId);
        node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->prevNodeId);
        pathcam_findTaggedNodeWindow(node2, prevWindow, lbl_803DD560->pathTag);
        pathcam_findTaggedNodeWindow(node, nextWindow, lbl_803DD560->pathTag);
        pathcam_buildWindowSamples(prevWindow, x, y, z, pitchS, yawS, rollS, fov);
        param = fn_8010AC48(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                         ((GameObject*)obj)->anim.worldPosZ, nextWindow);
        if (param < lbl_803E1888)
        {
            if (nextWindow[0] > -1)
            {
                lbl_803DD560->nextNodeId = nextWindow[0];
                node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->nextNodeId);
                pathcam_findTaggedNodeWindow(node2, nextWindow, lbl_803DD560->pathTag);
                if (prevWindow[0] > -1)
                {
                    lbl_803DD560->prevNodeId = prevWindow[0];
                    node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->prevNodeId);
                    pathcam_findTaggedNodeWindow(node2, prevWindow, lbl_803DD560->pathTag);
                    pathcam_buildWindowSamples(prevWindow, x, y, z, pitchS, yawS, rollS, fov);
                    param = fn_8010AC48(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                     ((GameObject*)obj)->anim.worldPosZ, nextWindow);
                    lbl_803DD560->pathProgress += lbl_803E188C;
                }
                else
                {
                    param = lbl_803E1888;
                }
            }
            else
            {
                param = lbl_803E1888;
            }
        }
        else if (param > *(f32*)&lbl_803E188C)
        {
            if (nextWindow[2] > -1 && nextWindow[3] > -1)
            {
                lbl_803DD560->nextNodeId = nextWindow[2];
                node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->nextNodeId);
                pathcam_findTaggedNodeWindow(node2, nextWindow, lbl_803DD560->pathTag);
                if (prevWindow[2] > -1 && prevWindow[3] > -1)
                {
                    lbl_803DD560->prevNodeId = prevWindow[2];
                    node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->prevNodeId);
                    pathcam_findTaggedNodeWindow(node2, prevWindow, lbl_803DD560->pathTag);
                    pathcam_buildWindowSamples(prevWindow, x, y, z, pitchS, yawS, rollS, fov);
                    param = fn_8010AC48(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                     ((GameObject*)obj)->anim.worldPosZ, nextWindow);
                    lbl_803DD560->pathProgress -= lbl_803E188C;
                }
                else
                {
                    param = lbl_803E188C;
                }
            }
            else
            {
                param = lbl_803E188C;
            }
        }
        t = lbl_803E18BC * (param - lbl_803DD560->pathProgress) +
            lbl_803DD560->pathProgress;
        lbl_803DD560->pathProgress = t;
        ((CameraObject*)cam)->anim.worldPosX = Curve_EvalBSpline(x, t, 0);
        ((CameraObject*)cam)->anim.worldPosY = Curve_EvalBSpline(y, t, 0);
        ((CameraObject*)cam)->anim.worldPosZ = Curve_EvalBSpline(z, t, 0);
        node2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->prevNodeId);
        flags = *(u8*)(node2 + 0x3b);
        lockPitch = flags & 1;
        if (lockPitch == 0)
        {
            *cam = (int)Curve_EvalCatmullRom(pitchS, t, 0) + 0x8000;
        }
        lockYaw = flags & 2;
        if (lockYaw == 0)
        {
            cam[1] = Curve_EvalCatmullRom(yawS, t, 0);
        }
        lockRoll = flags & 4;
        if (lockRoll == 0)
        {
            cam[2] = Curve_EvalCatmullRom(rollS, t, 0);
        }
        ((CameraObject*)cam)->fov = Curve_EvalBSpline(fov, t, 0);
        if (lbl_803DD560->transitionComplete == 0 && fn_8010AEA8(cam, flags) != 0)
        {
            lbl_803DD560->transitionComplete = 1;
        }
        dx = ((CameraObject*)cam)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        dy = ((CameraObject*)cam)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        dz = ((CameraObject*)cam)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        if (lockPitch != 0)
        {
            *cam = 0x8000 - getAngle(dx, dz);
        }
        if (lockYaw != 0)
        {
            int delta;
            yaw = getAngle(dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
            delta = (int)(((f32)yaw - Curve_EvalCatmullRom(yawS, t, 0)) -
                (f32)(cam[1] & 0xffff));
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            cam[1] += ((int)(delta * framesThisStep) >> 3);
        }
        if (lockRoll != 0)
        {
            int delta = cam[2] - (((GameObject*)obj)->anim.rotZ & 0xffff);
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            cam[2] += ((int)(delta * framesThisStep) >> 3);
        }
        if (lbl_803DD560->linkedObject != NULL)
        {
            f32 v;
            v = ((CameraObject*)cam)->anim.worldPosX;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.worldPosX = v;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.localPosX = v;
            v = ((CameraObject*)cam)->anim.worldPosY;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.worldPosY = v;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.localPosY = v;
            v = ((CameraObject*)cam)->anim.worldPosZ;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.worldPosZ = v;
            ((GameObject*)lbl_803DD560->linkedObject)->anim.localPosZ = v;
        }
        Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX, ((CameraObject*)cam)->anim.worldPosY,
                                       ((CameraObject*)cam)->anim.worldPosZ, (float*)(cam + 6),
                                       (float*)(cam + 8), (float*)(cam + 10), *(int*)(cam + 0x18));
    }
}

void CameraModeTestStrength_init(short* cam, int param2, int* param3)
{
    extern void cameraModeTestStrengthFn_8010b238(int camera, f32* pos, int pitch, int yaw, int roll); /* #57 */
    int romNode;
    int obj;
    int curveNode2;
    s16 pitch;
    s16 yaw;
    s16 roll;
    f32 t;
    f32 px;
    f32 py;
    f32 pz;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 fov;
    f32 pos[3];
    int nextW[4];
    int prevW[4];
    f32 pitchS[4];
    f32 yawS[4];
    f32 rollS[4];
    f32 fovS[4];
    f32 xS[4];
    f32 yS[4];
    f32 zS[4];
    int tags[2];

    obj = *(int*)&((CameraObject*)cam)->anim.targetObj;
    if (lbl_803DD560 == 0)
    {
        lbl_803DD560 = (CamCannonState*)mmAlloc(sizeof(CamCannonState), 0xf, 0);
    }
    memset(lbl_803DD560, 0, sizeof(CamCannonState));
    lbl_803DD560->pathTag = *param3;
    lbl_803DD560->transitionComplete = 1;
    tags[0] = 9;
    tags[1] = 0x1b;
    lbl_803DD560->nextNodeId = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
        ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
        ((GameObject*)obj)->anim.worldPosZ, tags, 2, lbl_803DD560->pathTag);
    tags[0] = 8;
    tags[1] = 0x1a;
    lbl_803DD560->prevNodeId = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
        ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
        ((GameObject*)obj)->anim.worldPosZ, tags, 2, lbl_803DD560->pathTag);
    fn_8010A104(&lbl_803DD560->nextNodeId, &lbl_803DD560->prevNodeId, ((GameObject*)obj)->anim.worldPosX,
                ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ, lbl_803DD560->pathTag);
    romNode = (int)(*gRomCurveInterface)->getById(lbl_803DD560->prevNodeId);
    curveNode2 = (int)(*gRomCurveInterface)->getById(lbl_803DD560->nextNodeId);
    pathcam_findTaggedNodeWindow(romNode, prevW, lbl_803DD560->pathTag);
    pathcam_findTaggedNodeWindow(curveNode2, nextW, lbl_803DD560->pathTag);
    pathcam_buildWindowSamples(prevW, xS, yS, zS, pitchS, yawS, rollS, fovS);
    t = fn_8010AC48(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                    ((GameObject*)obj)->anim.worldPosZ, nextW);
    if (t < lbl_803E1888)
    {
        t = lbl_803E1888;
    }
    else if (t > lbl_803E188C)
    {
        t = lbl_803E188C;
    }
    px = Curve_EvalBSpline(xS, t, 0);
    py = Curve_EvalBSpline(yS, t, 0);
    pz = Curve_EvalBSpline(zS, t, 0);
    dx = px - ((GameObject*)obj)->anim.worldPosX;
    dy = py - ((GameObject*)obj)->anim.worldPosY;
    dz = pz - ((GameObject*)obj)->anim.worldPosZ;
    if ((*(u8*)(romNode + 0x3b) & 1) != 0)
    {
        pitch = (s16)(0x8000 - getAngle(dx, dz));
    }
    else
    {
        pitch = (s16)((int)Curve_EvalCatmullRom(pitchS, t, 0) + 0x8000);
    }
    if ((*(u8*)(romNode + 0x3b) & 4) != 0)
    {
        roll = ((GameObject*)obj)->anim.rotZ;
    }
    else
    {
        roll = Curve_EvalCatmullRom(rollS, t, 0);
    }
    if ((*(u8*)(romNode + 0x3b) & 2) != 0)
    {
        yaw = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
        yaw = (f32)yaw - Curve_EvalCatmullRom(yawS, t, 0);
    }
    else
    {
        yaw = Curve_EvalCatmullRom(yawS, t, 0);
    }
    fov = Curve_EvalBSpline(fovS, t, 0);
    pos[0] = px;
    pos[1] = py;
    pos[2] = pz;
    if (*((u8*)param3 + 4) == 0 && param2 != 3)
    {
        cameraModeTestStrengthFn_8010b238((int)cam, pos, pitch, yaw, roll);
    }
    else
    {
        ((CameraObject*)cam)->anim.worldPosX = px;
        ((CameraObject*)cam)->anim.worldPosY = py;
        ((CameraObject*)cam)->anim.worldPosZ = pz;
        Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX, ((CameraObject*)cam)->anim.worldPosY,
                                       ((CameraObject*)cam)->anim.worldPosZ, (float*)(cam + 6),
                                       (float*)(cam + 8), (float*)(cam + 10), *(int*)(cam + 0x18));
        cam[0] = pitch;
        cam[1] = yaw;
        cam[2] = roll;
        ((CameraObject*)cam)->fov = fov;
    }
    lbl_803DD560->pathProgress = t;
}

void CameraModeTestStrength_release(void)
{
}

void CameraModeTestStrength_initialise(void)
{
}

