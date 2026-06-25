/*
 * DLL 0x0042 - camera mode-control objects [801046F4-801049B0).
 *
 * Implements the per-frame logic for the "normal"/follow camera and a
 * handful of related modes (slide, first-person, path/cutscene). Each
 * routine reads and mutates the shared CamcontrolModeSettings block held
 * in cameraMtxVar57:
 *   - camcontrol_updateVerticalBounds: collision-probes around the camera
 *     and derives upper/lower world-Y bounds from the hit results.
 *   - camslide_update: lateral slide + height tracking that follows the
 *     target (classId 1 = the player).
 *   - firstperson_updatePitch / firstperson_updatePosition: aim and
 *     distance handling for the first-person view.
 *   - firstperson_loadSettings / pathcam_loadSettings: load a settings
 *     blob into the mode-settings block (pathcam dispatches on a mode id
 *     0..4) and snapshot/restore the saved camera state.
 *   - camstatic_update: the main per-frame driver tying the above together
 *     plus wall-avoidance and collision-probe timers.
 *   - CameraModeNormal_func0A / _free and the mode-settings alloc/free.
 *
 * cameraMtxVar57 is the live CamcontrolModeSettings; classId 1 marks the
 * player target throughout.
 */
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/dll/CAM/cutCam.h"
#include "main/object_transform.h"
#include "main/camera_interface.h"
#include "main/mm.h"
#include "string.h"
#include "main/vecmath.h"
#include "main/dll/DR/dll_80209FE0_shared.h"
extern int objBboxFn_800640cc(f32* startPoints, f32* endPoints, int radii, int hitOut, int objOut,
                              int pointCount, int mask, int flags, int mode);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern void hitDetectFn_80067958(int obj, float* startPoints, float* endPoints, int pointCount,
                                 void* outPos, int mode);
extern void hitDetectFn_800691c0(int obj, u32* bounds, int mask, int flags);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, float* startPoints, float* endPoints, float* radii,
                                            int pointCount);

extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern float mathSinf(float x);

extern f32 fn_802966F4(GameObject* obj); /* returns a target proximity/distance scalar */
extern void fn_8029656C(int obj, float* out); /* fills out[] with a target motion scalar */
extern int EmissionController_IsLingering(int obj);
extern void cameraGetPrevPos2(int obj, f32* x, f32* y, f32* z);

#define gCamcontrolModeSettings cameraMtxVar57

extern f32 lbl_803DD52C;
extern f32 lbl_803E1688;
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16B8;
extern f32 lbl_803E16D0;
extern f32 lbl_803E16D4;
extern f32 lbl_803E16D8;
extern f32 lbl_803E16DC;
extern f32 lbl_803E16E0;
extern f32 lbl_803E16E4;
extern f32 lbl_803E16E8;
extern f32 lbl_803E16EC;
extern f32 lbl_803E16F0;
extern f32 lbl_803E16F4;
extern f32 lbl_803E1700;
extern f32 lbl_803E1704;
extern f32 lbl_803E1708;
extern f32 lbl_803E170C;
extern f32 gCamcontrolByteRateNormalizer;
extern f32 lbl_803E1714;
extern f32 lbl_803E1718;
extern f32 lbl_803E171C;
extern f32 lbl_803E1720;
extern f32 lbl_803E1724;
extern f32 lbl_803E1728;
extern f32 lbl_803E172C;
extern f32 lbl_803E1730;
extern f32 lbl_803E1734;
extern f32 lbl_803E1738;

void camcontrol_updateVerticalBounds(CameraObject* camera, int flags, int collisionFlag, float* upperBound,
                                     float* lowerBound)
{
    float zLim;
    float pt0;
    float zB;
    float diff;
    float bestUpper;
    float bestLower;
    int res;
    int count;
    int i;
    int j;
    int off;
    int off2;
    int camObj;
    int cameraAddr;
    u32 bounds[6];
    f32 pos[3];
    int hits;

    cameraAddr = (int)camera;
    camObj = (int)camera->anim.targetObj;
    if ((flags & 1) != 0)
    {
        *(float*)(cameraAddr + 0x74) = lbl_803E1688;
        *(s8*)(cameraAddr + 0x84) = -1;
        *(s8*)(cameraAddr + 0x88) = collisionFlag;
        res = objBboxFn_800640cc(&camera->probePosX, &camera->anim.worldPosX, 1, 0, 0, 0x10, 0xffffffff, 0xff, 0);
        camera->cameraCollisionActive = res;
        pos[0] = camera->anim.worldPosX;
        pos[1] = camera->anim.worldPosY;
        pos[2] = camera->anim.worldPosZ;
        hitDetect_calcSweptSphereBounds(bounds, &camera->probePosX, pos, (float*)(cameraAddr + 0x74), 1);
        hitDetectFn_800691c0(camObj, bounds, 0x240, 1);
        hitDetectFn_80067958(camObj, &camera->probePosX, pos, 1, &camera->anim.pad34[0], 0);
        camera->anim.worldPosX = pos[0];
        camera->anim.worldPosY = pos[1];
        camera->anim.worldPosZ = pos[2];
    }
    if ((flags & 2) != 0)
    {
        count = hitDetectFn_80065e50(camObj, camera->anim.worldPosX, camera->anim.worldPosY,
                                     camera->anim.worldPosZ, &hits, 1, 0x40);
        *upperBound = lbl_803E16D0;
        bestUpper = (*lowerBound = lbl_803E16D4);
        bestLower = bestUpper;
        off = 0;
        zLim = lbl_803E16AC;
        for (i = 0; i < count; i++)
        {
            zB = lbl_803E16B4;
            if ((*(float**)(hits + off))[2] < zLim)
            {
                pt0 = **(float**)(hits + off);
                if (pt0 > camera->anim.worldPosY - zB)
                {
                    diff = camera->anim.worldPosY - pt0;
                    if (diff < zLim)
                    {
                        diff = -diff;
                    }
                    if (diff < bestLower)
                    {
                        *lowerBound = pt0;
                        camera->unk12C = (*(float**)(hits + off))[2];
                        bestLower = diff;
                    }
                }
            }
            off += 4;
        }
        off2 = 0;
        zLim = lbl_803E16AC;
        for (j = 0; j < count; j++)
        {
            zB = lbl_803E16B4;
            if ((*(float**)(hits + off2))[2] > zLim)
            {
                pt0 = **(float**)(hits + off2);
                if (pt0 < zB + camera->anim.worldPosY)
                {
                    diff = camera->anim.worldPosY - pt0;
                    if (diff < zLim)
                    {
                        diff = -diff;
                    }
                    if (diff < bestUpper)
                    {
                        *upperBound = pt0;
                        camera->unk130 = (*(float**)(hits + off2))[2];
                        bestUpper = diff;
                    }
                }
            }
            off2 += 4;
        }
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                   camera->anim.worldPosZ, &camera->anim.localPosX,
                                   &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

void CameraModeNormal_func0A(float* minDistanceOut, float* maxDistanceOut,
                             float* lowerHeightOffsetOut, float* upperHeightOffsetOut,
                             float* targetHeightOut)
{
    *minDistanceOut = gCamcontrolModeSettings->minDistance;
    *maxDistanceOut = gCamcontrolModeSettings->maxDistance;
    if (lowerHeightOffsetOut != NULL)
    {
        *lowerHeightOffsetOut = gCamcontrolModeSettings->lowerHeightOffset;
    }
    if (upperHeightOffsetOut != NULL)
    {
        *upperHeightOffsetOut = gCamcontrolModeSettings->upperHeightOffset;
    }
    if (targetHeightOut != NULL)
    {
        *targetHeightOut = gCamcontrolModeSettings->targetHeight;
    }
}

typedef struct CamSlideRot
{
    s16 angles[4];
    f32 unk08;
    f32 unk0C;
    f32 unk10;
    f32 unk14;
} CamSlideRot;

STATIC_ASSERT(offsetof(CamSlideRot, angles) == 0x00);
STATIC_ASSERT(offsetof(CamSlideRot, unk08) == 0x08);
STATIC_ASSERT(offsetof(CamSlideRot, unk14) == 0x14);

typedef struct CamSlideObjectState
{
    u8 unk00[0x1A4];
    f32 vectorX;
    f32 vectorY;
    f32 vectorZ;
} CamSlideObjectState;

STATIC_ASSERT(offsetof(CamSlideObjectState, vectorX) == 0x1A4);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorY) == 0x1A8);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorZ) == 0x1AC);

void camslide_update(CameraObject* camera, GameObject* target, f32 upperBound, f32 lowerBound)
{

    extern f32 interpolate(f32 a, f32 t, f32 exp);

    CamSlideObjectState* state;
    u32 angle;
    int cur;
    f32 high;
    f32 low;
    f32 range;
    f32 slide;
    f32 approach;
    f32 mtx[16];
    CamSlideRot rot;
    f32 velX;
    f32 step;
    f32 velZ;
    f32 speed;
    f32 outX;
    f32 outY;
    f32 outZ;

    ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
        (int)camera, &velX, &step, &velZ, &speed, gCamcontrolModeSettings->targetHeight, 0);
    speed = velZ * velZ + (velX * velX + step * step);
    if (speed > *(f32*)&lbl_803E16AC)
    {
        speed = sqrtf(speed);
    }
    if (speed < *(f32*)&lbl_803E1694)
    {
        speed = lbl_803E1694;
    }
    high = gCamcontrolModeSettings->upperHeightOffset +
        (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight);
    low = gCamcontrolModeSettings->lowerHeightOffset +
        (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight);
    if (target->anim.classId == 1)
    {
        state = (CamSlideObjectState*)target->extra;
        angle = getAngle((f64)velX, velZ);
        rot.angles[0] = (s16)(0x8000 - angle);
        rot.angles[1] = 0;
        rot.angles[2] = 0;
        rot.unk08 = lbl_803E16A4;
        rot.unk0C = lbl_803E16AC;
        rot.unk10 = lbl_803E16AC;
        rot.unk14 = lbl_803E16AC;
        mtxRotateByVec3s(mtx, rot.angles);
        Matrix_TransformPoint(mtx, state->vectorX, state->vectorY,
                              state->vectorZ, &outX, &outY, &outZ);
        angle = 0x4000 - (getAngle((f64)outY, outZ) & 0xffff);
        cur = gCamcontrolModeSettings->slideAngle;
        gCamcontrolModeSettings->slideAngle =
            cur + ((int)(framesThisStep * ((int)angle - cur)) >> 5);
    }
    else
    {
        gCamcontrolModeSettings->slideAngle -=
            (int)(gCamcontrolModeSettings->slideAngle * framesThisStep) >> 5;
    }
    cur = gCamcontrolModeSettings->slideAngle;
    if (cur < 0)
    {
        slide = gCamcontrolModeSettings->slideLeftAmount *
            mathSinf((lbl_803E168C * cur) / lbl_803E1690);
    }
    else if (cur > 0)
    {
        slide = gCamcontrolModeSettings->slideRightAmount *
            mathSinf((lbl_803E168C * cur) / lbl_803E1690);
    }
    else
    {
        slide = lbl_803E16AC;
    }
    low += slide;
    high += slide;
    range = gCamcontrolModeSettings->minDistance - lbl_803E16D8;
    if (range < lbl_803E16DC)
    {
        range = lbl_803E16DC;
    }
    if (target->anim.classId == 1)
    {
        if (fn_802966F4(target) <= lbl_803E16DC)
        {
            step = lbl_803E16E0 * gCamcontrolModeSettings->maxDistance -
                gCamcontrolModeSettings->lowerHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4)
            {
                step = *(f32*)&lbl_803E16B4;
            }
            gCamcontrolModeSettings->lowerHeightOffset =
                gCamcontrolModeSettings->lowerHeightOffset + step;
            if (gCamcontrolModeSettings->lowerHeightOffset > gCamcontrolModeSettings->maxDistance)
            {
                gCamcontrolModeSettings->lowerHeightOffset = gCamcontrolModeSettings->maxDistance;
            }
            step = lbl_803E16E0 * gCamcontrolModeSettings->maxDistance -
                gCamcontrolModeSettings->upperHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4)
            {
                step = *(f32*)&lbl_803E16B4;
            }
            gCamcontrolModeSettings->upperHeightOffset =
                gCamcontrolModeSettings->upperHeightOffset + step;
            if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->maxDistance)
            {
                gCamcontrolModeSettings->upperHeightOffset = gCamcontrolModeSettings->maxDistance;
            }
        }
        else
        {
            step = gCamcontrolModeSettings->baseLowerHeightOffset -
                gCamcontrolModeSettings->lowerHeightOffset;
            step *= lbl_803E16E4;
            if (step > *(f32*)&lbl_803E16E8)
            {
                step = lbl_803E16E8;
            }
            if (step < *(f32*)&lbl_803E16EC)
            {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings->lowerHeightOffset =
                gCamcontrolModeSettings->lowerHeightOffset + step;
            if (gCamcontrolModeSettings->lowerHeightOffset <
                gCamcontrolModeSettings->baseLowerHeightOffset)
            {
                gCamcontrolModeSettings->lowerHeightOffset =
                    gCamcontrolModeSettings->baseLowerHeightOffset;
            }
            step = gCamcontrolModeSettings->baseUpperHeightOffset -
                gCamcontrolModeSettings->upperHeightOffset;
            step *= lbl_803E16E4;
            if (step > *(f32*)&lbl_803E16E8)
            {
                step = lbl_803E16E8;
            }
            if (step < *(f32*)&lbl_803E16EC)
            {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings->upperHeightOffset =
                gCamcontrolModeSettings->upperHeightOffset + step;
            if (gCamcontrolModeSettings->upperHeightOffset <
                gCamcontrolModeSettings->baseUpperHeightOffset)
            {
                gCamcontrolModeSettings->upperHeightOffset =
                    gCamcontrolModeSettings->baseUpperHeightOffset;
            }
            if (speed > lbl_803E16DC)
            {
                if (speed <= range)
                {
                    if (range - lbl_803E16DC > lbl_803E16AC)
                    {
                        speed = (speed - lbl_803E16DC) / (range - lbl_803E16DC);
                    }
                    if (speed < *(f32*)&lbl_803E16AC)
                    {
                        speed = lbl_803E16AC;
                    }
                    else if (speed > lbl_803E16A4)
                    {
                        speed = lbl_803E16A4;
                    }
                    low = speed * ((gCamcontrolModeSettings->targetHeight +
                        gCamcontrolModeSettings->lowerHeightOffset) - lbl_803E16F0) +
                        (lbl_803E16F0 + target->anim.worldPosY);
                    high = speed * ((gCamcontrolModeSettings->targetHeight +
                        gCamcontrolModeSettings->upperHeightOffset) - lbl_803E16F0) +
                        (lbl_803E16F0 + target->anim.worldPosY);
                }
            }
            else
            {
                high = lbl_803E16E0 * (lbl_803E16DC - speed) + (lbl_803E16F0 + target->anim.worldPosY);
                low = high;
            }
        }
    }
    if (camera->anim.worldPosY < low)
    {
        step = low - camera->anim.worldPosY;
    }
    else if (camera->anim.worldPosY > high)
    {
        step = high - camera->anim.worldPosY;
    }
    else
    {
        step = lbl_803E16AC;
    }
    approach = interpolate((f64)step, gCamcontrolModeSettings->heightAdjustRate,
                           timeDelta);
    step = approach;
    if ((f32)approach > lbl_803E16E8 && (f32)approach < lbl_803E16F4)
    {
        step = lbl_803E16AC;
    }
    camera->anim.worldPosY = camera->anim.worldPosY + step;
    if (camera->anim.worldPosY > lbl_803E16B8 + high)
    {
        camera->anim.worldPosY = lbl_803E16B8 + high;
    }
    if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->baseUpperHeightOffset)
    {
        if (gCamcontrolModeSettings->clampFlags.b6 &&
            camera->anim.worldPosY > gCamcontrolModeSettings->heightLockLimit)
        {
            camera->anim.worldPosY = gCamcontrolModeSettings->heightLockLimit;
        }
        if (target->anim.velocityY > lbl_803E16AC)
        {
            gCamcontrolModeSettings->clampFlags.b6 = 0;
        }
    }
    else
    {
        gCamcontrolModeSettings->clampFlags.b6 = 0;
    }
}

void firstperson_updatePitch(f32 targetY, CameraObject* camera)
{
    extern u32 getAngle();
    extern f32 interpolate(f32 a, f32 t, f32 exp);
    int v;
    f64 d;

    v = getAngle((f64)(camera->anim.worldPosY -
        (targetY + gCamcontrolModeSettings->targetHeight))) & 0xffff;
    v -= camera->anim.rotY & 0xffff;
    if (v > 0x8000)
    {
        v -= 0xffff;
    }
    if (v < -0x8000)
    {
        v += 0xffff;
    }
    d = interpolate((f64)(f32)v,
                    (f64)(lbl_803E16A4 / gCamcontrolModeSettings->yawResponseFrames),
                    timeDelta);
    camera->anim.rotY = (s16)((int)d + camera->anim.rotY);
}

void firstperson_updatePosition(CameraObject* camera, ObjAnimComponent* target)
{
    extern f32 interpolate(f32 a, f32 t, f32 exp);

    f32 dx;
    f32 dz;
    f32 dy;
    f32 dist;
    f32 clamped;
    f32 targetX;
    f32 targetZ;
    f32 ratio;
    f32 speed;

    ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
        (int)camera, &dx, &dz, &dy, &dist, gCamcontrolModeSettings->targetHeight, 1);
    dist = dy * dy + (dx * dx + dz * dz);
    if (dist > lbl_803E16AC)
    {
        dist = sqrtf(dist);
    }
    if (dist < *(f32 *)&lbl_803E1694)
    {
        dist = lbl_803E1694;
    }
    if (dist > lbl_803E1700 * gCamcontrolModeSettings->maxDistance)
    {
        camcontrol_getTargetPosition(camera, target, &camera->anim.worldPosX, &camera->anim.rotY);
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY,
                                       &camera->anim.localPosZ, (u32)camera->anim.parent);
        camera->probePosX = camera->anim.worldPosX;
        camera->probePosY = camera->anim.worldPosY;
        camera->probePosZ = camera->anim.worldPosZ;
        ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
            (int)camera, &dx, &dz, &dy, &dist, gCamcontrolModeSettings->targetHeight, 1);
        dist = dy * dy + (dx * dx + dz * dz);
        if (dist > lbl_803E16AC)
        {
            dist = sqrtf(dist);
        }
        if (dist < *(f32 *)&lbl_803E1694)
        {
            dist = lbl_803E1694;
        }
    }

    if (dist > gCamcontrolModeSettings->maxDistance)
    {
        clamped = gCamcontrolModeSettings->maxDistance;
        gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
        gCamcontrolModeSettings->clampFlags.b7 = 1;
    }
    else if (dist < gCamcontrolModeSettings->minDistance)
    {
        clamped = gCamcontrolModeSettings->minDistance;
        gCamcontrolModeSettings->clampFlags.b7 = 0;
    }
    else
    {
        clamped = dist;
        gCamcontrolModeSettings->clampFlags.b7 = 0;
    }

    targetX = camera->anim.localPosX;
    targetZ = camera->anim.localPosZ;
    if ((gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0) && (clamped != dist) &&
        (lbl_803E16AC != gCamcontrolModeSettings->distanceAdjustRate))
    {
        if (dist < lbl_803E16A4)
        {
            dist = lbl_803E16A4;
        }
        ratio = interpolate(dist - clamped, gCamcontrolModeSettings->distanceAdjustRate, timeDelta);
        ratio = (dist + ratio) / dist;
        if (ratio > lbl_803E16AC)
        {
            targetX = target->localPosX + dx / ratio;
            targetZ = target->localPosZ + dy / ratio;
        }
    }

    dx = targetX - camera->anim.localPosX;
    dy = targetZ - camera->anim.localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    if (dist > lbl_803E16AC)
    {
        dx = dx / dist;
        dy = dy / dist;
    }
    ratio = PSVECMag(&target->velocityX);
    speed = ratio * (lbl_803E1704 * timeDelta);
    if (speed < lbl_803E16A4)
    {
        speed = lbl_803E16A4;
    }
    dist = dist < lbl_803E16AC ? lbl_803E16AC : (dist > speed ? speed : dist);
    dist = dist < *(volatile f32*)&lbl_803E16AC ? lbl_803E16AC : (dist > lbl_803E1708 ? lbl_803E1708 : dist);
    camera->anim.localPosX = dx * dist + camera->anim.localPosX;
    camera->anim.localPosZ = dy * dist + camera->anim.localPosZ;

    if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->baseUpperHeightOffset)
    {
        dx = camera->anim.localPosX - target->localPosX;
        dy = camera->anim.localPosZ - target->localPosZ;
        dist = sqrtf(dx * dx + dy * dy);
        if (dist < lbl_803E170C * gCamcontrolModeSettings->minDistance)
        {
            if (dist > lbl_803E16AC)
            {
                dx = dx / dist;
                dy = dy / dist;
            }
            dist = *(f32 *)&lbl_803E170C * gCamcontrolModeSettings->minDistance;
            camera->anim.localPosX = dist * dx + target->localPosX;
            camera->anim.localPosZ = dist * dy + target->localPosZ;
        }
    }
}

void firstperson_loadSettings(CamcontrolFirstPersonActionSettings* settings)
{
    float fval;
    CameraObject* camera;

    camera = (CameraObject*)(*gCameraInterface)->getCamera();
    gCamcontrolModeSettings->savedTargetHeight = gCamcontrolModeSettings->targetHeight;
    gCamcontrolModeSettings->savedLowerHeightOffset = gCamcontrolModeSettings->lowerHeightOffset;
    gCamcontrolModeSettings->savedUpperHeightOffset = gCamcontrolModeSettings->upperHeightOffset;
    gCamcontrolModeSettings->savedMinDistance = gCamcontrolModeSettings->minDistance;
    gCamcontrolModeSettings->savedMaxDistance = gCamcontrolModeSettings->maxDistance;
    gCamcontrolModeSettings->savedFov = camera->fov;
    gCamcontrolModeSettings->savedSlideRightAmount = gCamcontrolModeSettings->slideRightAmount;
    gCamcontrolModeSettings->savedSlideLeftAmount = gCamcontrolModeSettings->slideLeftAmount;
    gCamcontrolModeSettings->savedHeightAdjustRate = gCamcontrolModeSettings->heightAdjustRate;
    gCamcontrolModeSettings->savedDistanceAdjustRate = gCamcontrolModeSettings->distanceAdjustRate;
    fval = settings->targetHeight;
    gCamcontrolModeSettings->targetHeight = fval;
    gCamcontrolModeSettings->targetTargetHeight = fval;
    fval = (f32)(u32)settings->lowerHeightOffset;
    gCamcontrolModeSettings->lowerHeightOffset = fval;
    gCamcontrolModeSettings->baseLowerHeightOffset = fval;
    gCamcontrolModeSettings->targetLowerHeightOffset = fval;
    fval = (f32)(u32)settings->upperHeightOffset;
    gCamcontrolModeSettings->upperHeightOffset = fval;
    gCamcontrolModeSettings->baseUpperHeightOffset = fval;
    gCamcontrolModeSettings->targetUpperHeightOffset = fval;
    fval = (f32)(u32)settings->minDistance;
    gCamcontrolModeSettings->minDistance = fval;
    gCamcontrolModeSettings->targetMinDistance = fval;
    fval = (f32)(u32)settings->maxDistance;
    gCamcontrolModeSettings->maxDistance = fval;
    gCamcontrolModeSettings->targetMaxDistance = fval;
    fval = settings->fov;
    camera->fov = fval;
    gCamcontrolModeSettings->fov = fval;
    fval = (f32)(u32)settings->slideRightAmount;
    gCamcontrolModeSettings->slideRightAmount = fval;
    gCamcontrolModeSettings->targetSlideRightAmount = fval;
    fval = (f32)(u32)settings->slideLeftAmount;
    gCamcontrolModeSettings->slideLeftAmount = fval;
    gCamcontrolModeSettings->targetSlideLeftAmount = fval;
    if (settings->distanceAdjustRate != 0)
    {
        fval = (f32)(u32)settings->distanceAdjustRate / gCamcontrolByteRateNormalizer;
        gCamcontrolModeSettings->distanceAdjustRate = fval;
        gCamcontrolModeSettings->targetDistanceAdjustRate = fval;
    }
    else
    {
        gCamcontrolModeSettings->targetDistanceAdjustRate = lbl_803E1714;
    }
    if (settings->heightAdjustRate != 0)
    {
        fval = (f32)(u32)settings->heightAdjustRate / gCamcontrolByteRateNormalizer;
        gCamcontrolModeSettings->heightAdjustRate = fval;
        gCamcontrolModeSettings->targetHeightAdjustRate = fval;
    }
    else
    {
        gCamcontrolModeSettings->targetHeightAdjustRate = lbl_803E1714;
    }
    gCamcontrolModeSettings->transitionTimer = 0;
    gCamcontrolModeSettings->transitionDuration = 0;
}

void CameraModeNormal_free(CameraObject* camera)
{
    gCamcontrolModeSettings->savedWorldX = camera->anim.worldPosX;
    gCamcontrolModeSettings->savedWorldY = camera->anim.worldPosY;
    gCamcontrolModeSettings->savedWorldZ = camera->anim.worldPosZ;
    gCamcontrolModeSettings->savedRotX = camera->anim.rotX;
    gCamcontrolModeSettings->savedRotY = camera->anim.rotY;
    gCamcontrolModeSettings->savedRotZ = camera->anim.rotZ;
    gCamcontrolModeSettings->wallAvoidanceFlags.b6 = 0;
}

void camstatic_update(CameraObject* camera)
{
    extern f32 interpolate(f32 a, f32 t, f32 exp);
    GameObject* target;
    float fa;
    int val;
    u32 angleDelta;
    int yaw;
    float aimZ2;
    float aimY2;
    float aimX2;
    float aimZ;
    float aimY;
    float aimX;
    float dx2;
    u8 relPosScratch[4];
    float dz;
    float dy;
    float dx;
    u8 probeTraceScratch[112];
    u8 wallTraceScratch[116];

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
    camMoveFn_80104040(camera, target);
    firstperson_updatePosition(camera, &target->anim);
    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY,
                                   camera->anim.localPosZ, &camera->anim.worldPosX,
                                   &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   (u32)camera->anim.parent);
    camslide_update(camera, target, gCamcontrolModeSettings->verticalUpperBound,
                    gCamcontrolModeSettings->verticalLowerBound);
    camcontrol_updateVerticalBounds(camera, 1, 8, &gCamcontrolModeSettings->verticalUpperBound,
                                    &gCamcontrolModeSettings->verticalLowerBound);
    if (gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0)
    {
        gCamcontrolModeSettings->targetActionFlags = *(u8*)((int)camera + 0xa2);
        if (((camera->cameraCollisionActive != 0) ||
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
            (target->anim.velocityY <= lbl_803E16AC))
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
        if ((gCamcontrolModeSettings->targetActionFlags == 1) || (camera->cameraCollisionActive != 0))
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
            camcontrol_traceMove(&aimX2, &camera->anim.worldPosX,
                                 &camera->anim.worldPosX, wallTraceScratch, 3, 1, 1, lbl_803E1688);
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
            camcontrol_traceMove(&aimX, &camera->anim.worldPosX,
                                 &camera->anim.worldPosX, probeTraceScratch, 3, 1, 1, lbl_803E1688);
            camera->probePosX = camera->anim.worldPosX;
            camera->probePosY = camera->anim.worldPosY;
            camera->probePosZ = camera->anim.worldPosZ;
            gCamcontrolModeSettings->collisionProbeTimer = 0;
        }
    }
    ((void (*)(int, f32*, f32*, f32*, f32*, int, f32))(*gCameraInterface)->getRelativePosition)(
        (int)camera, &dx2, (f32*)relPosScratch, &dz, &dy, 0, gCamcontrolModeSettings->targetHeight);
    yaw = 0x8000 - (u16)getAngle(dx2, dz);
    gCamcontrolModeSettings->pitchOffset = 0;
    camera->anim.rotX = yaw - gCamcontrolModeSettings->pitchOffset;
    angleDelta = (u16)getAngle(camera->anim.worldPosY -
                     (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight),
                     dy);
    angleDelta = angleDelta - ((int)camera->anim.rotY & 0xffffU);
    if (0x8000 < (int)angleDelta)
    {
        angleDelta = angleDelta - 0xffff;
    }
    if ((int)angleDelta < -0x8000)
    {
        angleDelta = angleDelta + 0xffff;
    }
    val = interpolate((f32)(int)angleDelta,
                             lbl_803E16A4 /
                             (f32)(u32)gCamcontrolModeSettings->yawResponseFrames, timeDelta);
    camera->anim.rotY = camera->anim.rotY + val;
    camcontrol_updateTargetAction(camera, target);
    val = interpolate((f32)camera->anim.rotZ, lbl_803E1730, timeDelta);
    camera->anim.rotZ = camera->anim.rotZ - val;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                   camera->anim.worldPosZ, &camera->anim.localPosX,
                                   &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (u32)camera->anim.parent);
}

void pathcam_loadSettings(CameraObject* cam, int mode, u8* data)
{
    GameObject* target;
    f32 vOutA;
    f32 vOutB;
    f32 vOutC;
    f32 vOutD;
    f32 fVal;
    u32 uVal;

    gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
    gCamcontrolModeSettings->collisionState = 0;
    gCamcontrolModeSettings->collisionProbeTimer = 0;
    gCamcontrolModeSettings->wallAvoidanceTimer = 0;
    gCamcontrolModeSettings->clampFlags.b7 = 0;
    gCamcontrolModeSettings->yawResponseFrames = 8;
    target = (GameObject*)cam->anim.targetObj;
    switch (mode)
    {
    case 0:
        memset(gCamcontrolModeSettings, 0, sizeof(CamcontrolModeSettings));
        if (data != NULL)
        {
            fVal = (f32)(u32) * (u16*)(data + 0x1c);
            gCamcontrolModeSettings->minDistance = fVal;
            gCamcontrolModeSettings->targetMinDistance = fVal;
            fVal = (f32)(u32) * (u16*)(data + 0x1a);
            gCamcontrolModeSettings->maxDistance = fVal;
            gCamcontrolModeSettings->targetMaxDistance = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->lowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->upperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
        }
        fVal = lbl_803E16F0;
        gCamcontrolModeSettings->targetHeight = fVal;
        gCamcontrolModeSettings->targetTargetHeight = fVal;
        fVal = lbl_803E1714;
        gCamcontrolModeSettings->distanceAdjustRate = fVal;
        gCamcontrolModeSettings->targetDistanceAdjustRate = fVal;
        fVal = lbl_803E1734;
        gCamcontrolModeSettings->savedHeightAdjustRate = fVal;
        gCamcontrolModeSettings->heightAdjustRate = fVal;
        gCamcontrolModeSettings->targetHeightAdjustRate = fVal;
        fVal = lbl_803E1738;
        gCamcontrolModeSettings->slideRightAmount = fVal;
        gCamcontrolModeSettings->targetSlideRightAmount = fVal;
        fVal = lbl_803E16DC;
        gCamcontrolModeSettings->slideLeftAmount = fVal;
        gCamcontrolModeSettings->targetSlideLeftAmount = fVal;
        gCamcontrolModeSettings->pad24 = lbl_803E16D0;
        gCamcontrolModeSettings->pad20 = lbl_803E16D4;
        gCamcontrolModeSettings->initialized = 1;
        gCamcontrolModeSettings->fov = cam->fov;
        camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
        fVal = cam->anim.worldPosX;
        cam->anim.localPosX = fVal;
        cam->probePosX = fVal;
        cam->anim.hitboxScale = fVal;
        fVal = cam->anim.worldPosY;
        cam->anim.localPosY = fVal;
        cam->probePosY = fVal;
        *(f32*)((u8*)cam + 0xAC) = fVal;
        fVal = cam->anim.worldPosZ;
        cam->anim.localPosZ = fVal;
        cam->probePosZ = fVal;
        *(f32*)((u8*)cam + 0xB0) = fVal;
        cam->anim.rotX = 0;
        cam->anim.rotZ = 0;
        if (data != NULL)
        {
            cam->fov = (f32)(u32)data[0x19];
        }
        break;
    case 4:
        camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       *(int*)&cam->anim.parent);
        ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
            (int)cam, &vOutA, &vOutB, &vOutC, &vOutD, gCamcontrolModeSettings->targetHeight, 0);
        vOutB = cam->anim.localPosY - (target->anim.localPosY + gCamcontrolModeSettings->targetHeight);
        cam->anim.rotY = getAngle(vOutB, vOutD);
        cam->anim.rotZ = 0;
        cam->probePosX = cam->anim.worldPosX;
        cam->probePosY = cam->anim.worldPosY;
        cam->probePosZ = cam->anim.worldPosZ;
        cam->anim.hitboxScale = cam->anim.localPosX;
        *(f32*)((u8*)cam + 0xAC) = cam->anim.localPosY;
        *(f32*)((u8*)cam + 0xB0) = cam->anim.localPosZ;
        cam->fov = gCamcontrolModeSettings->fov;
        gCamcontrolModeSettings->transitionTimer = 0;
        break;
    case 2:
        if (data != NULL)
        {
            gCamcontrolModeSettings->targetTargetHeight = lbl_803E16F0;
            fVal = (f32)(u32)data[6];
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)data[8];
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetMinDistance = (f32)(u32)data[3];
            gCamcontrolModeSettings->targetMaxDistance = (f32)(u32)data[4];
            gCamcontrolModeSettings->fov = (f32) * (s8*)(data + 2);
            gCamcontrolModeSettings->targetSlideRightAmount = (f32)(u32)data[9];
            gCamcontrolModeSettings->targetSlideLeftAmount = (f32)(u32)data[0xa];
            uVal = data[0xb];
            if (uVal != 0)
            {
                gCamcontrolModeSettings->targetDistanceAdjustRate = uVal / gCamcontrolByteRateNormalizer;
            }
            else
            {
                gCamcontrolModeSettings->targetDistanceAdjustRate = lbl_803E1714;
            }
            uVal = data[0xc];
            if (uVal != 0)
            {
                gCamcontrolModeSettings->targetHeightAdjustRate = uVal / gCamcontrolByteRateNormalizer;
            }
            else
            {
                gCamcontrolModeSettings->targetHeightAdjustRate = lbl_803E1714;
            }
            gCamcontrolModeSettings->transitionTimer = (s16) * (s8*)(data + 1);
            gCamcontrolModeSettings->transitionDuration = (s16) * (s8*)(data + 1);
            *(u8*)&cam->letterboxTargetOffset = data[7];
        }
        else
        {
            gCamcontrolModeSettings->targetTargetHeight = gCamcontrolModeSettings->savedTargetHeight;
            fVal = gCamcontrolModeSettings->savedLowerHeightOffset;
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = gCamcontrolModeSettings->savedUpperHeightOffset;
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetMinDistance = gCamcontrolModeSettings->savedMinDistance;
            gCamcontrolModeSettings->targetMaxDistance = gCamcontrolModeSettings->savedMaxDistance;
            gCamcontrolModeSettings->fov = gCamcontrolModeSettings->savedFov;
            gCamcontrolModeSettings->targetSlideRightAmount =
                gCamcontrolModeSettings->savedSlideRightAmount;
            gCamcontrolModeSettings->targetSlideLeftAmount =
                gCamcontrolModeSettings->savedSlideLeftAmount;
            gCamcontrolModeSettings->targetDistanceAdjustRate =
                gCamcontrolModeSettings->savedDistanceAdjustRate;
            gCamcontrolModeSettings->targetHeightAdjustRate =
                gCamcontrolModeSettings->savedHeightAdjustRate;
            gCamcontrolModeSettings->transitionTimer = 0x3c;
            gCamcontrolModeSettings->transitionDuration = 0x3c;
        }
        gCamcontrolModeSettings->savedTargetHeight = gCamcontrolModeSettings->targetHeight;
        gCamcontrolModeSettings->savedLowerHeightOffset = gCamcontrolModeSettings->lowerHeightOffset;
        gCamcontrolModeSettings->savedUpperHeightOffset = gCamcontrolModeSettings->upperHeightOffset;
        gCamcontrolModeSettings->savedMinDistance = gCamcontrolModeSettings->minDistance;
        gCamcontrolModeSettings->savedMaxDistance = gCamcontrolModeSettings->maxDistance;
        gCamcontrolModeSettings->savedFov = cam->fov;
        gCamcontrolModeSettings->savedSlideRightAmount = gCamcontrolModeSettings->slideRightAmount;
        gCamcontrolModeSettings->savedSlideLeftAmount = gCamcontrolModeSettings->slideLeftAmount;
        gCamcontrolModeSettings->savedDistanceAdjustRate =
            gCamcontrolModeSettings->distanceAdjustRate;
        gCamcontrolModeSettings->savedHeightAdjustRate = gCamcontrolModeSettings->heightAdjustRate;
        if ((data != NULL) && (data[0xd] != 0))
        {
            camcontrol_getTargetPosition(cam, &target->anim, &cam->anim.worldPosX, &cam->anim.rotY);
            Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                           &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                           *(int*)&cam->anim.parent);
            gCamcontrolModeSettings->transitionTimer = 0;
        }
        break;
    case 3:
        cam->fov = gCamcontrolModeSettings->fov;
        cam->anim.worldPosX = gCamcontrolModeSettings->savedWorldX;
        cam->anim.worldPosY = gCamcontrolModeSettings->savedWorldY;
        cam->anim.worldPosZ = gCamcontrolModeSettings->savedWorldZ;
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       *(int*)&cam->anim.parent);
        cam->anim.rotX = gCamcontrolModeSettings->savedRotX;
        cam->anim.rotY = gCamcontrolModeSettings->savedRotY;
        cam->anim.rotZ = gCamcontrolModeSettings->savedRotZ;
        cam->anim.hitboxScale = cam->anim.localPosX;
        *(f32*)((u8*)cam + 0xAC) = cam->anim.localPosY;
        *(f32*)((u8*)cam + 0xB0) = cam->anim.localPosZ;
        cam->probePosX = cam->anim.worldPosX;
        cam->probePosY = cam->anim.worldPosY;
        cam->probePosZ = cam->anim.worldPosZ;
        gCamcontrolModeSettings->transitionTimer = 0;
        break;
    case 1:
        cam->fov = gCamcontrolModeSettings->fov;
        gCamcontrolModeSettings->wallAvoidanceFlags.b7 =
            gCamcontrolModeSettings->wallAvoidanceFlags.b6;
        break;
    }
    gCamcontrolModeSettings->wallAvoidanceFlags.b6 = 0;
    cam->unk13E = 1;
}

void camcontrol_releaseModeSettings(void)
{
    mm_free(gCamcontrolModeSettings);
    gCamcontrolModeSettings = 0;
}

void camcontrol_initialiseModeSettings(void)
{
    gCamcontrolModeSettings = (CamcontrolModeSettings*)mmAlloc(sizeof(CamcontrolModeSettings), 0xf, 0);
    memset(gCamcontrolModeSettings, 0, sizeof(CamcontrolModeSettings));
}
