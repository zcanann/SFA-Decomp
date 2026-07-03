/* DLL 0x0049 (cameramodecombat) — Camera mode combat handlers [0x8010BF08-0x8010CEC0). */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/dll/CAM/cutCam.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/dll/fx_800944A0_shared.h"

#define CAMERAMODECOMBAT_OBJFLAG_FREED 0x40
#define PAD_BUTTON_B 0x200
extern CameraModeCombatState* gCamCombatState;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;
extern u32 Camera_GetCurrentViewSlot();



extern u32 fn_8029630C(int obj);
extern int objAnimFn_80296328(int obj);
extern u32 cameraGetPrevPos2();
extern s32 gCamCombatPrevYawDiff;
extern f64 lbl_803E1918;
extern f32 lbl_803E18CC;
extern f32 lbl_803E18D0;
extern f32 lbl_803E18D4;
extern f32 lbl_803E18D8;
extern f32 lbl_803E18DC;
extern f32 lbl_803E18E0;
extern f32 lbl_803E18E4;
extern f32 lbl_803E18E8;
extern f32 lbl_803E18EC;
extern f32 lbl_803E18F0;
extern f32 lbl_803E18F4;
extern f32 lbl_803E18F8;
extern f32 gCamCombatPi;
extern f32 gCamCombatBinAngleHalfCircle;
extern f32 lbl_803E1904;
extern f32 lbl_803E1908;
extern f32 lbl_803E190C;
extern f32 lbl_803E1910;
extern f32 lbl_803E1920;
extern f32 lbl_803E1924;
extern f32 lbl_803E1928;
extern f32 lbl_803E192C;
extern f32 lbl_803E1930;
extern f32 lbl_803E1940;
extern int getAngle(float y, float x);
extern f32 interpolate(f32 a, f32 t, f32 exp);
extern float powfBitEstimate(float x, float y);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern f32 PSVECMag(f32 * v);
extern void PSVECNormalize(f32 * v, f32 * out);
extern void PSVECScale(f32* v, f32* out, f32 s);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);

void CameraModeCombat_copyToCurrent_nop(void)
{
}

void fn_8010BF08(CameraObject* camera, float* outX, float* outY, float* outZ, f32* targetY)
{
    GameObject* focus;
    GameObject* target;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    u8 curIdx;
    float t;
    float lim;

    target = (GameObject*)camera->targetObj;
    focus = (GameObject*)camera->anim.targetObj;
    hitVolumes = target->anim.hitVolumeTransforms;
    curIdx = target->hitVolumeIndex;
    if ((u32)curIdx != gCamCombatState->pathBlendTargetIndex)
    {
        gCamCombatState->pathBlendStartIndex = gCamCombatState->pathBlendTargetIndex;
        gCamCombatState->pathBlendWeight = lbl_803E18C0;
    }
    t = gCamCombatState->pathBlendWeight;
    lim = lbl_803E18C4;
    if (t > lim)
    {
        gCamCombatState->pathBlendWeight = t - lbl_803E18C8 * timeDelta;
        t = gCamCombatState->pathBlendWeight;
        if (gCamCombatState->pathBlendWeight < lim)
        {
            gCamCombatState->pathBlendWeight = lim;
            gCamCombatState->pathBlendStartIndex = target->hitVolumeIndex;
        }
        {
            u8 ci = gCamCombatState->pathBlendStartIndex;
            u8 ti = target->hitVolumeIndex;
            float dx = hitVolumes[ci].centerX - hitVolumes[ti].centerX;
            float dy = hitVolumes[ci].centerY - hitVolumes[ti].centerY;
            float dz = hitVolumes[ci].centerZ - hitVolumes[ti].centerZ;
            float w = gCamCombatState->pathBlendWeight;
            dx *= w;
            dy *= w;
            dz *= w;
            dx += hitVolumes[ti].centerX;
            dy += hitVolumes[ti].centerY;
            dz += hitVolumes[ti].centerZ;
            *outX = dx - focus->anim.worldPosX;
            *outY = dy - *targetY;
            *outZ = dz - focus->anim.worldPosZ;
        }
    }
    else
    {
        *outX = hitVolumes[target->hitVolumeIndex].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->hitVolumeIndex].centerY - *targetY;
        *outZ = hitVolumes[target->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
    }
    gCamCombatState->pathBlendTargetIndex = target->hitVolumeIndex;
}

typedef struct {
    u8 b0 : 1;
    u8 b1 : 1;
    u8 b2 : 1;
    u8 b3 : 1;
    u8 b4 : 1;
    u8 b5 : 1;
    u8 b6 : 1;
    u8 b7 : 1;
} CameraModeCombatFlags;

void CameraModeCombat_free(CameraObject* camera)
{
    if (camera->targetObj != NULL)
    {
        (*gCameraInterface)->setTarget(0);
    }
    mm_free(gCamCombatState);
    gCamCombatState = 0;
    Rcp_DisableBlurFilter();
    ((CameraModeCombatFlags*)&camera->smoothingFlags)->b0 = 0;
}

#pragma opt_common_subs off
void CameraModeCombat_update(short* cam)
{
    extern void fn_8010BF08(CameraObject* camera, f32* dx, f32* dy, f32* dz, f32* ty); /* #57 */
    f32 vec[3];
    f32 prevZ;
    f32 prevY;
    f32 prevX;
    f32 dy;
    f32 ty;
    f32 dx;
    f32 dz;
    f32 n[3];
    u8 trace[116];
    int view = Camera_GetCurrentViewSlot();
    GameObject* tgt;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    GameObject* focus;
    f32 dist;
    f32 px;
    f32 py;
    f32 pz;
    f32 range;
    f32 step;
    f32 zoom;
    f32 mag;
    f32 speed;
    f32 lim;
    f32 c;
    f32 sn;
    f32 t;
    f32 fa;
    f32 fb;
    int ang;
    int diff;
    u32 ad;
    short classId;

    if (gCamCombatState->invalidTarget != 0)
    {
        if (((CameraObject*)cam)->targetObj != NULL)
        {
            if (*(u8*)&((GameObject*)((CameraObject*)cam)->targetObj)->anim.resetHitboxMode & 0x40)
            {
                return;
            }
            if (((CameraObject*)cam)->targetFlags & 2)
            {
                return;
            }
            (*gCameraInterface)->setTarget(0);
        }
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
    }
    else
    {
        focus = (GameObject*)((CameraObject*)cam)->anim.targetObj;
        if (focus->anim.classId == 1 && objAnimFn_80296328((int)focus) == 0)
        {
            if (((CameraObject*)cam)->targetObj != NULL)
            {
                if (*(u8*)&((GameObject*)((CameraObject*)cam)->targetObj)->anim.resetHitboxMode & 0x40)
                {
                    return;
                }
                if (((CameraObject*)cam)->targetFlags & 2)
                {
                    return;
                }
                (*gCameraInterface)->setTarget(0);
            }
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
        }
        else
        {
            tgt = (GameObject*)((CameraObject*)cam)->targetObj;
            if (tgt == NULL || (tgt->objectFlags & CAMERAMODECOMBAT_OBJFLAG_FREED) || (*(u8*)&tgt->anim.resetHitboxMode & 0x28))
            {
                if (tgt != NULL)
                {
                    if (*(u8*)&tgt->anim.resetHitboxMode & 0x40)
                    {
                        return;
                    }
                    if (((CameraObject*)cam)->targetFlags & 2)
                    {
                        return;
                    }
                    (*gCameraInterface)->setTarget(0);
                }
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            }
            else
            {
                hitVolumes = tgt->anim.hitVolumeTransforms;
                if (hitVolumes != NULL)
                {
                    range = (f32)(s32)((u32)tgt->anim.modelInstance->hitVolumes[0].bounds[1] << 2);
                    if (((u16)getButtonsJustPressed(0) & PAD_BUTTON_B) && (int)fn_8029630C((int)focus) != 0)
                    {
                        if (((CameraObject*)cam)->targetObj != NULL)
                        {
                            if (*(u8*)&((GameObject*)((CameraObject*)cam)->targetObj)->anim.resetHitboxMode & 0x40)
                            {
                                return;
                            }
                            if (((CameraObject*)cam)->targetFlags & 2)
                            {
                                return;
                            }
                            (*gCameraInterface)->setTarget(0);
                        }
                        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                    }
                    else
                    {
                        ty = lbl_803E18D0 + focus->anim.worldPosY;
                        classId = tgt->anim.classId;
                        if (classId == 0x1c || classId == 0x6d || classId == 0x2a)
                        {
                            if (tgt->anim.seqId == 0x200)
                            {
                                ty = ty + lbl_803E18D0;
                            }
                            if (tgt->anim.modelInstance->hitVolumeCount > 1)
                            {
                                fn_8010BF08((CameraObject*)cam, &dx, &dy, &dz, &ty);
                            }
                            else
                            {
                                dx = hitVolumes[tgt->hitVolumeIndex].centerX - focus->anim.worldPosX;
                                dy = hitVolumes[tgt->hitVolumeIndex].centerY - ty;
                                dz = hitVolumes[tgt->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
                            }
                        }
                        else
                        {
                            ty = lbl_803E18D0 + focus->anim.worldPosY;
                            dx = hitVolumes[tgt->hitVolumeIndex].centerX - focus->anim.worldPosX;
                            dy = hitVolumes[tgt->hitVolumeIndex].centerY - ty;
                            dz = hitVolumes[tgt->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
                        }
                        fa = dx * dx;
                        fb = dz * dz;
                        dist = sqrtf(fa + fb);
                        ((CameraObject*)cam)->letterboxTargetOffset = 0x30;
                        ((CameraObject*)cam)->letterboxStep = 1;
                        if (dist > range)
                        {
                            if (((CameraObject*)cam)->targetObj != NULL)
                            {
                                if (*(u8*)&((GameObject*)((CameraObject*)cam)->targetObj)->anim.resetHitboxMode & 0x40)
                                {
                                    return;
                                }
                                if (((CameraObject*)cam)->targetFlags & 2)
                                {
                                    return;
                                }
                                (*gCameraInterface)->setTarget(0);
                            }
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        }
                        else
                        {
                            cameraGetPrevPos2(focus, &prevX, &prevY, &prevZ);
                            px = lbl_803E18D4 * dx + focus->anim.worldPosX;
                            py = lbl_803E18D8 + ty;
                            pz = lbl_803E18D4 * dz + focus->anim.worldPosZ;
                            ang = getAngle(dx, dz);
                            ad = (ang & 0xffff) + 0x8000;
                            diff = (int)*cam - ((0x8000 - ad) & 0xffff);
                            if (diff > 0x8000)
                            {
                                diff = diff - 0xffff;
                            }
                            if (diff < -0x8000)
                            {
                                diff = diff + 0xffff;
                            }
                            if (diff > 9000)
                            {
                                step = interpolate((f32)(s32)(diff - 9000), lbl_803E18DC, timeDelta);
                                *cam = (s16)((f32)(s32) * cam - step);
                            }
                            else if (diff < -9000)
                            {
                                step = interpolate((f32)(s32)(diff + 9000), lbl_803E18DC, timeDelta);
                                *cam = (s16)((f32)(s32) * cam - step);
                            }
                            if (diff < 3000 && diff > 0)
                            {
                                if (gCamCombatPrevYawDiff < 3000 && diff < 1000 && gCamCombatPrevYawDiff > diff)
                                {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (s16)((f32)(s32) * cam + step);
                                }
                                else
                                {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (s16)((f32)(s32) * cam + step);
                                }
                            }
                            else if (diff > -3000 && diff < 0)
                            {
                                if (gCamCombatPrevYawDiff > -3000 && diff > -1000 && gCamCombatPrevYawDiff < diff)
                                {
                                    step = interpolate((f32)(s32)(3000 - diff), lbl_803E18E0, timeDelta);
                                    *cam = (s16)((f32)(s32) * cam + step);
                                }
                                else
                                {
                                    step = interpolate((f32)(s32)(-diff - 3000), lbl_803E18E0, timeDelta);
                                    *cam = (s16)((f32)(s32) * cam + step);
                                }
                            }
                            gCamCombatPrevYawDiff = diff;
                            if (diff < 0)
                            {
                                diff = -diff;
                            }
                            if (diff > 9000)
                            {
                                diff = 9000;
                            }
                            zoom = (f32)(s32)(9000 - diff) / lbl_803E18E4;
                            step = interpolate(lbl_803E18E8 - gCamCombatState->heightOffset, lbl_803E18EC, timeDelta);
                            gCamCombatState->heightOffset = gCamCombatState->heightOffset + step;
                            fb = lbl_803E18C0 - zoom;
                            fb = lbl_803E18F0 + fb;
                            step = interpolate(
                                fb / lbl_803E18F4 - gCamCombatState->zoomOffset,
                                lbl_803E18F8, timeDelta);
                            gCamCombatState->zoomOffset = gCamCombatState->zoomOffset + step;
                            c = mathSinf((gCamCombatPi * (f32)(s32) * cam) / gCamCombatBinAngleHalfCircle);
                            sn = mathCosf((gCamCombatPi * (f32)(s32) * cam) / gCamCombatBinAngleHalfCircle);
                            t = gCamCombatState->followDistance * c;
                            n[0] = px + t;
                            t = gCamCombatState->followDistance * sn;
                            n[2] = pz - t;
                            dy = dy * lbl_803E1904;
                            dy = ty - dy;
                            dy = dy + gCamCombatState->heightOffset;
                            step = interpolate(((CameraObject*)cam)->anim.worldPosY - dy, lbl_803E1908, timeDelta);
                            n[1] = ((CameraObject*)cam)->anim.worldPosY - step;
                            PSVECSubtract(n, &((CameraObject*)cam)->anim.worldPosX, vec);
                            mag = PSVECMag(vec);
                            if (mag > lbl_803E18C4)
                            {
                                PSVECNormalize(vec, vec);
                            }
                            if (((CameraObject*)cam)->blendProgress <= lbl_803E18C4)
                            {
                                fa = focus->anim.previousWorldPosX - focus->anim.worldPosX;
                                fb = focus->anim.previousWorldPosZ - focus->anim.worldPosZ;
                                speed = sqrtf(fa * fa + fb * fb);
                                lim = speed * (lbl_803E190C * timeDelta);
                                if ((f64)lim < lbl_803E1918)
                                {
                                    lim = lbl_803E1910;
                                }
                                if (mag < lbl_803E18C4)
                                {
                                    mag = lbl_803E18C4;
                                }
                                else if (mag > lim)
                                {
                                    mag = lim;
                                }
                            }
                            PSVECScale(vec, vec,
                                       (mag < lbl_803E18C4)
                                           ? lbl_803E18C4
                                           : ((mag > lbl_803E18D0) ? lbl_803E18D0 : mag));
                            PSVECAdd(&((CameraObject*)cam)->anim.worldPosX, vec, &((CameraObject*)cam)->anim.worldPosX);
                            camcontrol_traceMove(&prevX, &((CameraObject*)cam)->anim.worldPosX,
                                                 &((CameraObject*)cam)->anim.worldPosX, trace, 3, 1, 1, lbl_803E18CC);
                            t = lbl_803E18F8 * dz + focus->anim.worldPosZ;
                            fb = *(f32*)(view + 0xc) - (lbl_803E18F8 * dx + focus->anim.worldPosX);
                            dy = *(f32*)(view + 0x10) - py;
                            fa = *(f32*)(view + 0x14) - t;
                            t = sqrtf(fb * fb + fa * fa);
                            ang = getAngle(dy, t) & 0xffff;
                            ad = ang - ((int)cam[1] & 0xffffU);
                            if ((int)ad > 0x8000)
                            {
                                ad = ad - 0xffff;
                            }
                            if ((int)ad < -0x8000)
                            {
                                ad = ad + 0xffff;
                            }
                            step = interpolate((f32)(s32)ad, lbl_803E1920, timeDelta);
                            cam[1] = (s16)
                            ((f32)(s32)
                            cam[1] + step
                            )
                            ;
                            fa = lbl_803E1924 + dist;
                            if (fa < lbl_803E1928)
                            {
                                fa = lbl_803E1928;
                            }
                            if (fa > lbl_803E192C)
                            {
                                fa = lbl_803E192C;
                            }
                            fa = fa - gCamCombatState->followDistance;
                            step = powfBitEstimate(lbl_803E18EC, timeDelta);
                            fa = fa * step;
                            if (fa > lbl_803E18D8 * timeDelta)
                            {
                                fa = lbl_803E18D8 * timeDelta;
                            }
                            else if (fa < lbl_803E1930 * timeDelta)
                            {
                                fa = lbl_803E1930 * timeDelta;
                            }
                            gCamCombatState->followDistance = gCamCombatState->followDistance + fa;
                            turnOnBlurFilter(tgt->anim.worldPosX, tgt->anim.worldPosY, tgt->anim.worldPosZ, 1, 0);
                            if (lbl_803E18C4 == ((CameraObject*)cam)->blendProgress)
                            {
                                ((struct { u8 b7 : 1; } *)&((CameraObject*)cam)->smoothingFlags)->b7 = 1;
                            }
                            Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX,
                                                           ((CameraObject*)cam)->anim.worldPosY,
                                                           ((CameraObject*)cam)->anim.worldPosZ,
                                                           &((CameraObject*)cam)->anim.localPosX,
                                                           &((CameraObject*)cam)->anim.localPosY,
                                                           &((CameraObject*)cam)->anim.localPosZ,
                                                           *(int*)&((CameraObject*)cam)->anim.parent);
                        }
                    }
                }
            }
        }
    }
}
#pragma opt_common_subs reset

void CameraModeCombat_init(CameraObject* camera, u32 arg2, GameObject** targetPtr)
{
    float dx;
    float dz;
    ObjHitVolumeRuntimeTransform* hitVolume;
    GameObject* target;
    GameObject* focus;

    camera->targetObj = *targetPtr;
    focus = (GameObject*)camera->anim.targetObj;
    if (gCamCombatState == (CameraModeCombatState*)0x0)
    {
        gCamCombatState = (CameraModeCombatState*)mmAlloc(0x1c, 0xf, 0);
    }
    dx = lbl_803E18C4;
    gCamCombatState->heightOffset = lbl_803E18C4;
    gCamCombatState->zoomOffset = lbl_803E18C0;
    gCamCombatState->invalidTarget = 0;
    gCamCombatState->unk11 = 0;
    gCamCombatState->pathBlendStartIndex = 1;
    gCamCombatState->pathBlendTargetIndex = 1;
    gCamCombatState->pathBlendWeight = dx;
    if (focus->anim.classId != 1)
    {
        gCamCombatState->invalidTarget = 1;
    }
    else
    {
        target = (GameObject*)camera->targetObj;
        if (target == NULL)
        {
            gCamCombatState->invalidTarget = 1;
        }
        else
        {
            if (target->anim.hitVolumeTransforms == NULL)
            {
                dx = focus->anim.worldPosX - target->anim.worldPosX;
                dz = focus->anim.worldPosZ - target->anim.worldPosZ;
            }
            else
            {
                hitVolume = &target->anim.hitVolumeTransforms[target->hitVolumeIndex];
                dx = hitVolume->centerX - focus->anim.worldPosX;
                dz = hitVolume->centerZ - focus->anim.worldPosZ;
            }
            if (target->anim.classId != 0x6d)
            {
                gCamCombatState->followDistance = sqrtf(dx * dx + dz * dz);
            }
            else
            {
                gCamCombatState->followDistance = lbl_803E1940;
            }
            gCamCombatState->unk10 = 0;
        }
    }
    return;
}


void CameraModeCombat_release(void)
{
}

void CameraModeCombat_initialise(void)
{
}

