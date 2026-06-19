/* DLL 0x0049 (cameramodecombat) — Camera mode combat handlers [0x8010BF08-0x8010CEC0). */
#include "main/camera_interface.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/dll/CAM/cutCam.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
extern CameraModeCombatState* lbl_803DD568;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;
extern f32 timeDelta;
extern u32 Camera_GetCurrentViewSlot();
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern u32 fn_8029630C(int obj);
extern int objAnimFn_80296328(int obj);
extern u32 cameraGetPrevPos2();
extern s32 lbl_803DD56C;
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
extern f32 lbl_803E18FC;
extern f32 lbl_803E1900;
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
    curIdx = target->unkE4;
    if ((u32)curIdx != lbl_803DD568->pathBlendTargetIndex)
    {
        lbl_803DD568->pathBlendStartIndex = lbl_803DD568->pathBlendTargetIndex;
        lbl_803DD568->pathBlendWeight = lbl_803E18C0;
    }
    t = lbl_803DD568->pathBlendWeight;
    lim = lbl_803E18C4;
    if (t > lim)
    {
        lbl_803DD568->pathBlendWeight = t - lbl_803E18C8 * timeDelta;
        t = lbl_803DD568->pathBlendWeight;
        if (lbl_803DD568->pathBlendWeight < lim)
        {
            lbl_803DD568->pathBlendWeight = lim;
            lbl_803DD568->pathBlendStartIndex = target->unkE4;
        }
        {
            u8 ci = lbl_803DD568->pathBlendStartIndex;
            u8 ti = target->unkE4;
            float dx = hitVolumes[ci].centerX - hitVolumes[ti].centerX;
            float dy = hitVolumes[ci].centerY - hitVolumes[ti].centerY;
            float dz = hitVolumes[ci].centerZ - hitVolumes[ti].centerZ;
            float w = lbl_803DD568->pathBlendWeight;
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
        *outX = hitVolumes[target->unkE4].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->unkE4].centerY - *targetY;
        *outZ = hitVolumes[target->unkE4].centerZ - focus->anim.worldPosZ;
    }
    lbl_803DD568->pathBlendTargetIndex = target->unkE4;
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
    mm_free(lbl_803DD568);
    lbl_803DD568 = 0;
    Rcp_DisableBlurFilter();
    ((CameraModeCombatFlags*)&camera->smoothingFlags)->b0 = 0;
}

void CameraModeCombat_update(short* cam)
{
    extern void fn_8010BF08(CameraObject* camera, f32* dx, f32* dy, f32* dz, f32* ty); /* #57 */
    f32 n[3];
    f32 prevZ;
    f32 prevY;
    f32 prevX;
    f32 dy;
    f32 ty;
    f32 dx;
    f32 dz;
    f32 vec[3];
    u8 trace[116];
    int view = Camera_GetCurrentViewSlot();
    GameObject* tgt;
    GameObject* focus;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    f32 range;
    f32 dist;
    f32 px;
    f32 py;
    f32 pz;
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
    int abs2;
    u32 ad;
    short classId;

    if (lbl_803DD568->invalidTarget != 0)
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
            if (tgt == NULL || (tgt->objectFlags & 0x40) || (*(u8*)&tgt->anim.resetHitboxMode & 0x28))
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
                    if (((u16)getButtonsJustPressed(0) & 0x200) && (int)fn_8029630C((int)focus) != 0)
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
                                dx = hitVolumes[tgt->unkE4].centerX - focus->anim.worldPosX;
                                dy = hitVolumes[tgt->unkE4].centerY - ty;
                                dz = hitVolumes[tgt->unkE4].centerZ - focus->anim.worldPosZ;
                            }
                        }
                        else
                        {
                            ty = lbl_803E18D0 + focus->anim.worldPosY;
                            dx = hitVolumes[tgt->unkE4].centerX - focus->anim.worldPosX;
                            dy = hitVolumes[tgt->unkE4].centerY - ty;
                            dz = hitVolumes[tgt->unkE4].centerZ - focus->anim.worldPosZ;
                        }
                        dist = sqrtf(dx * dx + dz * dz);
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
                                if (lbl_803DD56C < 3000 && diff < 1000 && diff < lbl_803DD56C)
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
                                if (lbl_803DD56C < -2999 || diff < -999 || diff <= lbl_803DD56C)
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
                            abs2 = diff;
                            if (diff < 0)
                            {
                                abs2 = -diff;
                            }
                            if (abs2 > 9000)
                            {
                                abs2 = 9000;
                            }
                            zoom = (f32)(s32)(9000 - abs2) / lbl_803E18E4;
                            lbl_803DD56C = diff;
                            step = interpolate(lbl_803E18E8 - lbl_803DD568->heightOffset, lbl_803E18EC, timeDelta);
                            lbl_803DD568->heightOffset = lbl_803DD568->heightOffset + step;
                            step = interpolate(
                                (lbl_803E18F0 + (lbl_803E18C0 - zoom)) / lbl_803E18F4 - lbl_803DD568->zoomOffset,
                                lbl_803E18F8, timeDelta);
                            lbl_803DD568->zoomOffset = lbl_803DD568->zoomOffset + step;
                            c = mathSinf((lbl_803E18FC * (f32)(s32) * cam) / lbl_803E1900);
                            sn = mathCosf((lbl_803E18FC * (f32)(s32) * cam) / lbl_803E1900);
                            t = lbl_803DD568->followDistance * c;
                            n[0] = px + t;
                            t = lbl_803DD568->followDistance * sn;
                            n[2] = pz - t;
                            dy = dy * lbl_803E1904;
                            dy = ty - dy;
                            dy = dy + lbl_803DD568->heightOffset;
                            step = interpolate(((CameraObject*)cam)->anim.worldPosY - dy, lbl_803E1908, timeDelta);
                            n[1] = ((CameraObject*)cam)->anim.worldPosY - step;
                            PSVECSubtract(n, (f32*)((char*)cam + 0x18), vec);
                            mag = PSVECMag(vec);
                            if (lbl_803E18C4 < mag)
                            {
                                PSVECNormalize(vec, vec);
                            }
                            speed = mag;
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
                                speed = mag;
                                if (mag < lbl_803E18C4)
                                {
                                    speed = lbl_803E18C4;
                                }
                                else if (mag > lim)
                                {
                                    speed = lim;
                                }
                            }
                            if (speed < lbl_803E18C4)
                            {
                                speed = lbl_803E18C4;
                            }
                            else if (speed > lbl_803E18D0)
                            {
                                speed = lbl_803E18D0;
                            }
                            PSVECScale(vec, vec, speed);
                            PSVECAdd((f32*)((char*)cam + 0x18), vec, (f32*)((char*)cam + 0x18));
                            camcontrol_traceMove(&prevX, (f32*)((char*)cam + 0x18),
                                                 (f32*)((char*)cam + 0x18), trace, 3, 1, 1, lbl_803E18CC);
                            fb = *(f32*)(view + 0xc) - (lbl_803E18F8 * dx + focus->anim.worldPosX);
                            dy = *(f32*)(view + 0x10) - py;
                            fa = *(f32*)(view + 0x14) - (lbl_803E18F8 * dz + focus->anim.worldPosZ);
                            t = sqrtf(fb * fb + fa * fa);
                            ad = getAngle(dy, t);
                            ad = (ad & 0xffff) - ((int)cam[1] & 0xffffU);
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
                            if (lbl_803E1924 + dist < lbl_803E1928)
                            {
                                fa = lbl_803E1928;
                            }
                            if (lbl_803E192C < fa)
                            {
                                fa = lbl_803E192C;
                            }
                            t = fa - lbl_803DD568->followDistance;
                            step = powfBitEstimate(lbl_803E18EC, timeDelta);
                            fa = t * step;
                            if (fa > lbl_803E18D8 * timeDelta)
                            {
                                fa = lbl_803E18D8 * timeDelta;
                            }
                            else if (fa < lbl_803E1930 * timeDelta)
                            {
                                fa = lbl_803E1930 * timeDelta;
                            }
                            lbl_803DD568->followDistance = lbl_803DD568->followDistance + fa;
                            turnOnBlurFilter(tgt->anim.worldPosX, tgt->anim.worldPosY, tgt->anim.worldPosZ, 1, 0);
                            if (lbl_803E18C4 == ((CameraObject*)cam)->blendProgress)
                            {
                                ((CameraObject*)cam)->smoothingFlags |= 0x80;
                            }
                            Obj_TransformWorldPointToLocal(*(f32*)((char*)cam + 0x18),
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

void CameraModeCombat_init(CameraObject* camera, u32 arg2, GameObject** targetPtr)
{
    float dx;
    float dz;
    ObjHitVolumeRuntimeTransform* hitVolume;
    GameObject* target;
    GameObject* focus;

    camera->targetObj = *targetPtr;
    focus = (GameObject*)camera->anim.targetObj;
    if (lbl_803DD568 == (CameraModeCombatState*)0x0)
    {
        lbl_803DD568 = (CameraModeCombatState*)mmAlloc(0x1c, 0xf, 0);
    }
    dx = lbl_803E18C4;
    lbl_803DD568->heightOffset = lbl_803E18C4;
    lbl_803DD568->zoomOffset = lbl_803E18C0;
    lbl_803DD568->invalidTarget = 0;
    lbl_803DD568->unk11 = 0;
    lbl_803DD568->pathBlendStartIndex = 1;
    lbl_803DD568->pathBlendTargetIndex = 1;
    lbl_803DD568->pathBlendWeight = dx;
    if (focus->anim.classId != 1)
    {
        lbl_803DD568->invalidTarget = 1;
    }
    else
    {
        target = (GameObject*)camera->targetObj;
        if (target == NULL)
        {
            lbl_803DD568->invalidTarget = 1;
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
                hitVolume = &target->anim.hitVolumeTransforms[target->unkE4];
                dx = hitVolume->centerX - focus->anim.worldPosX;
                dz = hitVolume->centerZ - focus->anim.worldPosZ;
            }
            if (target->anim.classId != 0x6d)
            {
                lbl_803DD568->followDistance = sqrtf(dx * dx + dz * dz);
            }
            else
            {
                lbl_803DD568->followDistance = lbl_803E1940;
            }
            lbl_803DD568->unk10 = 0;
        }
    }
    return;
}

void CameraModeShipBattle_update(short* cam);

void CameraModeCombat_release(void)
{
}

void CameraModeCombat_initialise(void)
{
}

void CameraModeShipBattle_copyToCurrent_nop(void);
