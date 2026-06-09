#include "main/dll/CAM/camslide.h"
#include "main/game_object.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"

#pragma peephole off
#pragma scheduling off

extern uint getAngle();
extern void mtxRotateByVec3s(void *matrix, void *angles);
extern void Matrix_TransformPoint(void *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);
extern f64 interpolate(f64 value, f64 rate, f64 t);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 fn_802966F4(GameObject *obj);

extern u8 framesThisStep;
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16B8;
extern f32 lbl_803E16D8;
extern f32 lbl_803E16DC;
extern f32 lbl_803E16E0;
extern f32 lbl_803E16E4;
extern f32 lbl_803E16E8;
extern f32 lbl_803E16EC;
extern f32 lbl_803E16F0;
extern f32 lbl_803E16F4;
extern f32 timeDelta;

#define gCamcontrolModeSettings cameraMtxVar57

typedef struct CamSlideRot {
    s16 angles[4];
    f32 unkA4;
    f32 unkA0;
    f32 unk9C;
    f32 unk98;
} CamSlideRot;

typedef struct CamSlideObjectState {
    u8 pad00[0x1A4];
    f32 vectorX;
    f32 vectorY;
    f32 vectorZ;
} CamSlideObjectState;

STATIC_ASSERT(offsetof(CamSlideObjectState, vectorX) == 0x1A4);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorY) == 0x1A8);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorZ) == 0x1AC);

/*
 * --INFO--
 *
 * Function: camslide_update
 * EN v1.0 Address: 0x801049B0
 * EN v1.0 Size: 1552b
 * EN v1.1 Address: 0x80104C4C
 * EN v1.1 Size: 1552b
 */
void camslide_update(CameraObject *camera, GameObject *target)
{
    f32 fVar1;
    CamSlideObjectState *state;
    uint angle;
    int cur;
    f32 high;
    f32 low;
    f32 range;
    f32 slide;
    f64 approach;
    f32 mtx[16];
    CamSlideRot rot;
    f32 velX;
    f32 step;
    f32 velZ;
    f32 speed;
    f32 outX;
    f32 outY;
    f32 outZ;

    (*gCameraInterface)->getRelativePosition(gCamcontrolModeSettings->targetHeight, (int)camera, &velX,
                                             &step, &velZ, &speed, 0);
    speed = velZ * velZ + (velX * velX + step * step);
    if (speed > lbl_803E16AC) {
        speed = sqrtf(speed);
    }
    if (speed < lbl_803E1694) {
        speed = lbl_803E1694;
    }
    high = gCamcontrolModeSettings->upperHeightOffset +
        (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight);
    low = gCamcontrolModeSettings->lowerHeightOffset +
        (target->anim.worldPosY + gCamcontrolModeSettings->targetHeight);
    if (target->anim.classId == 1) {
        state = (CamSlideObjectState *)target->extra;
        angle = getAngle((f64)velX, (f64)velZ);
        rot.angles[0] = (s16)(0x8000 - angle);
        rot.angles[1] = 0;
        rot.angles[2] = 0;
        rot.unkA4 = lbl_803E16A4;
        rot.unkA0 = lbl_803E16AC;
        rot.unk9C = lbl_803E16AC;
        rot.unk98 = lbl_803E16AC;
        mtxRotateByVec3s(mtx, rot.angles);
        Matrix_TransformPoint(mtx, (f64)state->vectorX, (f64)state->vectorY,
                              (f64)state->vectorZ, &outX, &outY, &outZ);
        angle = getAngle((f64)outY, (f64)outZ);
        gCamcontrolModeSettings->slideAngle +=
            (int)(framesThisStep * ((0x4000 - (angle & 0xffff)) -
            gCamcontrolModeSettings->slideAngle)) >> 5;
    } else {
        gCamcontrolModeSettings->slideAngle -=
            (int)(gCamcontrolModeSettings->slideAngle * framesThisStep) >> 5;
    }
    cur = gCamcontrolModeSettings->slideAngle;
    if (cur < 0) {
        slide = gCamcontrolModeSettings->slideLeftAmount *
            mathSinf((lbl_803E168C * (f32)cur) / lbl_803E1690);
    } else if (cur > 0) {
        slide = gCamcontrolModeSettings->slideRightAmount *
            mathSinf((lbl_803E168C * (f32)cur) / lbl_803E1690);
    } else {
        slide = lbl_803E16AC;
    }
    low += slide;
    high += slide;
    range = gCamcontrolModeSettings->minDistance - lbl_803E16D8;
    if (range < lbl_803E16DC) {
        range = lbl_803E16DC;
    }
    if (target->anim.classId == 1) {
        if (fn_802966F4(target) <= lbl_803E16DC) {
            step = lbl_803E16E0 * gCamcontrolModeSettings->maxDistance -
                gCamcontrolModeSettings->lowerHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4) {
                step = lbl_803E16B4;
            }
            gCamcontrolModeSettings->lowerHeightOffset =
                gCamcontrolModeSettings->lowerHeightOffset + step;
            if (gCamcontrolModeSettings->lowerHeightOffset > gCamcontrolModeSettings->maxDistance) {
                gCamcontrolModeSettings->lowerHeightOffset = gCamcontrolModeSettings->maxDistance;
            }
            step = lbl_803E16E0 * gCamcontrolModeSettings->maxDistance -
                gCamcontrolModeSettings->upperHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4) {
                step = lbl_803E16B4;
            }
            gCamcontrolModeSettings->upperHeightOffset =
                gCamcontrolModeSettings->upperHeightOffset + step;
            if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->maxDistance) {
                gCamcontrolModeSettings->upperHeightOffset = gCamcontrolModeSettings->maxDistance;
            }
        } else {
            step = gCamcontrolModeSettings->baseLowerHeightOffset -
                gCamcontrolModeSettings->lowerHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16E8) {
                step = lbl_803E16E8;
            }
            if (step < lbl_803E16EC) {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings->lowerHeightOffset =
                gCamcontrolModeSettings->lowerHeightOffset + step;
            if (gCamcontrolModeSettings->lowerHeightOffset <
                gCamcontrolModeSettings->baseLowerHeightOffset) {
                gCamcontrolModeSettings->lowerHeightOffset =
                    gCamcontrolModeSettings->baseLowerHeightOffset;
            }
            step = gCamcontrolModeSettings->baseUpperHeightOffset -
                gCamcontrolModeSettings->upperHeightOffset;
            step *= lbl_803E16E4;
            if (step > lbl_803E16E8) {
                step = lbl_803E16E8;
            }
            if (step < lbl_803E16EC) {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings->upperHeightOffset =
                gCamcontrolModeSettings->upperHeightOffset + step;
            if (gCamcontrolModeSettings->upperHeightOffset <
                gCamcontrolModeSettings->baseUpperHeightOffset) {
                gCamcontrolModeSettings->upperHeightOffset =
                    gCamcontrolModeSettings->baseUpperHeightOffset;
            }
            if (speed > lbl_803E16DC) {
                if (speed <= range) {
                    if (range - lbl_803E16DC > lbl_803E16AC) {
                        speed = (speed - lbl_803E16DC) / (range - lbl_803E16DC);
                    }
                    if (speed < lbl_803E16AC) {
                        speed = lbl_803E16AC;
                    } else if (speed > lbl_803E16A4) {
                        speed = lbl_803E16A4;
                    }
                    fVar1 = lbl_803E16F0 + target->anim.worldPosY;
                    low = speed * ((gCamcontrolModeSettings->targetHeight +
                        gCamcontrolModeSettings->lowerHeightOffset) - lbl_803E16F0) + fVar1;
                    high = speed * ((gCamcontrolModeSettings->targetHeight +
                        gCamcontrolModeSettings->upperHeightOffset) - lbl_803E16F0) + fVar1;
                }
            } else {
                high = lbl_803E16E0 * (lbl_803E16DC - speed) + (lbl_803E16F0 + target->anim.worldPosY);
                low = high;
            }
        }
    }
    if (camera->anim.worldPosY < low) {
        step = low - camera->anim.worldPosY;
    } else if (camera->anim.worldPosY > high) {
        step = high - camera->anim.worldPosY;
    } else {
        step = lbl_803E16AC;
    }
    approach = interpolate((f64)step, (f64)gCamcontrolModeSettings->heightAdjustRate,
                           (f64)timeDelta);
    step = approach;
    if ((f32)approach > lbl_803E16E8 && (f32)approach < lbl_803E16F4) {
        step = lbl_803E16AC;
    }
    camera->anim.worldPosY = camera->anim.worldPosY + step;
    if (camera->anim.worldPosY > lbl_803E16B8 + high) {
        camera->anim.worldPosY = lbl_803E16B8 + high;
    }
    if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->baseUpperHeightOffset) {
        if (gCamcontrolModeSettings->clampFlags.b6 &&
            camera->anim.worldPosY > gCamcontrolModeSettings->heightLockLimit) {
            camera->anim.worldPosY = gCamcontrolModeSettings->heightLockLimit;
        }
        if (target->anim.velocityY > lbl_803E16AC) {
            gCamcontrolModeSettings->clampFlags.b6 = 0;
        }
    } else {
        gCamcontrolModeSettings->clampFlags.b6 = 0;
    }
}

/*
 * --INFO--
 *
 * Function: firstperson_updatePitch
 * EN v1.0 Address: 0x80104FC0
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x8010525C
 * EN v1.1 Size: 220b
 */
void firstperson_updatePitch(f32 targetY, CameraObject *camera)
{
    int v;
    f64 d;

    v = (getAngle((f64)(camera->anim.worldPosY -
        (targetY + gCamcontrolModeSettings->targetHeight))) & 0xffff) -
        ((uint)camera->anim.rotY & 0xffff);
    if (v > 0x8000) {
        v -= 0xffff;
    }
    if (v < -0x8000) {
        v += 0xffff;
    }
    d = interpolate((f64)(f32)v,
                    (f64)(lbl_803E16A4 / (f32)gCamcontrolModeSettings->yawResponseFrames),
                    (f64)timeDelta);
    camera->anim.rotY = (s16)((int)d + camera->anim.rotY);
}
