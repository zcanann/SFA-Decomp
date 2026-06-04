#include "ghidra_import.h"
#include "main/dll/CAM/camslide.h"

#pragma peephole off
#pragma scheduling off

extern uint getAngle();
extern void mtxRotateByVec3s(void *matrix, void *angles);
extern void Matrix_TransformPoint(void *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);
extern f64 interpolate(f64 value, f64 rate, f64 t);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern f32 fn_802966F4(int obj);

extern u8 framesThisStep;
extern int *gCameraInterface;
extern f32 *cameraMtxVar57;
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

typedef struct CamSlideFlags {
    u8 unk80 : 1;
    u8 heightLock : 1;
    u8 rest : 6;
} CamSlideFlags;

typedef void (*CamSlideQueryFn)(int obj, f32 *outX, f32 *outY, f32 *outZ, f32 *outSpeed, f32 range, int arg);

/*
 * --INFO--
 *
 * Function: camslide_update
 * EN v1.0 Address: 0x801049B0
 * EN v1.0 Size: 1552b
 * EN v1.1 Address: 0x80104C4C
 * EN v1.1 Size: 1552b
 */
void camslide_update(int param_1, int param_2)
{
    f32 fVar1;
    int obj;
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

    (*(CamSlideQueryFn)*(void **)(*gCameraInterface + 0x38))(param_1, &velX, &step, &velZ, &speed, gCamcontrolModeSettings[0x23], 0);
    speed = velZ * velZ + (velX * velX + step * step);
    if (speed > lbl_803E16AC) {
        speed = sqrtf(speed);
    }
    if (speed < lbl_803E1694) {
        speed = lbl_803E1694;
    }
    high = gCamcontrolModeSettings[3] + (*(f32 *)(param_2 + 0x1c) + gCamcontrolModeSettings[0x23]);
    low = gCamcontrolModeSettings[2] + (*(f32 *)(param_2 + 0x1c) + gCamcontrolModeSettings[0x23]);
    if (*(s16 *)(param_2 + 0x44) == 1) {
        obj = *(int *)(param_2 + 0xb8);
        angle = getAngle((f64)velX, (f64)velZ);
        rot.angles[0] = (s16)(0x8000 - angle);
        rot.angles[1] = 0;
        rot.angles[2] = 0;
        rot.unkA4 = lbl_803E16A4;
        rot.unkA0 = lbl_803E16AC;
        rot.unk9C = lbl_803E16AC;
        rot.unk98 = lbl_803E16AC;
        mtxRotateByVec3s(mtx, rot.angles);
        Matrix_TransformPoint(mtx, (f64)*(f32 *)(obj + 0x1a4), (f64)*(f32 *)(obj + 0x1a8),
                              (f64)*(f32 *)(obj + 0x1ac), &outX, &outY, &outZ);
        angle = getAngle((f64)outY, (f64)outZ);
        *(s32 *)(gCamcontrolModeSettings + 0x2b) +=
            (int)(framesThisStep * ((0x4000 - (angle & 0xffff)) - *(s32 *)(gCamcontrolModeSettings + 0x2b))) >> 5;
    } else {
        *(s32 *)(gCamcontrolModeSettings + 0x2b) -=
            (int)(*(s32 *)(gCamcontrolModeSettings + 0x2b) * framesThisStep) >> 5;
    }
    cur = *(s32 *)(gCamcontrolModeSettings + 0x2b);
    if (cur < 0) {
        slide = gCamcontrolModeSettings[7] * fn_80293E80((lbl_803E168C * (f32)cur) / lbl_803E1690);
    } else if (cur > 0) {
        slide = gCamcontrolModeSettings[6] * fn_80293E80((lbl_803E168C * (f32)cur) / lbl_803E1690);
    } else {
        slide = lbl_803E16AC;
    }
    low += slide;
    high += slide;
    range = *gCamcontrolModeSettings - lbl_803E16D8;
    if (range < lbl_803E16DC) {
        range = lbl_803E16DC;
    }
    if (*(s16 *)(param_2 + 0x44) == 1) {
        if (fn_802966F4(param_2) <= lbl_803E16DC) {
            step = lbl_803E16E0 * gCamcontrolModeSettings[1] - gCamcontrolModeSettings[2];
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4) {
                step = lbl_803E16B4;
            }
            gCamcontrolModeSettings[2] = gCamcontrolModeSettings[2] + step;
            if (gCamcontrolModeSettings[2] > gCamcontrolModeSettings[1]) {
                gCamcontrolModeSettings[2] = gCamcontrolModeSettings[1];
            }
            step = lbl_803E16E0 * gCamcontrolModeSettings[1] - gCamcontrolModeSettings[3];
            step *= lbl_803E16E4;
            if (step > lbl_803E16B4) {
                step = lbl_803E16B4;
            }
            gCamcontrolModeSettings[3] = gCamcontrolModeSettings[3] + step;
            if (gCamcontrolModeSettings[3] > gCamcontrolModeSettings[1]) {
                gCamcontrolModeSettings[3] = gCamcontrolModeSettings[1];
            }
        } else {
            step = gCamcontrolModeSettings[0x26] - gCamcontrolModeSettings[2];
            step *= lbl_803E16E4;
            if (step > lbl_803E16E8) {
                step = lbl_803E16E8;
            }
            if (step < lbl_803E16EC) {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings[2] = gCamcontrolModeSettings[2] + step;
            if (gCamcontrolModeSettings[2] < gCamcontrolModeSettings[0x26]) {
                gCamcontrolModeSettings[2] = gCamcontrolModeSettings[0x26];
            }
            step = gCamcontrolModeSettings[0x27] - gCamcontrolModeSettings[3];
            step *= lbl_803E16E4;
            if (step > lbl_803E16E8) {
                step = lbl_803E16E8;
            }
            if (step < lbl_803E16EC) {
                step = lbl_803E16EC;
            }
            gCamcontrolModeSettings[3] = gCamcontrolModeSettings[3] + step;
            if (gCamcontrolModeSettings[3] < gCamcontrolModeSettings[0x27]) {
                gCamcontrolModeSettings[3] = gCamcontrolModeSettings[0x27];
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
                    fVar1 = lbl_803E16F0 + *(f32 *)(param_2 + 0x1c);
                    low = speed * ((gCamcontrolModeSettings[0x23] + gCamcontrolModeSettings[2]) - lbl_803E16F0) + fVar1;
                    high = speed * ((gCamcontrolModeSettings[0x23] + gCamcontrolModeSettings[3]) - lbl_803E16F0) + fVar1;
                }
            } else {
                high = lbl_803E16E0 * (lbl_803E16DC - speed) + (lbl_803E16F0 + *(f32 *)(param_2 + 0x1c));
                low = high;
            }
        }
    }
    if (*(f32 *)(param_1 + 0x1c) < low) {
        step = low - *(f32 *)(param_1 + 0x1c);
    } else if (*(f32 *)(param_1 + 0x1c) > high) {
        step = high - *(f32 *)(param_1 + 0x1c);
    } else {
        step = lbl_803E16AC;
    }
    approach = interpolate((f64)step, (f64)gCamcontrolModeSettings[5], (f64)timeDelta);
    step = approach;
    if ((f32)approach > lbl_803E16E8 && (f32)approach < lbl_803E16F4) {
        step = lbl_803E16AC;
    }
    *(f32 *)(param_1 + 0x1c) = *(f32 *)(param_1 + 0x1c) + step;
    if (*(f32 *)(param_1 + 0x1c) > lbl_803E16B8 + high) {
        *(f32 *)(param_1 + 0x1c) = lbl_803E16B8 + high;
    }
    if (gCamcontrolModeSettings[3] > gCamcontrolModeSettings[0x27]) {
        if (((CamSlideFlags *)(gCamcontrolModeSettings + 0x32))->heightLock &&
            *(f32 *)(param_1 + 0x1c) > gCamcontrolModeSettings[0x2f]) {
            *(f32 *)(param_1 + 0x1c) = gCamcontrolModeSettings[0x2f];
        }
        if (*(f32 *)(param_2 + 0x28) > lbl_803E16AC) {
            ((CamSlideFlags *)(gCamcontrolModeSettings + 0x32))->heightLock = 0;
        }
    } else {
        ((CamSlideFlags *)(gCamcontrolModeSettings + 0x32))->heightLock = 0;
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
void firstperson_updatePitch(f32 param_1, int param_2)
{
    int v;
    f64 d;

    v = (getAngle((f64)(*(f32 *)(param_2 + 0x1c) - (param_1 + gCamcontrolModeSettings[0x23]))) & 0xffff) -
        ((uint)*(s16 *)(param_2 + 2) & 0xffff);
    if (v > 0x8000) {
        v -= 0xffff;
    }
    if (v < -0x8000) {
        v += 0xffff;
    }
    d = interpolate((f64)(f32)v,
                    (f64)(lbl_803E16A4 / (f32)*((u8 *)gCamcontrolModeSettings + 0xc2)),
                    (f64)timeDelta);
    *(s16 *)(param_2 + 2) = (s16)(*(s16 *)(param_2 + 2) + (int)d);
}
