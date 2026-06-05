#include "main/dll/dll_80220608_shared.h"

extern f32 lbl_803E72B4;
extern f32 lbl_803E72B8;
extern f32 lbl_803E72BC;
extern f32 lbl_803E72C0;
extern f32 lbl_803E72C4;
extern f32 lbl_803E72C8;
extern f32 lbl_803E72CC;
extern f32 lbl_803E72D0;
extern f32 lbl_803E72D4;

#pragma peephole off
#pragma scheduling off
void waterflowwe_calcCurrentVector(int obj, f32 *vx, f32 *vz)
{
    int count;
    int i;
    int anyCurrent;
    int *objects;
    int other;
    f32 *current;
    f32 currentX;
    f32 currentZ;
    f32 dx;
    f32 dz;
    f32 dy;
    f32 distance;
    f32 radius;
    f32 strength;
    f32 angle;

    current = *(f32 **)(obj + 0xb8);
    currentX = lbl_803E72B0;
    currentZ = lbl_803E72B0;
    objects = ObjGroup_GetObjects(0x14, &count);
    anyCurrent = 0;
    for (i = 0; i < count; i++) {
        other = objects[i];
        if (((*(u8 **)(other + 0x4c))[0x1a] & 2) != 0) {
            anyCurrent = 1;
            dy = *(f32 *)(other + 0x10) - *(f32 *)(obj + 0x10);
            if ((dy <= lbl_803E72B4) && (dy >= lbl_803E72B8)) {
                dx = *(f32 *)(other + 0xc) - *(f32 *)(obj + 0xc);
                dz = *(f32 *)(other + 0x14) - *(f32 *)(obj + 0x14);
                distance = sqrtf(dx * dx + dz * dz);
                radius = lbl_803E72BC * (f32)(u32)(*(u8 **)(other + 0x4c))[0x19];
                if (distance < radius) {
                    strength = ((radius - distance) / radius) * (lbl_803E72C0 * *(f32 *)(other + 8));
                    currentX += strength * fn_80293E80((lbl_803E72C4 * (f32)*(s16 *)other) / lbl_803E72C8);
                    currentZ += strength * sin((lbl_803E72C4 * (f32)*(s16 *)other) / lbl_803E72C8);
                }
            }
        }
    }

    objects = ObjGroup_GetObjects(0x50, &count);
    {
        f32 strengthDiv = lbl_803E72C0;
        f32 dyMax = lbl_803E72B4;
    for (i = 0; i < count; i++) {
        f32 objectStrength;
        s16 currentAngle;

        other = objects[i];
        objectStrength = (f32)(u32)(*(u8 **)(other + 0x4c))[0x32] / strengthDiv;
        anyCurrent = 1;
        dy = *(f32 *)(other + 0x10) - *(f32 *)(obj + 0x10);
        if ((dy <= dyMax) && (dy >= lbl_803E72B8)) {
            dx = *(f32 *)(other + 0xc) - *(f32 *)(obj + 0xc);
            dz = *(f32 *)(other + 0x14) - *(f32 *)(obj + 0x14);
            currentAngle = (s16)(getAngle(dx, dz) + 0x84d0);
            distance = sqrtf(dx * dx + dz * dz);
            radius = (f32)(s32)((*(u8 **)(other + 0x4c))[0x29] << 3);
            if (distance < radius) {
                strength = ((radius - distance) / radius) * objectStrength;
                angle = (lbl_803E72C4 * (f32)currentAngle) / lbl_803E72C8;
                currentX += strength * fn_80293E80(angle);
                currentZ += strength * sin(angle);
            }
        }
    }

    }

    if (anyCurrent != 0) {
        currentX = currentX / (f32)anyCurrent;
        currentZ = currentZ / (f32)anyCurrent;
        {
            f32 k = lbl_803E72CC;
            current[0] = current[0] - k * currentX;
            current[1] = current[1] - k * currentZ;
        }
        {
            f32 k = lbl_803E72D0;
            current[0] = current[0] * k;
            current[1] = current[1] * k;
        }
        distance = sqrtf(current[0] * current[0] + current[1] * current[1]);
        if (distance > lbl_803E72D4) {
            strength = lbl_803E72D4 / distance;
            current[0] = current[0] * strength;
            current[1] = current[1] * strength;
        }
        *vx = current[0] * timeDelta;
        *vz = current[1] * timeDelta;
    } else {
        f32 z = lbl_803E72B0;
        *vx = z;
        *vz = z;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int waterflowwe_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int waterflowwe_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void waterflowwe_init(int obj, u8 *setup)
{
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    if (setup[0x1b] != 0) {
        *(f32 *)(obj + 8) = (f32)(u32)setup[0x1b] / lbl_803E72F4;
        if (*(f32 *)(obj + 8) == lbl_803E72B0) {
            *(f32 *)(obj + 8) = lbl_803E72E8;
        }
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    }
    *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x2000;
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72B0, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void waterflowwe_free(int obj)
{
    if ((u32)obj == (u32)lbl_803DDDA8) {
        lbl_803DDDA8 = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void waterflowwe_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E72E8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void waterflowwe_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void waterflowwe_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    f32 vx, vz;

    waterflowwe_calcCurrentVector(obj, &vx, &vz);
    *(s16 *)obj = (s16)(getAngle(vx, vz) + 0x4000);
    if ((u32)lbl_803DDDA8 == 0 && *(u8 *)(setup + 0x1f) == 0) {
        lbl_803DDDA8 = obj;
    }
    if ((u32)obj == (u32)lbl_803DDDA8) {
        f32 a;

        lbl_803DDDB0 = lbl_803E72EC * timeDelta + lbl_803DDDB0;
        a = lbl_803DDDB0;
        while (a > lbl_803E72E8) {
            a -= lbl_803E72E8;
        }
        lbl_803DDDB0 = a;
        lbl_803DDDAC = lbl_803E72F0 * timeDelta + lbl_803DDDAC;
        a = lbl_803DDDAC;
        while (a > lbl_803E72E8) {
            a -= lbl_803E72E8;
        }
        lbl_803DDDAC = a;
    }
    if (lbl_803E72B0 == vx && lbl_803E72B0 == vz) {
        ObjAnim_SetCurrentMove(obj, 1, lbl_803DDDB0, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDDB0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void waterflowwe_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void waterflowwe_initialise(void)
{
    lbl_803DDDA8 = 0;
    lbl_803DDDB0 = lbl_803E72B0;
    lbl_803DDDAC = lbl_803E72B0;
}
#pragma scheduling reset
#pragma peephole reset
