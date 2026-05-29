#include "main/dll/dll_80220608_shared.h"

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

#pragma peephole on
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
    *(u16 *)(obj + 0xb0) |= 0x2000;
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

#pragma peephole on
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
