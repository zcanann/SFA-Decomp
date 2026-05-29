#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int wcbouncycra_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcbouncycra_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcbouncycra_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D38);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbouncycra_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if ((*(u8 *)(state + 0xa) & 1) == 0) {
        int n = (int)((f32)*(s16 *)(state + 8) - timeDelta);
        *(s16 *)(state + 8) = n;
        if ((s16)n <= 0) {
            f32 v = lbl_803E6D20;
            f32 dist;

            if ((void *)ObjGroup_FindNearestObject(3, obj, &v) == NULL) {
                dist = lbl_803E6D24;
            } else if (v < lbl_803E6D28) {
                dist = lbl_803E6D2C;
            } else if (v > lbl_803E6D30) {
                dist = lbl_803E6D24;
            } else {
                dist = (lbl_803E6D38 - (v - lbl_803E6D28) / lbl_803E6D34) * lbl_803E6D2C;
            }
            *(f32 *)(obj + 0x28) = dist;
            *(u8 *)(state + 0xa) |= 1;
            *(u8 *)(state + 0xb) = 0;
        }
    } else {
        *(f32 *)(obj + 0x28) = lbl_803E6D3C * timeDelta + *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) <= *(f32 *)(state + 0)) {
            *(f32 *)(obj + 0x10) =
                *(f32 *)(obj + 0x10) + (*(f32 *)(state + 0) - *(f32 *)(obj + 0x10));
            *(f32 *)(obj + 0x28) = lbl_803E6D40 * -*(f32 *)(obj + 0x28);
            *(u8 *)(state + 0xb) += 1;
            if (*(u8 *)(state + 0xb) > 0xa) {
                *(u8 *)(state + 0xa) &= ~1;
                *(s16 *)(state + 8) = 0x28;
                *(f32 *)(obj + 0x10) = *(f32 *)(state + 0);
                *(f32 *)(obj + 0x28) = lbl_803E6D24;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcbouncycra_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)state = *(f32 *)(setup + 0xc);
    *(s16 *)(state + 8) = 0x28;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_802242A8(int p1, int p2, int p3)
{
    f32 cy;
    f32 cx;
    int result;

    if ((s8)*(u8 *)(p1 + 0xad) == 1) {
        (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x30))(
            *(u8 *)(p2 + 0x283), p2 + 0x27e, p2 + 0x280,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
        (*(void (**)(int, int, int, f32 *, f32 *, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x20))(
            p1, *(s16 *)(p2 + 0x27e), *(s16 *)(p2 + 0x280), &cy, &cx,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
    } else {
        (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x4c))(
            *(u8 *)(p2 + 0x283), p2 + 0x27e, p2 + 0x280,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
        (*(void (**)(int, int, int, f32 *, f32 *, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x3c))(
            p1, *(s16 *)(p2 + 0x27e), *(s16 *)(p2 + 0x280), &cy, &cx,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
    }
    if (*(f32 *)(p3 + 0xc) > cy + lbl_803E6D50 || *(f32 *)(p3 + 0xc) < cy - lbl_803E6D50)
        result = 1;
    else if (*(f32 *)(p3 + 0x14) > cx + lbl_803E6D50 || *(f32 *)(p3 + 0x14) < cx - lbl_803E6D50)
        result = 1;
    else
        result = 0;
    return result;
}
#pragma scheduling reset
#pragma peephole reset
