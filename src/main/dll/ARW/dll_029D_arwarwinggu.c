#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int arwarwinggu_getExtraSize(int obj)
{
    switch (*(s16 *)(obj + 0x46)) {
    case 0x606:
        return 8;
    case 0x610:
    case 0x615:
        return 4;
    case 0x611:
        return 1;
    default:
        return 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwinggu_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_init(int obj)
{
    if (*(s16 *)(obj + 0x46) == 0x606) {
        return;
    }
    *(s16 *)(obj + 6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwinggu_setActiveVisible(int obj, u8 active, u8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (active != 0) {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        *(s16 *)(obj + 6) &= ~0x4000;
        *(u8 *)(obj + 0x36) = 0xff;
        *(f32 *)state = lbl_803E7058;
    } else {
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwinggu_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwinggu_update(int obj)
{
    switch (*(s16 *)(obj + 0x46)) {
    case 0x606: {
        int state = *(int *)(obj + 0xb8);
        int model = Obj_GetActiveModel(obj);
        int texture = (int)objFindTexture(obj, 0, 0);
        int anim = fn_800283E8(*(int *)model, 0);
        fn_800541A4(anim, (u16)*(int *)(state + 4));
        textureAnimFn_80053f2c(anim, state, texture);
        break;
    }
    case 0x610:
    case 0x615: {
        int state = *(int *)(obj + 0xb8);
        if (*(f32 *)state > lbl_803E7060) {
            *(f32 *)state -= timeDelta;
            if (*(f32 *)state <= lbl_803E7060) {
                *(f32 *)state = lbl_803E7060;
                *(u8 *)(obj + 0x36) = 0;
            }
        }
        break;
    }
    case 0x611: {
        int state = *(int *)(obj + 0xb8);
        f32 v;
        if (*(u8 *)state != 0) {
            v = lbl_803E705C * timeDelta + (f32)(u32)*(u8 *)(obj + 0x36);
        } else {
            v = (f32)(u32)*(u8 *)(obj + 0x36) - lbl_803E705C * timeDelta;
        }
        if (v < lbl_803E7060) {
            v = lbl_803E7060;
        } else if (v > lbl_803E705C) {
            v = lbl_803E705C;
        }
        *(u8 *)(obj + 0x36) = (int)v;
        break;
    }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022F270(int obj, int p2) { *(int *)(*(int *)(obj + 0xb8) + 0x4) = p2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void fn_8022F27C(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int model = Obj_GetActiveModel(obj);
    int *texture = objFindTexture(obj, 0, 0);
    int anim = fn_800283E8(*(int *)model, 0);
    fn_800541A4(anim, (u16)*(int *)(state + 4));
    textureAnimFn_80053f2c(anim, state, (int)texture);
}
#pragma scheduling reset
#pragma peephole reset
