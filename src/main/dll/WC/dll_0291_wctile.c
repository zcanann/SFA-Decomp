#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int wctile_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wctile_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DF0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctile_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);

    *(f32 *)(obj + 0x10) = lbl_803E6DFC + *(f32 *)(setup + 0xc);
    obj[0xad] = setup[0x19];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    *(s16 *)(state + 8) = *(s16 *)(setup + 0x1a);
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel((int)obj), fn_800284CC);
    obj[0x36] = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctile_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctile_update(int obj)
{
    f32 nearest = lbl_803E6DF4;
    int state = *(int *)(obj + 0xb8);

    if (*(void **)(state + 0) == NULL) {
        *(int *)(state + 0) = ObjGroup_FindNearestObject(9, obj, &nearest);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    *(s16 *)(obj + 0) += (int)(lbl_803E6DF8 * timeDelta);
    if (*(s16 *)(state + 0xa) != 5) {
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if ((u32)GameBit_Get(0x812) != 0)
                *(s16 *)(state + 0xa) = 5;
            else if ((u32)GameBit_Get(0x808) != 0)
                *(s16 *)(state + 0xa) = 3;
        } else {
            if ((u32)GameBit_Get(0x813) != 0)
                *(s16 *)(state + 0xa) = 5;
            else if ((u32)GameBit_Get(0x809) != 0)
                *(s16 *)(state + 0xa) = 3;
        }
    }
    switch (*(s16 *)(state + 0xa)) {
    case 0:
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x30))(
                *(s16 *)(state + 8), state + 4, state + 6,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x20))(
                obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
        } else {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x4c))(
                *(s16 *)(state + 8), state + 4, state + 6,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x3c))(
                obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
        }
        *(u8 *)(obj + 0x36) = 0xff;
        *(s16 *)(state + 0xa) = 1;
        break;
    case 2:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case 5:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case 3:
        {
            int v = *(u8 *)(obj + 0x36) - framesThisStep * 8;
            if (v < 0)
                v = 0;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x30))(
                    *(s16 *)(state + 8), state + 4, state + 6,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
                (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x20))(
                    obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            } else {
                (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x4c))(
                    *(s16 *)(state + 8), state + 4, state + 6,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
                (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x3c))(
                    obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            }
            *(s16 *)(state + 0xa) = 4;
        }
        break;
    case 4:
        {
            int v = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (v > 0xff)
                v = 0xff;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) >= 0xff)
            *(s16 *)(state + 0xa) = 1;
        break;
    case 1:
    default:
        {
            int v = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (v > 0xff)
                v = 0xff;
            *(u8 *)(obj + 0x36) = v;
        }
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if (*(s16 *)(state + 8) !=
                (u8)(*(int (**)(int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x2c))(
                    *(s16 *)(state + 4), *(s16 *)(state + 6),
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68))))
                *(s16 *)(state + 0xa) = 2;
        } else {
            if (*(s16 *)(state + 8) !=
                (u8)(*(int (**)(int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x48))(
                    *(s16 *)(state + 4), *(s16 *)(state + 6),
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68))))
                *(s16 *)(state + 0xa) = 2;
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
