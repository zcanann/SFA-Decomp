#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int vortex_getExtraSize(void) { return 0x28; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int vortex_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vortex_init(int obj, int initData)
{
    f32 *base = lbl_8032BE20;
    int state = *(int *)(obj + 0xb8);
    u8 i;

    ((VortexFlags *)(state + 0x26))->active = 0;
    if (*(s16 *)(initData + 0x20) != -1) {
        ((VortexFlags *)(state + 0x26))->active = (u8)GameBit_Get(*(s16 *)(initData + 0x20));
    }
    if (*(s16 *)(obj + 0x46) == 0x835) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC400[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (*(s16 *)(obj + 0x46) == 0x838) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC408[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (*(s16 *)(obj + 0x46) == 0x83d) {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 3];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i + 6];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 9];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
        if (((VortexFlags *)(state + 0x26))->active != 0) {
            if (*(s16 *)(initData + 0x1e) != -1) {
                ((VortexFlags *)(state + 0x26))->active = !GameBit_Get(*(s16 *)(initData + 0x1e));
            }
        }
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
    if (((VortexFlags *)(state + 0x26))->active != 0)
        *(f32 *)(state + 0) = lbl_803E73E0;
    else
        *(f32 *)(state + 0) = lbl_803E73D0;
    *(f32 *)(state + 4) = (f32)randomGetRange(0, 0x14);
    *(f32 *)(obj + 0x40) = *(f32 *)(obj + 0x40) * lbl_803E7404;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vortex_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    ((VortexFlags *)(state + 0x26))->active = 0;
    if (*(s16 *)(setup + 0x20) != -1) {
        ((VortexFlags *)(state + 0x26))->active = (u8)GameBit_Get(*(s16 *)(setup + 0x20));
    }

    if (*(s16 *)(obj + 0x46) == 0x29a || *(s16 *)(obj + 0x46) == 0x829) {
        if (((VortexFlags *)(state + 0x26))->active != 0) {
            if (*(s16 *)(setup + 0x1e) != -1) {
                ((VortexFlags *)(state + 0x26))->active = !GameBit_Get(*(s16 *)(setup + 0x1e));
            }
        }
    }

    if (((VortexFlags *)(state + 0x26))->active != 0) {
        f32 lim = lbl_803E73E0;
        if (*(f32 *)(state + 0) < lim) {
            *(f32 *)(state + 0) = lbl_803E7400 * timeDelta + *(f32 *)(state + 0);
            if (*(f32 *)(state + 0) > lim) {
                *(f32 *)(state + 0) = lim;
            }
        }
    } else {
        f32 lim = lbl_803E73D0;
        if (*(f32 *)(state + 0) > lim) {
            *(f32 *)(state + 0) = *(f32 *)(state + 0) - lbl_803E7400 * timeDelta;
            if (*(f32 *)(state + 0) < lim) {
                *(f32 *)(state + 0) = lim;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void vortex_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
