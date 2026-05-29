#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int dll_2A3_getExtraSize_ret_12(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dll_2A3_getObjectTypeId(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_release_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_initialise_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_free(void) { lbl_803DDD90 = lbl_803DDD90 - 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7118);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A3_hitDetect(void) { lbl_803DDD94 = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A3_update(int obj)
{
    f32 v;
    int state = *(int *)(obj + 0xb8);

    if (*(f32 *)state > lbl_803E711C) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= lbl_803E711C) {
            *(f32 *)state = lbl_803E711C;
            Obj_FreeObject(obj);
            return;
        }
    }

    v = (f32)(u32) * (u8 *)(obj + 0x36) + lbl_803E7120 * timeDelta;
    if (v > lbl_803E7124) {
        v = lbl_803E7124;
    }
    *(u8 *)(obj + 0x36) = (u8)v;

    *(s16 *)(obj + 0) = (s16)((f32) * (s16 *)(state + 4) * timeDelta + (f32) * (s16 *)(obj + 0));
    *(s16 *)(obj + 2) = (s16)((f32) * (s16 *)(state + 6) * timeDelta + (f32) * (s16 *)(obj + 2));
    *(s16 *)(obj + 4) = (s16)((f32) * (s16 *)(state + 8) * timeDelta + (f32) * (s16 *)(obj + 4));

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);

    if (lbl_803DDD94 == 0) {
        lbl_803DDD94 = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A3_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(obj + 0x36) = 0;
    *(s16 *)(obj + 0) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 2) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 4) = randomGetRange(0, 0xffff);
    *(s16 *)(state + 4) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 6) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 8) = randomGetRange(-0x32, 0x32);
    lbl_803DDD90 = lbl_803DDD90 + 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023137C(int obj, int src)
{
    *(f32 *)(obj + 0x24) = *(f32 *)(src + 0x0);
    *(f32 *)(obj + 0x28) = *(f32 *)(src + 0x4);
    *(f32 *)(obj + 0x2c) = *(f32 *)(src + 0x8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023134C(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
#pragma scheduling reset
#pragma peephole reset
