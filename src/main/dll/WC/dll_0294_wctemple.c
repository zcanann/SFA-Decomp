#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int wctemple_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctemple_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E20);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemple_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)state -= timeDelta;
    if (*(f32 *)state < lbl_803E6E24) {
        *(f32 *)state = lbl_803E6E24;
    }

    if (*(u8 *)(state + 4) == 0) {
        if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
            *(u8 *)(state + 4) = 1;
        }
    } else {
        if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
            *(u8 *)(state + 4) = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctemple_init(int obj, int setup)
{
    int angle = (s8)*(u8 *)(setup + 0x18);

    *(s16 *)obj = (s16)(angle << 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
