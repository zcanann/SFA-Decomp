#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int arwgenerato_getExtraSize(void) { return 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwgenerato_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7150);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwgenerato_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    *(f32 *)(state + 0) = (f32)(u32)*(u16 *)(setup + 0x18);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwgenerato_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    f32 thr = lbl_803E7154;

    if (*(f32 *)state > thr) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= thr) {
            switch (*(u8 *)(setup + 0x25)) {
            case 0:
                fn_802317A8(obj, state, setup);
                break;
            case 1:
                fn_802315EC(obj, state, setup);
                break;
            }
            *(f32 *)state = (f32)(u32)*(u16 *)(setup + 0x18);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
