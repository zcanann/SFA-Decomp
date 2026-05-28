#include "main/dll/WM/wm_shared.h"

int wmnewcrystal_getExtraSize(void) { return 0x6c; }

int wmnewcrystal_getObjectTypeId(void) { return 0x0; }

void wmnewcrystal_free(void) {}

void wmnewcrystal_hitDetect(void) {}

void wmnewcrystal_update(void) {}

void wmnewcrystal_release(void) {}

void wmnewcrystal_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmnewcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E605C);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmnewcrystal_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)fn_801F943C;
    if ((u8)(*(int (*)(int))(*(int *)(*gMapEventInterface + 0x40)))((s8)*(u8 *)((char *)obj + 0xac)) > 1) {
        GameBit_Set(0xd27, 1);
        *(u8 *)((char *)inner + 0x68) = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset
