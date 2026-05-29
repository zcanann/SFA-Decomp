#include "main/dll/WM/wm_shared.h"

int wmspiritset_getExtraSize(void) { return 0x2; }

int wmspiritset_getObjectTypeId(void) { return 0x0; }

void wmspiritset_free(void) {}

void wmspiritset_hitDetect(void) {}

void wmspiritset_update(void) {}

void wmspiritset_release(void) {}

void wmspiritset_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmspiritset_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    if (*(s16 *)((char *)obj + 0x46) == 0x264) {
        *(f32 *)((char *)obj + 8) = lbl_803E5F94;
    }
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmspiritset_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    s16 v = *(s16 *)inner;
    if ((v == -1 || GameBit_Get(v) != 0) && vis != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F90);
    }
}
#pragma scheduling reset
#pragma peephole reset
