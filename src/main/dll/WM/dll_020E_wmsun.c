#include "main/dll/WM/wm_shared.h"

int fn_801F6E8C(int p1, int p2, int actor)
{
    int ret;

    ret = 0;
    *(s16 *)(actor + 0x6e) = -1;
    *(u8 *)(actor + 0x56) = (u8)ret;
    return ret;
}

int wmsun_getExtraSize(void) { return 0x10; }

int wmsun_getObjectTypeId(void) { return 0x0; }

void wmsun_hitDetect(void) {}

void wmsun_release(void) {}

void wmsun_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmsun_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)((char *)inner + 8) != NULL) {
        mm_free(*(void **)((char *)inner + 8));
    }
    *(int *)((char *)inner + 8) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmsun_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if (vis != 0 && *(u8 *)((char *)inner + 0xd) != 0) {
        doNothing_8005D148(p2, 0x10000);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F24);
        doNothing_8005D14C(p2, 0x10000);
    }
}
#pragma scheduling reset
#pragma peephole reset
