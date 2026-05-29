#include "main/dll/VF/vf_shared.h"

int vfpminifire_getExtraSize(void) { return 0xc; }

int vfpminifire_getObjectTypeId(void) { return 0x0; }

void vfpminifire_hitDetect(void) {}

void vfpminifire_release(void) {}

void vfpminifire_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpminifire_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    if (vis != 0 && *(u8 *)(p1 + 0x36) != 0) {
        fn_80053ED0(8);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6088);
        fn_80053EBC(8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpminifire_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpminifire_init(int *obj, u8 *init) {
    *(f32 *)((char *)obj + 0x28) = lbl_803E6090;
    *(f32 *)((char *)obj + 0x10) = lbl_803E60A4 + *(f32 *)((char *)init + 0xc);
    *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * lbl_803E609C;
    (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x38c, 0, 2, -1, 0);
    Sfx_PlayFromObject((int)obj, 0x103);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset
