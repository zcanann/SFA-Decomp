#include "main/dll/VF/vf_shared.h"

int vfpstatueball_getExtraSize(void) { return 0xc; }

int vfpstatueball_getObjectTypeId(void) { return 0x0; }

void vfpstatueball_render(void) {}

void vfpstatueball_hitDetect(void) {}

void vfpstatueball_release(void) {}

void vfpstatueball_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpstatueball_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpstatueball_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(s16 *)((char *)inner + 2) = 0x19;
    *(u16 *)((char *)obj + 0xb0) |= 0x4000;
    if (*(s16 *)((char *)init + 0x1a) > 2) {
        *(s16 *)((char *)init + 0x1a) = 2;
    }
    if (*(s16 *)((char *)init + 0x1c) > 1) {
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * (f32)(s32)*(s16 *)((char *)init + 0x1c);
    }
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    *(u8 *)((char *)inner + 5) = (u8)GameBit_Get(*(s16 *)inner);
}
#pragma scheduling reset
#pragma peephole reset
