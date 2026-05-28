#include "main/dll/VF/vf_shared.h"

int fn_801FAFEC(void) { return 0x0; }

int vfpladders_getExtraSize(void) { return 0x8; }

int vfpladders_getObjectTypeId(void) { return 0x0; }

void vfpladders_render(void) {}

void vfpladders_hitDetect(void) {}

void vfpladders_release(void) {}

void vfpladders_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpladders_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x20);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    *(void **)((char *)obj + 0xbc) = (void *)fn_801FAFEC;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpladders_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset
