#include "main/dll/VF/vf_shared.h"

int vfpobjcreator_getExtraSize(void) { return 0xa; }

int vfpobjcreator_getObjectTypeId(void) { return 0x0; }

void vfpobjcreator_free(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) return;
}
#pragma scheduling reset
#pragma peephole reset

void vfpobjcreator_hitDetect(void) {}

void vfpobjcreator_release(void) {}

void vfpobjcreator_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x1e] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x18);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 4) = *(s16 *)((char *)inner + 2);
    *(s16 *)((char *)inner + 6) = (s8)init[0x1f];
    *(s16 *)((char *)inner + 8) = init[0x20];
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset
