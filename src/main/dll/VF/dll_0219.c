#include "main/dll/VF/vf_shared.h"

int dll_219_getExtraSize_ret_4(void) { return 0x4; }

int dll_219_getObjectTypeId(void) { return 0x0; }

void dll_219_render_nop(void) {}

void dll_219_hitDetect_nop(void) {}

void dll_219_release_nop(void) {}

void dll_219_initialise_nop(void) {}

#pragma peephole off
#pragma scheduling off
void dll_219_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_219_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
}
#pragma scheduling reset
#pragma peephole reset
