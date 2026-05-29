#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int dll_299_getExtraSize_ret_2(void) { return 0x2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dll_299_getObjectTypeId(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_299_render_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_299_hitDetect_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_299_release_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_299_initialise_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_299_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
    (*(void (**)(int))(*gModgfxInterface + 0x14))(obj);
    Resource_Release(lbl_803DDD80);
    lbl_803DDD80 = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_299_update(int obj)
{
    if (randomGetRange(0, 2) == 0) {
        (*(void (**)(int, int, int, int, int, int))(*(int *)lbl_803DDD80 + 0x4))(obj, 1, 0, 4, -1, 0);
    }
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_299_init(int obj, int setup)
{
    *(s16 *)*(int *)(obj + 0xb8) = *(s16 *)(setup + 0x1e);
    *(u16 *)(obj + 0xb0) |= 0x2000;
    lbl_803DDD80 = Resource_Acquire(0xa6, 1);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x546, 0, 0x802, -1, 0);
}
#pragma scheduling reset
#pragma peephole reset
