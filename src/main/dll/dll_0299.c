#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"

int dll_299_getExtraSize_ret_2(void) { return 0x2; }

int dll_299_getObjectTypeId(void) { return 0x0; }

void dll_299_render_nop(void) {}

void dll_299_hitDetect_nop(void) {}

void dll_299_release_nop(void) {}

void dll_299_initialise_nop(void) {}

#pragma peephole off
#pragma scheduling off
void dll_299_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void *)obj);
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
    (*gPartfxInterface)->spawnObject((void *)obj, 0x547, NULL, 4, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x547, NULL, 4, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x547, NULL, 4, -1, NULL);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_299_init(int obj, int setup)
{
    *(s16 *)*(int *)&((GameObject *)obj)->extra = *(s16 *)(setup + 0x1e);
    ((GameObject *)obj)->objectFlags |= 0x2000;
    lbl_803DDD80 = Resource_Acquire(0xa6, 1);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x545, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x545, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x545, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x546, NULL, 0x802, -1, NULL);
}
#pragma scheduling reset
#pragma peephole reset
