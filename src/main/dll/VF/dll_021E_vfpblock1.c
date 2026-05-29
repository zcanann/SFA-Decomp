#include "main/dll/VF/vf_shared.h"

/*
 * DLL 0x021E (gVFP_Block1ObjDescriptor) fragment.
 * Only getExtraSize/getObjectTypeId/free/render/hitDetect fall in this object's
 * .text range here (0x801FB9AC-0x801FB9F4); update/init/release/initialise for
 * this DLL live in the adjacent unit main/light.c (next .text range).
 */

int vfpblock1_getExtraSize(void) { return 0x2; }

int vfpblock1_getObjectTypeId(void) { return 0x0; }

void vfpblock1_render(void) {}

void vfpblock1_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void vfpblock1_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset
