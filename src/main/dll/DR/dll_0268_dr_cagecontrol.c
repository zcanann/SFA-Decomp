#include "main/dll/DR/dll_80211C24_shared.h"

void cagecontrol_free(void) {}

int cagecontrol_getExtraSize(void) { return 0x4; }

int cagecontrol_getObjectTypeId(void) { return 0x0; }

void cagecontrol_hitDetect(void) {}

void cagecontrol_initialise(void) {}

void cagecontrol_release(void) {}

#pragma scheduling off
#pragma peephole off
void cagecontrol_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cagecontrol_init(int obj, char *arg) {
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        ObjHits_DisableObject(obj);
    }
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cagecontrol_update(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    if (GameBit_Get(*(s16 *)(p + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        ObjHits_DisableObject(obj);
    } else {
        *(s16 *)((char *)obj + 0x6) &= ~0x4000;
        ObjHits_EnableObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
