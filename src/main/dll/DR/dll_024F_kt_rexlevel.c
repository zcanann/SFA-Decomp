#include "main/dll/DR/dll_80211C24_shared.h"

int ktrexlevel_getExtraSize(void) { return 0x4; }

int ktrexlevel_getObjectTypeId(void) { return 0x0; }

void ktrexlevel_hitDetect(void) {}

void ktrexlevel_initialise(void) {}

void ktrexlevel_release(void) {}

#pragma scheduling off
#pragma peephole off
void ktrexlevel_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E67A0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void ktrexlevel_clearPathGameBits(void) {
    GameBit_Set(0x54a, 0);
    GameBit_Set(0x54e, 0);
    GameBit_Set(0x552, 0);
    GameBit_Set(0x556, 0);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexlevel_free(void) {
    GameBit_Set(0xefd, 0);
    GameBit_Set(0xcd1, 0);
    GameBit_Set(0xccd, 0);
    GameBit_Set(0xccf, 0);
    GameBit_Set(0xcd0, 0);
    GameBit_Set(0xedb, 0);
    GameBit_Set(0xcbb, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexlevel_updatePathGameBits(void) {
    if (GameBit_Get(0x55a) != 0) {
        GameBit_Set(0x54a, 2);
        GameBit_Set(0x54e, 2);
        GameBit_Set(0x552, 1);
        GameBit_Set(0x556, 1);
    } else if (GameBit_Get(0x55b) != 0) {
        GameBit_Set(0x54a, 1);
        GameBit_Set(0x54e, 1);
        GameBit_Set(0x552, 2);
        GameBit_Set(0x556, 2);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexlevel_init(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    setDrawCloudsAndLights(0);
    GameBit_Set(0x572, 0);
    GameBit_Set(0x56e, 1);
    GameBit_Set(0x566, 1);
    GameBit_Set(0x569, 1);
    *(f32 *)p = lbl_803E67A8;
    GameBit_Set(0x55a, 1);
    GameBit_Set(0x54a, 2);
    GameBit_Set(0x54e, 2);
    GameBit_Set(0x552, 1);
    GameBit_Set(0x556, 1);
    *(int *)((char *)obj + 0xf4) = 0;
    GameBit_Set(0xefd, 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexlevel_update(int obj) {
    if (*(int *)((char *)obj + 0xf4) == 0) {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, obj, 0x18f, 0);
        getEnvfxAct(obj, obj, 0x18e, 0);
        getEnvfxAct(obj, obj, 0x190, 0);
        skyFn_80088e54(1, lbl_803E67A4);
        GameBit_Set(0x55e, 1);
        *(int *)((char *)obj + 0xf4) = 1;
    }
    lbl_803DDD40 = GameBit_Get(0x572);
}
#pragma peephole reset
#pragma scheduling reset
