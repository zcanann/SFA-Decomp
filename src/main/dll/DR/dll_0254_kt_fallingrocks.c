#include "main/dll/DR/dll_80211C24_shared.h"

int ktfallingrocks_getExtraSize(void) { return 0x0; }

int ktfallingrocks_getObjectTypeId(void) { return 0x0; }

void ktfallingrocks_hitDetect(void) {}

void ktfallingrocks_initialise(void) {}

void ktfallingrocks_release(void) {}

#pragma scheduling off
#pragma peephole off
void ktfallingrocks_init(int obj) {
    *(int *)((char *)obj + 0xbc) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktfallingrocks_free(u8 *obj) {
    ((void (*)(u8 *))(*(u32 *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktfallingrocks_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktfallingrocks_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    ObjPosParams params;
    int player;
    int i;
    if (GameBit_Get(*(s16 *)(q + 0x24)) == 0) {
        return;
    }
    player = (int)Obj_GetPlayerObject();
    if (player == 0) {
        return;
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)(player + 0xc);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)(player + 0x14);
    for (i = 0; i < 10; i++) {
        params.x = *(f32 *)((char *)obj + 0xc) + (f32)(int)randomGetRange(-200, 200);
        params.y = *(f32 *)((char *)obj + 0x10);
        params.z = *(f32 *)((char *)obj + 0x14) + (f32)(int)randomGetRange(-200, 200);
        (*(void (**)(int, int, ObjPosParams *, int, int, int))((char *)*gPartfxInterface + 0x8))(
            obj, *(u16 *)(q + 0x20), &params, 0x200001, -1, 0);
    }
    Sfx_PlayFromObject(obj, 696);
    GameBit_Set(*(s16 *)(q + 0x24), 0);
}
#pragma peephole reset
#pragma scheduling reset
