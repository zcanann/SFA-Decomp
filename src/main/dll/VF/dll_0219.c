#include "main/dll/VF/vf_shared.h"

extern f32 lbl_803E60A8;
extern f32 lbl_803E60AC;
extern f32 lbl_803E60B0;

typedef struct Dll219State {
    s16 gameBit;
} Dll219State;

typedef struct Dll219Object {
    u8 pad00[0xc];
    f32 x;
    u8 pad10[0x46 - 0x10];
    s16 objectId;
    u8 pad48[0x4c - 0x48];
    u8 *setup;
    u8 pad50[0xb8 - 0x50];
    Dll219State *state;
} Dll219Object;

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
void dll_219_update(Dll219Object *obj) {
    f32 targetX;
    f32 loweredTargetX;

    if (obj->objectId == 0x3a6) {
        if (GameBit_Get(obj->state->gameBit) != 0) {
            loweredTargetX = *(f32 *)(obj->setup + 0x8) - lbl_803E60A8;
            if (obj->x > loweredTargetX) {
                obj->x -= lbl_803E60AC;
                targetX = *(f32 *)(obj->setup + 0x8) - lbl_803E60A8;
                if (obj->x < targetX) {
                    obj->x = targetX;
                }
                return;
            }
        }
        if (GameBit_Get(obj->state->gameBit) == 0) {
            targetX = *(f32 *)(obj->setup + 0x8);
            if (obj->x < targetX) {
                obj->x += lbl_803E60B0;
                if (obj->x > *(f32 *)(obj->setup + 0x8)) {
                    obj->x = *(f32 *)(obj->setup + 0x8);
                }
            }
        }
    }
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
