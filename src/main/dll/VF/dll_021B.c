#include "main/dll/VF/vf_shared.h"

int dll_21B_getExtraSize_ret_4(void) { return 0x4; }

int dll_21B_getObjectTypeId(void) { return 0x0; }

void dll_21B_render_nop(void) {}

void dll_21B_hitDetect_nop(void) {}

#define DLL_21B_ENABLE_BIT_A 0x503
#define DLL_21B_ENABLE_BIT_B 0x504
#define DLL_21B_REACHED_BIT 0x4ec
#define DLL_21B_MOVING_BIT 0x4ed
#define DLL_21B_RESET_BIT 0x4ea
#define DLL_21B_BIT_SET(bit) ((u32)GameBit_Get(bit) != 0u)
#define DLL_21B_BIT_CLEAR(bit) ((u32)GameBit_Get(bit) == 0u)

extern f32 lbl_803E60D0;
extern f32 lbl_803E60D4;

typedef struct Dll21BState {
    s16 gameBit;
} Dll21BState;

void dll_21B_release_nop(void) {}

void dll_21B_initialise_nop(void) {}

#pragma peephole off
#pragma scheduling off
void dll_21B_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_21B_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_21B_update(int obj)
{
    u8 *setup = *(u8 **)(obj + 0x4c);
    Dll21BState *state = *(Dll21BState **)(obj + 0xb8);
    f32 limit;

    if ((s8)setup[0x19] == 1) {
        if (DLL_21B_BIT_SET(state->gameBit) &&
            *(f32 *)(setup + 0x10) - lbl_803E60D0 < *(f32 *)(obj + 0x14)) {
            *(f32 *)(obj + 0x14) -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B)) {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            limit = *(f32 *)(setup + 0x10) - lbl_803E60D0;
            if (limit < *(f32 *)(obj + 0x14)) {
                return;
            }
            *(f32 *)(obj + 0x14) = limit;
            if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A)) {
                return;
            }
            if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B)) {
                return;
            }
            GameBit_Set(DLL_21B_REACHED_BIT, 1);
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->gameBit) &&
            *(f32 *)(obj + 0x14) < *(f32 *)(setup + 0x10)) {
            *(f32 *)(obj + 0x14) -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B)) {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (*(f32 *)(setup + 0x10) < *(f32 *)(obj + 0x14)) {
                *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B)) {
                    GameBit_Set(DLL_21B_RESET_BIT, 0);
                    GameBit_Set(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    } else {
        if (DLL_21B_BIT_SET(state->gameBit) &&
            *(f32 *)(obj + 0x14) < lbl_803E60D0 + *(f32 *)(setup + 0x10)) {
            *(f32 *)(obj + 0x14) += lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B)) {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            limit = lbl_803E60D0 + *(f32 *)(setup + 0x10);
            if (*(f32 *)(obj + 0x14) < limit) {
                return;
            }
            *(f32 *)(obj + 0x14) = limit;
            if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A)) {
                return;
            }
            if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B)) {
                return;
            }
            GameBit_Set(DLL_21B_REACHED_BIT, 1);
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->gameBit) &&
            *(f32 *)(setup + 0x10) < *(f32 *)(obj + 0x14)) {
            *(f32 *)(obj + 0x14) -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B)) {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (*(f32 *)(obj + 0x14) < *(f32 *)(setup + 0x10)) {
                *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B)) {
                    GameBit_Set(DLL_21B_RESET_BIT, 0);
                    GameBit_Set(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
