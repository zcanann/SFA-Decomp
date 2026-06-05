#include "main/dll/VF/vf_shared.h"

#include "main/audio/sfx_ids.h"
extern f32 lbl_803E60D8;
extern f32 lbl_803E60DC;

int vfpladders_SeqFn(void) { return 0x0; }

int vfpladders_getExtraSize(void) { return 0x8; }

int vfpladders_getObjectTypeId(void) { return 0x0; }

void vfpladders_render(void) {}

void vfpladders_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void vfpladders_update(int obj) {
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    int countdown;

    if (*(s16 *)(obj + 0x46) == 0x548) {
        if ((u32)GameBit_Get(*(s16 *)(state + 2)) != 0) {
            if ((u32)GameBit_Get(*(s16 *)state) == 0) {
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
            }
        }
        if ((u32)GameBit_Get(*(s16 *)(state + 2)) == 0) {
            if ((u32)GameBit_Get(*(s16 *)state) != 0) {
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
            }
        }
    } else {
        if (*(s16 *)(state + 6) != 0) {
            countdown = *(s16 *)(state + 6);
            countdown -= (s32)timeDelta;
            *(s16 *)(state + 6) = countdown;
            if (*(s16 *)(state + 6) <= 0) {
                *(s16 *)(state + 4) = 1;
                Sfx_PlayFromObject(obj, SFXen_flybuzz_loop);
                *(s16 *)(state + 6) = 0;
            }
        } else {
            if (*(s16 *)(state + 4) == 0 && (u32)GameBit_Get(*(s16 *)(state + 2)) != 0) {
                *(s16 *)(state + 6) = 0x5a;
            }
            if (*(s16 *)(state + 4) == 1 &&
                *(f32 *)(obj + 0x10) > *(f32 *)(setup + 0xc) - lbl_803E60D8) {
                *(f32 *)(obj + 0x10) =
                    *(f32 *)(obj + 0x10) - lbl_803E60DC * timeDelta;
                if (*(f32 *)(obj + 0x10) < *(f32 *)(setup + 0xc) - lbl_803E60D8) {
                    *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc) - lbl_803E60D8;
                    *(s16 *)(state + 4) = 2;
                }
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void vfpladders_release(void) {}

void vfpladders_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpladders_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x20);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    *(void **)((char *)obj + 0xbc) = (void *)vfpladders_SeqFn;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpladders_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset
