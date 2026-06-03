#include "main/dll/VF/vf_shared.h"

int vfplift_getExtraSize(void) { return 0x20; }

int vfplift_getObjectTypeId(void) { return 0x0; }

void vfplift_release(void) {}

void vfplift_initialise(void) {}

#pragma peephole off
#pragma scheduling off
int vfplift_SeqFn(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x1c) |= 0x40;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E60F0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_update(int obj) {
    int v;
    Obj_GetPlayerObject();
    v = *(s16 *)((char *)obj + 0x46);
    if (v == 0x3b7) {
        fn_801FB434(obj);
    } else if (v == 0x3bf) {
        fn_801FB23C(obj);
    } else if (v == 0x53f) {
        fn_801FB23C(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_hitDetect(int obj) {
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s16 *)((char *)inner + 0xc) != -1 && (u32)GameBit_Get(*(s16 *)((char *)inner + 0xc)) == 0) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
    } else if ((*(u8 *)((char *)obj + 0xaf) & 8) != 0) {
        *(u8 *)((char *)obj + 0xaf) ^= 8;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)vfplift_SeqFn;
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = *(s16 *)((char *)init + 0x20);
    *(s16 *)((char *)inner + 0xe) = *(s16 *)((char *)init + 0x1e);
    *(f32 *)inner = (f32)(s32)*(s16 *)((char *)init + 0x1a);
    *(u8 *)((char *)inner + 0x1a) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 0x12) = 0;
    *(s16 *)((char *)inner + 0x14) = 0;
    *(s16 *)((char *)inner + 0x16) = 0;
    *(s16 *)((char *)inner + 0x18) = 0;
    if (*(s16 *)((char *)obj + 0x46) == 0x3bf) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        } else {
            *(s16 *)((char *)inner + 0xa) = 3;
        }
    }
    if (*(s16 *)((char *)obj + 0x46) == 0x3b7 && GameBit_Get(0x4ee) != 0) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 3;
        } else {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset
