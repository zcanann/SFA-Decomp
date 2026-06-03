#include "main/dll/WM/wm_shared.h"

int fn_801F6E8C(int p1, int p2, int actor)
{
    int ret;

    ret = 0;
    *(s16 *)(actor + 0x6e) = -1;
    *(u8 *)(actor + 0x56) = (u8)ret;
    return ret;
}

int wmsun_getExtraSize(void) { return 0x10; }

int wmsun_getObjectTypeId(void) { return 0x0; }

void wmsun_hitDetect(void) {}

void wmsun_release(void) {}

void wmsun_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmsun_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)((char *)inner + 8) != NULL) {
        mm_free(*(void **)((char *)inner + 8));
    }
    *(int *)((char *)inner + 8) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmsun_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if (vis != 0 && *(u8 *)((char *)inner + 0xd) != 0) {
        doNothing_8005D148(p2, 0x10000);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F24);
        doNothing_8005D14C(p2, 0x10000);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int mmAlloc(int size, int tag, int p3);
extern f32 lbl_803E5F8C;
extern s16 lbl_803DDCA8;
extern s16 lbl_803DDCAA;
extern s16 lbl_803DDCAC;
extern s16 lbl_803DDCAE;
extern s16 lbl_803DDCB0;
#pragma scheduling off
#pragma peephole off
void wmsun_init(int obj, int params)
{
    int state = *(int *)(obj + 0xb8);
    u8 c;
    int c2;
    s16 i;
    int j;
    s16 mode;

    *(void **)(obj + 0xbc) = (void *)fn_801F6E8C;
    c = (*(code *)(*gMapEventInterface + 0x40))((int)*(s8 *)(obj + 0xac));
    if (c == 3 && (u32)GameBit_Get(0x21b) == 0) {
        GameBit_Set(0x21b, 1);
    }
    *(int *)(state + 8) = 0;
    *(u8 *)(state + 0xd) = 1;
    mode = *(s16 *)(obj + 0x46);
    if (mode == 0x262) {
        *(s16 *)obj = (s16)(*(s8 *)(params + 0x18) << 8);
        *(s16 *)(state + 2) = 100;
        if (*(s16 *)(params + 0x1c) >= 1000) {
            *(f32 *)(obj + 8) = (f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C;
        } else {
            *(f32 *)(obj + 8) = lbl_803E5F24;
        }
    } else if (mode == 0x2bd) {
        lbl_803DDCB0 = 800;
        lbl_803DDCAE = 800;
        lbl_803DDCAC = 800;
        lbl_803DDCAA = 800;
        lbl_803DDCA8 = 800;
        *(s16 *)obj = (s16)(*(s8 *)(params + 0x18) << 8);
        if (*(s16 *)(params + 0x1c) >= 0) {
            *(f32 *)(obj + 8) = (f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C;
        } else {
            *(f32 *)(obj + 8) = lbl_803E5F24;
        }
        *(u8 *)(obj + 0xad) = *(u8 *)(params + 0x19);
        c2 = *(s8 *)(obj + 0xad);
        if (c2 == 0) {
            *(s16 *)(state + 2) = randomGetRange(300, 600);
            *(s16 *)(state + 4) = randomGetRange(300, 600);
        } else if (c2 == 1) {
            *(s16 *)(state + 2) = randomGetRange(500, 800);
            *(s16 *)(state + 4) = randomGetRange(500, 800);
        } else if (c2 == 2) {
            *(s16 *)(state + 2) = randomGetRange(700, 1000);
            *(s16 *)(state + 4) = randomGetRange(700, 1000);
        }
        *(u8 *)(obj + 0x36) = 0;
    } else if (mode == 0x2c2) {
        *(int *)(state + 8) = mmAlloc(0xa0, 0xe, 0);
        i = 0x14;
        j = 0x28;
        while (i != 0) {
            j -= 2;
            i--;
            *(s16 *)(*(int *)(state + 8) + j + 0x28) = 0;
            *(s16 *)(*(int *)(state + 8) + j + 0x50) = randomGetRange(10, 0x14);
            *(s16 *)(*(int *)(state + 8) + j + 0x78) = randomGetRange(0x50, 0xff);
        }
        *(u8 *)(obj + 0x36) = 0;
        if (*(s16 *)(params + 0x1c) != 0) {
            *(f32 *)(obj + 8) = lbl_803E5F24 / ((f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
