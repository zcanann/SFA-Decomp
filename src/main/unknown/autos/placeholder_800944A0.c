#include "ghidra_import.h"

extern f32 lbl_803DF318;
extern f32 lbl_803DF348;
extern f32 lbl_803DF34C;
extern f32 lbl_803DB790;
extern f32 lbl_803DD20C;
extern int lbl_803DB618[2];
extern int lbl_803DD1F0;
extern u8 lbl_803DD1F8;
extern u8 lbl_8039AB28[];
extern f32 lbl_8039AB48[];
extern int objFindTexture(int name, int a, int b);
extern f32 PSVECSquareDistance(f32 *a, f32 *b);
extern void *memset(void *dst, int c, int n);

void cloudaction_func08_nop(void) {}
void cloudaction_func09_nop(void) {}
void cloudaction_release(void) {}

#pragma scheduling off
#pragma peephole off
void viewFinderSetZoomTo50(void) {
    lbl_803DB790 = lbl_803DF34C;
}

void viewFinderSetZoom(f32 zoom) {
    lbl_803DB790 = lbl_803DF348 / zoom;
}

void waterfx_func0A(int flag, f32 val) {
    if (flag != 0) {
        val = lbl_803DF318;
    }
    lbl_803DD20C = val;
}

void cloudaction_initialise(void) {
    lbl_803DB618[0] = -1;
    lbl_803DB618[1] = -1;
    lbl_803DD1F0 = 0;
}

void cloudaction_onMapSetup(void) {
    memset(lbl_8039AB28, 0, 0x1c);
}

void cloudaction_func05(void) {
    int tex;
    if (*(void **)lbl_8039AB28 != NULL) {
        tex = objFindTexture(*(int *)lbl_8039AB28, 0, 0);
        if (tex != 0) {
            *(s16 *)(tex + 8) = *(s16 *)(tex + 8) - lbl_8039AB28[0x18];
            if (*(s16 *)(tex + 8) < -0x2710) {
                *(s16 *)(tex + 8) = *(s16 *)(tex + 8) + 0x2710;
            }
        }
    }
}

int fn_800956F4(int vec, f32 dist) {
    if (lbl_803DD1F8 != 0 && PSVECSquareDistance((f32 *)vec, lbl_8039AB48) < dist * dist) {
        lbl_803DD1F8 = 0;
        return 1;
    }
    lbl_803DD1F8 = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
