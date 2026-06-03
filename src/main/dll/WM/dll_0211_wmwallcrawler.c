#include "main/dll/WM/wm_shared.h"

int wmwallcrawler_getExtraSize(void) { return 0x29c; }

int wmwallcrawler_getObjectTypeId(void) { return 0x0; }

void wmwallcrawler_release(void) {}

void wmwallcrawler_initialise(void) {}

#pragma peephole off
#pragma scheduling off
int fn_801F7FF4(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x296) = 1;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_free(int obj) {
    ObjGroup_RemoveObject(obj, 3);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if ((*(u16 *)((char *)inner + 0x294) & 0x40) != 0 && (u8)*(u8 *)(p1 + 0x36) < 0xff) {
        if (*(u8 *)(p1 + 0x36) > 0xff - framesThisStep) {
            *(u8 *)(p1 + 0x36) = 0xff;
            *(u16 *)((char *)inner + 0x294) &= ~0x40;
        } else {
            *(u8 *)(p1 + 0x36) += framesThisStep;
        }
    }
    if (vis != 0 && *(s16 *)((char *)inner + 0x28c) == 0) {
        objRenderFn_8003b8f4(lbl_803E5FB4);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void mathFn_80021ac8(void* mtx, f32* vec);
extern f32 lbl_803E5FB0;
typedef struct { s16 r0, r1, r2; f32 m8, mc, m10, m14; } WcXf;

#pragma peephole off
#pragma scheduling off
void fn_801F8008(int a, f32* b)
{
    WcXf mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = b[1];
    in[1] = b[2];
    in[2] = b[3];
    mtx.mc = lbl_803E5FB0;
    mtx.m10 = lbl_803E5FB0;
    mtx.m14 = lbl_803E5FB0;
    mtx.m8 = lbl_803E5FB4;
    mtx.r2 = 0;
    mtx.r1 = 0;
    mtx.r0 = *(s16*)a;
    mathFn_80021ac8(&mtx, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    *(s16*)(a + 2) = (s16)ang2;
    *(s16*)(a + 4) = (s16)ang;
}
#pragma scheduling reset
#pragma peephole reset
