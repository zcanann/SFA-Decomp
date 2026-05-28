#include "main/dll/DR/dll_80211C24_shared.h"

int drchimmey_getExtraSize(void) { return 0x18; }

#pragma scheduling off
#pragma peephole off
void drchimmey_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69E0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drchimmey_init(int obj, char *arg) {
    int p;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    p = *(int *)((char *)obj + 0xb8);
    *(f32 *)(p + 0xc) = lbl_803E69E8;
    *(s16 *)(p + 0x14) = *(s16 *)(arg + 0x1e);
    *(u8 *)(p + 0x16) = 3;
    storeZeroToFloatParam((void *)(p + 0x10));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drchimmey_countdownCallback(int obj, int dec) {
    s8 *p = (s8 *)*(char **)((char *)obj + 0xb8);
    p[0x16] -= dec;
    return p[0x16] == 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drchimmey_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    *(u8 *)((char *)obj + 0xaf) |= 8;
    if (*(s16 *)(q + 0x20) != -1 && GameBit_Get(*(s16 *)(q + 0x20)) == 0) {
        return;
    }
    if (fn_80080150((void *)(p + 0x10)) == 0) {
        if ((s8)p[0x16] <= 0) {
            p[0x17] = 1;
            s16toFloat((void *)(p + 0x10), (int)*(f32 *)(p + 0xc));
            GameBit_Set(*(s16 *)(p + 0x14), 1);
        } else {
            int *tricky = getTrickyObject();
            if (tricky != 0) {
                if ((*(u8 *)((char *)obj + 0xaf) & 4) != 0) {
                    (*(void (**)(int *, int, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8 *)((char *)obj + 0xaf) &= ~8;
                objRenderFn_80041018(obj);
            }
        }
    }
    if (timerCountDown((void *)(p + 0x10)) != 0) {
        *(int *)p = 0;
        *(f32 *)(p + 0x10) = lbl_803E69E4;
        p[0x17] = 0;
        p[0x16] = 1;
        GameBit_Set(*(s16 *)(p + 0x14), 0);
        GameBit_Set(0xea4, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
