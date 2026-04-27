#include "dolphin.h"

extern int InitializeUART(u32);
extern int WriteUARTN(void* buf, u32 n);

extern u8 lbl_803326E8[];
extern u32 lbl_803DE418;

void PPCMtdec(u32 newDec) {
    (void)newDec;
}

void PPCHalt(void) {
}

u8 fn_8029465C(int x) {
    if (x == -1) {
        return 0xFF;
    }

    return lbl_803326E8[(u8)x];
}

int __write_console(int handle, void* buf, u32* count) {
    int result = 0;

    (void)handle;
    if (!lbl_803DE418) {
        result = InitializeUART(0xE100);
        if (result == 0) {
            lbl_803DE418 = 1;
        }
    }

    if (result != 0) {
        return 1;
    }

    if (WriteUARTN(buf, *count) != 0) {
        *count = 0;
        return 1;
    }

    return 0;
}

float __fabsf(float x) {
    return x < 0.0f ? -x : x;
}

float fn_80294724(float x, int n) {
    (void)n;
    return (float)(int)x;
}
