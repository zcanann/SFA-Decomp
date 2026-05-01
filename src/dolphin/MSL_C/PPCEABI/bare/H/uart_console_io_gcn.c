#include "dolphin.h"

extern int InitializeUART(u32);
extern int WriteUARTN(void* buf, u32 n);

extern u8 lbl_803326E8[];
extern s32 lbl_803DE418;

__declspec(weak) asm void PPCMtdec(register u32 newDec) {
    nofralloc
    mtdec r3
    blr
}

__declspec(weak) asm void PPCHalt(void) {
    nofralloc
    sync
loop:
    nop
    li r3, 0
    nop
    b loop
}

int tolower(int x) {
    if (x == -1) {
        return -1;
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

asm float fabsf__Ff(register float x) {
    nofralloc
    fabs f1, f1
    blr
}

float fn_80294724(float x) {
    int n = (int)x;
    float truncated = (float)n;

    if (truncated != x && ((*(u32*)&x & 0x7F800000) < 0x4B800000)) {
        if (*(u32*)&x & 0x80000000) {
            n--;
        }
        truncated = (float)n;
    }

    return truncated;
}
