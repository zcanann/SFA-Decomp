#include "ghidra_import.h"
#include "main/dll/FRONT/dll_44.h"

extern u8 lbl_803A5D60[];

extern void DCInvalidateRange(void *start, u32 nBytes);
extern void DVDClose(void);

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_80118C88
 * EN v1.0 Address: 0x80118C88
 * EN v1.0 Size: 548b
 */
int fn_80118C88(int arg1, int arg2, int arg3, int arg4, int arg5, int arg6)
{
    u8 *base;
    u8 *base2;
    int curr;
    u32 align1;
    u32 align2;
    int i;

    base = lbl_803A5D60;
    if (*(int *)(base + 0x98) == 0) return 0;
    if (*(u8 *)(base + 0x9c) != 0) return 0;

    if (*(int *)(base + 0xa8) != 0) {
        *(int *)(base + 0xac) = arg1;
        curr = arg1 + *(int *)(base + 0x58);
    } else {
        *(int *)(base + 0xf4) = arg1;
        *(int *)(base + 0xfc) = arg1 + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x104) = *(int *)(base + 0xfc) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x10c) = *(int *)(base + 0x104) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x114) = *(int *)(base + 0x10c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x11c) = *(int *)(base + 0x114) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x124) = *(int *)(base + 0x11c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x12c) = *(int *)(base + 0x124) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x134) = *(int *)(base + 0x12c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x13c) = *(int *)(base + 0x134) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        curr = *(int *)(base + 0x13c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
    }

    base2 = lbl_803A5D60;
    align1 = (*(int *)(base2 + 0x80) * *(int *)(base2 + 0x84) + 0x1f) & ~0x1f;
    align2 = ((u32)(*(int *)(base2 + 0x80) * *(int *)(base2 + 0x84)) >> 2) + 0x1f & ~0x1f;
    i = 0;
    do {
        *(int *)(base2 + 0x144) = arg2;
        DCInvalidateRange((void *)curr, align1);
        *(int *)(base2 + 0x148) = arg3;
        DCInvalidateRange((void *)curr, align2);
        *(int *)(base2 + 0x14c) = arg4;
        DCInvalidateRange((void *)curr, align2);
        curr += align2;
        base2 += 0x10;
        i++;
    } while (i < 3);

    base = lbl_803A5D60;
    if (*(u8 *)(base + 0x9f) != 0) {
        *(int *)(base + 0x174) = arg5;
        *(int *)(base + 0x178) = arg5;
        *(int *)(base + 0x17c) = 0;
        {
            int sz = (*(int *)(base + 0x48) * 4 + 0x1f) & ~0x1f;
            int p2 = arg5 + sz;
            *(int *)(base + 0x184) = p2;
            *(int *)(base + 0x188) = p2;
            *(int *)(base + 0x18c) = 0;
            p2 += sz;
            *(int *)(base + 0x194) = p2;
            *(int *)(base + 0x198) = p2;
            *(int *)(base + 0x19c) = 0;
        }
    }

    *(int *)(lbl_803A5D60 + 0x94) = arg6;
    return 1;
}

/*
 * --INFO--
 *
 * Function: fn_80118EAC
 * EN v1.0 Address: 0x80118EAC
 * EN v1.0 Size: 256b
 */
void fn_80118EAC(int *out1, int *out2, int *out3, int *out4, int *out5, int *out6)
{
    u8 *base;

    base = lbl_803A5D60;
    if (*(int *)(base + 0x98) == 0) {
        *out1 = 0;
        *out2 = 0;
        *out3 = 0;
        *out4 = 0;
        *out5 = 0;
        *out6 = 0;
        return;
    }

    if (*(int *)(base + 0xa8) != 0) {
        *out1 = (*(int *)(base + 0x58) + 0x1f) & ~0x1f;
    } else {
        *out1 = ((*(int *)(base + 0x44) + 0x1f) & ~0x1f) * 10;
    }
    *out2 = ((*(int *)(base + 0x80) * *(int *)(base + 0x84) + 0x1f) & ~0x1f) * 3;
    *out3 = ((((u32)(*(int *)(base + 0x80) * *(int *)(base + 0x84)) >> 2) + 0x1f) & ~0x1f) * 3;
    *out4 = ((((u32)(*(int *)(base + 0x80) * *(int *)(base + 0x84)) >> 2) + 0x1f) & ~0x1f) * 3;
    if (*(u8 *)(base + 0x9f) != 0) {
        *out5 = ((*(int *)(base + 0x48) * 4 + 0x1f) & ~0x1f) * 3;
    } else {
        *out5 = 0;
    }
    *out6 = 0x1000;
}

/*
 * --INFO--
 *
 * Function: fn_80118FAC
 * EN v1.0 Address: 0x80118FAC
 * EN v1.0 Size: 84b
 */
int fn_80118FAC(void)
{
    u8 *base;

    base = lbl_803A5D60;
    if (*(int *)(base + 0x98) == 0) return 0;
    if (*(u8 *)(base + 0x9c) != 0) return 0;
    *(int *)(base + 0x98) = 0;
    DVDClose();
    return 1;
}

#pragma peephole reset
#pragma scheduling reset
