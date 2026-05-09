#include "ghidra_import.h"

extern void *memset(void *dst, int val, u32 n);
extern void DCFlushRangeNoSync(void *p, u32 n);
extern void salFree(int p);

extern u8 *lbl_803DE338;
extern u8 *lbl_803DE344;
extern u8 *lbl_803DE340;
extern u8 *lbl_803DE33C;
extern u8 *lbl_803DE330;
extern u8 lbl_803CC1E0[][0xbc];
extern u8 lbl_803DE37C;
extern u8 lbl_803DE37D;

/*
 * fn_8027BA04 - large voice processing (~932 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027BA04(void) {}
#pragma dont_inline reset

/*
 * Clear and flush a 256-byte voice scratch buffer.
 *
 * EN v1.1 Address: 0x8027BDA8, size 56b
 */
void fn_8027BDA8(void)
{
    memset(lbl_803DE338, 0, 0x100);
    DCFlushRangeNoSync(lbl_803DE338, 0x100);
}

/*
 * Free all voice/studio resources, then return 1.
 *
 * EN v1.1 Address: 0x8027BDE0, size 220b
 */
int audioFreeFn_8027bde0(void)
{
    int i;
    int offset;
    salFree((int)lbl_803DE338);
    offset = 0;
    for (i = 0; (u8)i < lbl_803DE37D; i++) {
        salFree(*(int *)(lbl_803DE344 + offset));
        salFree(*(int *)(lbl_803DE344 + offset + 4));
        offset += 0xf4;
    }
    for (i = 0; (u8)i < lbl_803DE37C; i++) {
        salFree(*(int *)(&lbl_803CC1E0[i][0]));
        salFree(*(int *)(&lbl_803CC1E0[i][0x28]));
    }
    salFree((int)lbl_803DE340);
    salFree((int)lbl_803DE344);
    salFree((int)lbl_803DE33C);
    salFree((int)lbl_803DE330);
    return 1;
}

/*
 * fn_8027BEBC - voice-buffer init with several memset/flush calls
 * (~264 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027BEBC(u8 idx, u8 a, int b)
{
    (void)idx; (void)a; (void)b;
}
#pragma dont_inline reset

/*
 * Clear active flag for studio idx.
 *
 * EN v1.1 Address: 0x8027BFC4, size 32b
 */
void fn_8027BFC4(u8 idx)
{
    lbl_803CC1E0[idx][0x50] = 0;
}

/*
 * fn_8027BFE4 - pitch/interval mapper (~244 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8027BFE4(int r3, u16 *r4, u16 *r5, u16 r6, u16 *r7, u16 r8)
{
    (void)r3; (void)r4; (void)r5; (void)r6; (void)r7; (void)r8;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_8027C0D8 - large voice param updater (~696 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027C0D8(int r3, int r4)
{
    (void)r3; (void)r4;
}
#pragma dont_inline reset

/*
 * fn_8027C390 - large voice routing (~252 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027C390(void) {}
#pragma dont_inline reset
