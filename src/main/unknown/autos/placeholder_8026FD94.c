#include "ghidra_import.h"

extern int fn_80271178(int handle, int mode, int flag);
extern u8 *lbl_803DE268;
extern int lbl_803DE278;
extern int lbl_803DE27C;

/*
 * fn_8026FC8C — voice handler (~608 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026FC8C(void) {}
#pragma dont_inline reset

/*
 * fn_8026FEEC — voice handler (~664 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026FEEC(void) {}
#pragma dont_inline reset

/*
 * fn_80270184 — large voice handler (~1972 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270184(void) {}
#pragma dont_inline reset

/*
 * fn_80270938 — large voice handler (~1712 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270938(void) {}
#pragma dont_inline reset

/*
 * fn_80270FE8 — voice handler (~400 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270FE8(void) {}
#pragma dont_inline reset

/*
 * fn_80271178 — internal helper used by the wrappers below (~336
 * instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80271178(int handle, int mode, int flag)
{
    (void)handle; (void)mode; (void)flag;
    return 0;
}
#pragma dont_inline reset

/*
 * Reset four pos/timer fields on the handle, then advance both
 * channels (modes 0 and 1).
 *
 * EN v1.1 Address: 0x802712C8, size 100b
 */
int fn_802712C8(int handle)
{
    {
        int a = lbl_803DE278;
        int b = lbl_803DE27C;
        *(int *)(handle + 0x24) = a;
        *(int *)(handle + 0x28) = b;
    }
    {
        int a = lbl_803DE278;
        int b = lbl_803DE27C;
        *(int *)(handle + 0x2c) = a;
        *(int *)(handle + 0x30) = b;
    }
    fn_80271178(handle, 0, 0);
    return fn_80271178(handle, 1, 0);
}

/*
 * Advance both channels (modes 0 and 1) of the handle.
 *
 * EN v1.1 Address: 0x8027132C, size 68b
 */
int fn_8027132C(int handle)
{
    fn_80271178(handle, 0, 0);
    return fn_80271178(handle, 1, 0);
}

/*
 * Wrapper for fn_80271178(handle, 2, 0).
 *
 * EN v1.1 Address: 0x80271370, size 40b
 */
int fn_80271370(int handle)
{
    return fn_80271178(handle, 2, 0);
}

/*
 * Walk a voice linked-list, marking each entry's slot 9 as 0xff and
 * invoking the callback for entries whose voice's 0x11c field is 0.
 *
 * EN v1.1 Address: 0x80271398, size 148b
 */
void fn_80271398(int head, void (*cb)(u8 idx))
{
    int cur = *(int *)head;
    while (cur != 0) {
        int next = *(int *)cur;
        *(u8 *)(cur + 0x9) = 0xff;
        {
            u8 idx = *(u8 *)(cur + 0x8);
            if (*(u8 *)(lbl_803DE268 + idx * 0x404 + 0x11c) == 0) {
                cb(idx);
            }
        }
        cur = next;
    }
    *(int *)head = 0;
}

/*
 * fn_8027142C — list-walker variant (~108 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027142C(void) {}
#pragma dont_inline reset

/*
 * fn_80271498 — list-walker variant (~792 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80271498(void) {}
#pragma dont_inline reset

/*
 * fn_802717B0 — voice handler (~188 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_802717B0(int a, int b, int c, int d, u8 e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    return 0;
}
#pragma dont_inline reset
