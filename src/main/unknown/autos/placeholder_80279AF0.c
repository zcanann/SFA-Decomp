#include "ghidra_import.h"

extern void fn_80278A98(int state, int x);
extern void fn_802794EC(int state);

extern u8 lbl_803CB190[];
extern u8 lbl_803DE2FE;
extern u8 lbl_803DE2FF;
extern u8 lbl_803DE300;
extern u8 lbl_803DE301;

/*
 * fn_8027975C — large voice-allocation/sort routine (~1084 instructions).
 * Stubbed.
 */
#pragma dont_inline on
int fn_8027975C(int state)
{
    (void)state;
    return 0;
}
#pragma dont_inline reset

/*
 * Release a voice slot: clear voice flags, unlink from id table,
 * decrement counter, and mark id slot as free (-1).
 *
 * EN v1.1 Address: 0x80279B98, size 228b
 */
void fn_80279B98(int state)
{
    fn_80278A98(state, 2);
    fn_802794EC(state);
    *(u32 *)(state + 0x34) = 0;
    *(u8 *)(state + 0x10c) = 0;
    {
        u32 voice = *(u32 *)(state + 0xf4);
        u8 v = (u8)voice;
        u8 *slot = lbl_803CB190 + v * 4;
        if (*(u16 *)(slot + 2) == 0) {
            *(u16 *)(slot + 2) = 1;
            if (lbl_803DE301 != 0xff) {
                *(slot + 1) = 0xff;
                *(slot) = lbl_803DE300;
                *(lbl_803CB190 + lbl_803DE300 * 4 + 1) = v;
            } else {
                *(slot + 1) = 0xff;
                *(slot) = 0xff;
                lbl_803DE301 = v;
            }
            lbl_803DE300 = v;
            if (*(u8 *)(state + 0x11d) != 0) {
                lbl_803DE2FF--;
            } else {
                lbl_803DE2FE--;
            }
        }
    }
    *(int *)(state + 0xf4) = -1;
}
