#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027280C.h"

extern void fn_80284AF4(void);
extern void fn_80284ABC(void);
extern void fn_8026D6E4(int a, int b, int c, int d);
extern int fn_8027186C(int a, int b, int c);
extern int fn_80271954(int a, int b, int c);
extern int fn_80271AC0(int a);
extern int fn_802717B0(int a, int b, int c, int d, u8 e);
extern int fn_80271B4C(int a, int b, int c, int d, int e);
extern int fn_8027949C(u32 id);
extern void fn_80273870(void);
extern void hwAddInput(u8 idx);
extern void hwRemoveInput(u8 idx);
extern void hwActivateStudio(int a, int b, int c);
extern void hwDisableHRTF(void);

extern u8 lbl_803BCC90[];
extern u8 lbl_803BD150[];
extern u8 lbl_803BD9C4[];
extern u8 lbl_803BDA04[];
extern u8 lbl_803BDA24[];
extern u8 lbl_803DE244[];
extern u8 lbl_803DE254[];
extern u32 lbl_803DE264;
extern u8 *lbl_803DE268;

/*
 * Critical-section wrapper around fn_8026D6E4.
 *
 * EN v1.1 Address: 0x80272720, size 100b
 */
void fn_80272720(int a, int b, int c, int d)
{
    fn_80284AF4();
    fn_8026D6E4(a, b, c, d);
    fn_80284ABC();
}

/*
 * Look up an event halfword from a 2D table (slot[u8] × event[u8]).
 *
 * EN v1.1 Address: 0x80272788, size 32b
 */
u16 fn_80272788(u8 slot, u8 event)
{
    return *(u16 *)(lbl_803BCC90 + slot * 32 + event * 2);
}

/*
 * Critical-section wrapper around fn_8027186C.
 *
 * EN v1.1 Address: 0x802727A8, size 96b
 */
int fn_802727A8(int a, int b, int c)
{
    int result;
    fn_80284AF4();
    result = fn_8027186C(a, b, c);
    fn_80284ABC();
    return result;
}

/*
 * Critical-section wrapper around fn_80271954.
 *
 * EN v1.1 Address: 0x80272808, size 96b
 */
int fn_80272808(int a, int b, int c)
{
    int result;
    fn_80284AF4();
    result = fn_80271954(a, b, c);
    fn_80284ABC();
    return result;
}

/*
 * Critical-section wrapper around fn_80271AC0 (single-arg variant).
 *
 * EN v1.1 Address: 0x80272868, size 64b
 */
int fn_80272868(int a)
{
    int result;
    fn_80284AF4();
    result = fn_80271AC0(a);
    fn_80284ABC();
    return result;
}

/*
 * Critical-section wrapper plus 2D table u8 lookup.
 *
 * EN v1.1 Address: 0x802728A8, size 132b
 */
int fn_802728A8(int a, int b, int c, u8 d)
{
    int result;
    u8 e;
    fn_80284AF4();
    e = *(u8 *)(lbl_803BDA24 + d * 2 + 1);
    result = fn_802717B0(a, b, c, d, e);
    fn_80284ABC();
    return result;
}

/*
 * Map id → slot via fn_8027949C, returns -1 sentinel if not found,
 * else returns the input id.
 *
 * EN v1.1 Address: 0x8027292C, size 68b
 */
int fn_8027292C(u32 id)
{
    int slot;
    slot = fn_8027949C(id);
    if (slot == -1) {
        return -1;
    }
    return (int)id;
}

/*
 * Critical-section wrapper around fn_80271B4C with last 2 args set to
 * (0, -1).
 *
 * EN v1.1 Address: 0x80272970, size 96b
 */
void fn_80272970(int a, int b, int c)
{
    fn_80284AF4();
    fn_80271B4C(a, b, c, 0, -1);
    fn_80284ABC();
}

/*
 * Conditionally fire one or two events (codes 0x15, 0x16) under
 * critical section, skipping each if its u8 flag is zero.
 *
 * EN v1.1 Address: 0x802729D0, size 148b
 */
void fn_802729D0(int a, int b, u8 flag1, u8 flag2)
{
    fn_80284AF4();
    if (flag1 != 0) {
        fn_80271B4C(a, b, 0x15, 0, -1);
    }
    if (flag2 != 0) {
        fn_80271B4C(a, b, 0x16, 0, -1);
    }
    fn_80284ABC();
}

/*
 * Three-way HRTF-mode setter that toggles two bits in lbl_803DE264
 * and resets all voices' stream flags if the mask changed.
 *
 * EN v1.1 Address: 0x80272A64, size 248b
 */
void fn_80272A64(int mode)
{
    u32 oldFlags = lbl_803DE264;
    switch (mode) {
    case 0:
        lbl_803DE264 = (lbl_803DE264 | 0x1) & ~0x4;
        hwDisableHRTF();
        break;
    case 1:
        lbl_803DE264 = (lbl_803DE264 & ~0x1) & ~0x4;
        hwDisableHRTF();
        break;
    case 2:
        lbl_803DE264 = (lbl_803DE264 & ~0x1) | 0x2;
        hwDisableHRTF();
        break;
    }
    if (oldFlags != lbl_803DE264) {
        u32 i;
        for (i = 0; i < lbl_803BD150[0x210]; i++) {
            u32 *flags = (u32 *)(lbl_803DE268 + i * 0x404 + 0x114);
            flags[0] |= 0x2000;
        }
        fn_80273870();
    }
}

/*
 * fn_80272B5C — large fn ~360 bytes, complex routing. Stubbed.
 */
#pragma dont_inline on
void fn_80272B5C(int a, int b, int c, int d)
{
    (void)a; (void)b; (void)c; (void)d;
}
#pragma dont_inline reset

/*
 * Reset a slot's tracking state (clear two ptr arrays + 0xFF in two
 * byte arrays + zero in a third) and call hwActivateStudio.
 *
 * EN v1.1 Address: 0x80272CC4, size 176b
 */
void fn_80272CC4(u8 slot, int a, int b)
{
    fn_80284AF4();
    *(u32 *)(lbl_803BD9C4 + slot * 4) = 0;
    *(u32 *)(lbl_803BDA04 + slot * 4) = 0;
    lbl_803DE254[slot] = 0xff;
    lbl_803DE244[slot] = 0xff;
    *(u8 *)(lbl_803BDA24 + slot * 2 + 1) = 0;
    *(u8 *)(lbl_803BDA24 + slot * 2) = 0;
    hwActivateStudio(slot, a, b);
    fn_80284ABC();
}

/*
 * fn_80272D74 — large fn ~240 bytes, voice cleanup loop. Stubbed.
 */
#pragma dont_inline on
void fn_80272D74(u8 slot)
{
    (void)slot;
}
#pragma dont_inline reset

/*
 * Wrapper for hwAddInput.
 *
 * EN v1.1 Address: 0x80272E64, size 32b
 */
void fn_80272E64(u8 idx)
{
    hwAddInput(idx);
}

/*
 * Wrapper for hwRemoveInput.
 *
 * EN v1.1 Address: 0x80272E84, size 32b
 */
void fn_80272E84(u8 idx)
{
    hwRemoveInput(idx);
}
