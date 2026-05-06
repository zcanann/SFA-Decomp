#include "ghidra_import.h"

extern u32 hwIsActive(u32 voice);
extern void hwBreak(u32 voice);
extern void fn_80279038(int handle);
extern void fn_80279B98(int handle);
extern u32 fn_80279004(u32 id);
extern void fn_802737EC(u8 voice);

extern u8 *lbl_803DE268;
extern u8 gSynthInitialized;
extern u8 lbl_803CAB50[];
extern u8 lbl_803CAAD0[][16];

/*
 * fn_80279C7C — large voice/slot table init (~204 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80279C7C(void) {}
#pragma dont_inline reset

/*
 * Voice cleanup: if voice handle is valid, break the active voice and
 * reset its id slot.
 *
 * EN v1.1 Address: 0x80279FAC, size 128b
 */
void fn_80279FAC(u32 voice)
{
    if (voice == 0xffffffff) return;
    if (hwIsActive(voice) != 0) {
        hwBreak(voice);
    }
    *(u32 *)(lbl_803DE268 + voice * 0x404 + 0xf4) = voice;
    fn_80279B98((int)(lbl_803DE268 + voice * 0x404));
    *(u8 *)(lbl_803DE268 + voice * 0x404 + 0x11c) = 0;
}

/*
 * Voice teardown: clears state flags then breaks the voice.
 *
 * EN v1.1 Address: 0x8027A02C, size 160b
 */
void fn_8027A02C(u32 voice)
{
    int base = (int)(lbl_803DE268 + voice * 0x404);
    if (*(u32 *)(base + 0x34) != 0) {
        fn_80279038(base);
        *(u32 *)(base + 0x118) = *(u32 *)(base + 0x118) & ~3;
        *(u32 *)(base + 0x114) = *(u32 *)(base + 0x114) & ~0;
        *(u32 *)(base + 0x110) = 0;
        fn_80279B98(base);
    }
    if (*(u8 *)(base + 0x11c) != 0) {
        fn_802737EC((u8)voice);
    }
    hwBreak(voice);
}

/*
 * Walk the synth's voice list for the given id, breaking each match.
 * Returns 0 if at least one match was broken, else -1.
 *
 * EN v1.1 Address: 0x8027A0CC, size 272b
 */
int fn_8027A0CC(u32 id)
{
    int result = -1;
    u32 next;
    if (gSynthInitialized == 0) return result;

    if (id == 0xffffffff) {
        next = 0xffffffff;
    } else {
        u32 s = fn_80279004(id);
        if (s == 0) {
            next = 0xffffffff;
        } else {
            next = *(u32 *)(s + 0xc);
        }
    }

    while (next != 0xffffffff) {
        u8 v = (u8)next;
        int handle = (int)(lbl_803DE268 + v * 0x404);
        u32 chain = *(u32 *)(handle + 0xec);
        if (next == *(u32 *)(handle + 0xf4)) {
            if (*(u32 *)(handle + 0x34) != 0) {
                fn_80279038(handle);
                *(u32 *)(handle + 0x118) = *(u32 *)(handle + 0x118) & ~3;
                *(u32 *)(handle + 0x114) = *(u32 *)(handle + 0x114) & ~0;
                *(u32 *)(handle + 0x110) = 0;
                fn_80279B98(handle);
            }
            if (*(u8 *)(handle + 0x11c) != 0) {
                fn_802737EC(v);
            }
            hwBreak(v);
            result = 0;
        }
        next = chain;
    }

    return result;
}

/*
 * Returns 1 if state's voice id is currently registered in the
 * appropriate slot table, else 0.
 *
 * EN v1.1 Address: 0x8027A1DC, size 124b
 */
int fn_8027A1DC(int state)
{
    u32 voice = *(u32 *)(state + 0xf4);
    u8 a;
    u8 b;
    u8 v;
    if (voice == 0xffffffff) goto fail;
    a = *(u8 *)(state + 0x121);
    if (a == 0xff) goto fail;
    b = *(u8 *)(state + 0x122);
    v = (u8)voice;
    if (b == 0xff) {
        if (lbl_803CAB50[v] == v) return 1;
        goto fail;
    }
    if (v == lbl_803CAAD0[b][a]) return 1;
fail:
    return 0;
}

/*
 * Register the state's voice id in either the 1D or 2D slot table.
 *
 * EN v1.1 Address: 0x8027A258, size 92b
 */
void fn_8027A258(int state)
{
    u32 voice = *(u32 *)(state + 0xf4);
    u8 a;
    u8 b;
    u8 v;
    if (voice == 0xffffffff) return;
    a = *(u8 *)(state + 0x121);
    if (a == 0xff) return;
    b = *(u8 *)(state + 0x122);
    v = (u8)voice;
    if (b == 0xff) {
        lbl_803CAB50[v] = v;
    } else {
        lbl_803CAAD0[b][a] = v;
    }
}
