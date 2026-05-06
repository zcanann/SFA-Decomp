#include "ghidra_import.h"

extern int hwTransAddr(int x);

/*
 * fn_80273D2C — large voice/instrument lookup (~584 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80273D2C(void) {}
#pragma dont_inline reset

/*
 * fn_80273F74 — voice handler (~460 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80273F74(void) {}
#pragma dont_inline reset

/*
 * fn_80274140 — voice handler (~504 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274140(void) {}
#pragma dont_inline reset

/*
 * fn_80274338 — voice handler (~388 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274338(void) {}
#pragma dont_inline reset

/*
 * audioLoadSdiFile — voice handler (~364 instructions). Stubbed.
 */
#pragma dont_inline on
void audioLoadSdiFile(void) {}
#pragma dont_inline reset

/*
 * fn_80274628 — voice handler (~216 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274628(void) {}
#pragma dont_inline reset

/*
 * fn_80274700 — voice handler (~152 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274700(void) {}
#pragma dont_inline reset

/*
 * fn_80274798 — voice handler (~296 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274798(void) {}
#pragma dont_inline reset

/*
 * fn_802748C0 — voice handler (~784 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_802748C0(void) {}
#pragma dont_inline reset

/*
 * fn_80274BD0 — voice handler (~668 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274BD0(void) {}
#pragma dont_inline reset

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4).
 *
 * EN v1.1 Address: 0x80274E6C, size 16b
 */
int fn_80274E6C(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * fn_80274E7C — table lookup helper (~148 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80274E7C(int key)
{
    (void)key;
    return 0;
}
#pragma dont_inline reset

/*
 * Comparator: return a->key - b->key (u16 at offset 0).
 *
 * EN v1.1 Address: 0x80274F10, size 16b
 */
int fn_80274F10(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * fn_80274F20 — voice find/copy (~296 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80274F20(int a, int b)
{
    (void)a; (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * fn_80274E6C but separate symbol used for a different bsearch table.
 *
 * EN v1.1 Address: 0x80275048, size 16b
 */
int fn_80275048(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * fn_80275058 — bsearch wrapper (~96 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80275058(int key)
{
    (void)key;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_802750B8 — bsearch wrapper (~96 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_802750B8(int key)
{
    (void)key;
    return 0;
}
#pragma dont_inline reset

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * the others but separate symbol.
 *
 * EN v1.1 Address: 0x80275118, size 16b
 */
int fn_80275118(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * fn_80275128 — bsearch wrapper (~128 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80275128(int key, u16 *out)
{
    (void)key; (void)out;
    return 0;
}
#pragma dont_inline reset

/*
 * Comparator: return a->key - b->key (u16 at offset 0). Same body as
 * fn_80274F10 but separate symbol.
 *
 * EN v1.1 Address: 0x802751A8, size 16b
 */
int fn_802751A8(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * fn_802751B8 — linear search (~168 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_802751B8(int key)
{
    (void)key;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_80275260 — handler (~228 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_80275260(int a, int b)
{
    (void)a; (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * Wrapper for hwTransAddr.
 *
 * EN v1.1 Address: 0x80275344, size 32b
 */
int fn_80275344(int x)
{
    return hwTransAddr(x);
}
