#include "ghidra_import.h"

extern int hwTransAddr(int x);

/*
 * fn_80273D2C - large voice/instrument lookup (~584 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80273D2C(void) {}
#pragma dont_inline reset

/*
 * fn_80273F74 - voice handler (~460 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80273F74(void) {}
#pragma dont_inline reset

/*
 * fn_80274140 - voice handler (~504 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274140(void) {}
#pragma dont_inline reset

/*
 * fn_80274338 - voice handler (~388 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274338(void) {}
#pragma dont_inline reset

/*
 * audioLoadSdiFile - voice handler (~364 instructions). Stubbed.
 */
#pragma dont_inline on
void audioLoadSdiFile(void) {}
#pragma dont_inline reset

/*
 * fn_80274628 - voice handler (~216 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274628(void) {}
#pragma dont_inline reset

/*
 * fn_80274700 - voice handler (~152 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274700(void) {}
#pragma dont_inline reset

/*
 * fn_80274798 - voice handler (~296 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80274798(void) {}
#pragma dont_inline reset

/*
 * fn_802748C0 - voice handler (~784 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_802748C0(void) {}
#pragma dont_inline reset

/*
 * fn_80274BD0 - voice handler (~668 instructions). Stubbed.
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
 * fn_80274E7C - table lookup helper (~148 instructions). Stubbed.
 */
extern void *sndBSearch(void *key, void *base, u16 count, u32 stride,
                        int (*cmp)(void *a, void *b));
extern u8 lbl_803C5678[];
extern u32 lbl_803DE294;
extern u32 lbl_803DE298;
extern u8 lbl_803DE29C[];
extern void *lbl_803DE2A4;

void *fn_80274E7C(u32 key)
{
    u16 *bucketTable;

    bucketTable = (u16 *)lbl_803C5678;
    lbl_803DE298 = (key >> 6) & 0x3ff;
    if (bucketTable[lbl_803DE298 * 2] != 0) {
        lbl_803DE294 = bucketTable[lbl_803DE298 * 2 + 1];
        *(u16 *)(lbl_803DE29C + 4) = key;
        lbl_803DE2A4 =
            sndBSearch(lbl_803DE29C, lbl_803C5678 + 0x800 + lbl_803DE294 * 8,
                       bucketTable[lbl_803DE298 * 2], 8, fn_80274E6C);
        if (lbl_803DE2A4 != 0) {
            return *(void **)lbl_803DE2A4;
        }
    }
    return 0;
}

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
 * fn_80274F20 - voice find/copy (~296 instructions). Stubbed.
 */
extern u8 lbl_803BFC78[];
extern u16 lbl_803DE288;
extern void *lbl_803DE2A8;
extern u8 *lbl_803DE2AC;

int fn_80274F20(u16 key, u32 *out)
{
    u32 i;
    u32 *bucket;
    u8 *entry;
    u8 *searchKey;

    i = 0;
    bucket = (u32 *)lbl_803BFC78;
    searchKey = lbl_803C5678 + 0x4c00;
    *(u16 *)searchKey = key;
    while (i < lbl_803DE288) {
        lbl_803DE2A8 = sndBSearch(searchKey, (void *)*bucket, *(u16 *)(bucket + 2), 0x20,
                                  fn_80274F10);
        entry = lbl_803DE2A8;
        if ((entry != 0) && (*(s16 *)(entry + 2) != -1)) {
            lbl_803DE2AC = entry + 0xc;
            out[0] = *(u32 *)lbl_803DE2AC;
            out[1] = *(u32 *)(entry + 8);
            out[3] = 0;
            out[5] = *(u32 *)(lbl_803DE2AC + 8);
            out[4] = *(u32 *)(lbl_803DE2AC + 4) & 0xffffff;
            out[6] = *(u32 *)(lbl_803DE2AC + 0xc);
            *(u8 *)(out + 7) = *(u32 *)(lbl_803DE2AC + 4) >> 0x18;
            if (*(int *)(entry + 0x1c) != 0) {
                out[2] = *(int *)(entry + 0x1c) + *bucket;
            }
            return 0;
        }
        bucket += 3;
        i++;
    }
    return -1;
}

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
 * Look up a keygroup/sample indirection table by id.
 */
extern void *sndBSearch(void *key, void *base, u16 count, u32 stride,
                        int (*cmp)(void *a, void *b));
extern u8 lbl_803C0278[];
extern u8 lbl_803C4278[];
extern u8 lbl_803C5678[];
extern u16 lbl_803DE28A;
extern u16 lbl_803DE28C;
extern u16 lbl_803DE28E;
extern u16 lbl_803DE292;
extern u8 lbl_803DE2B0[];
extern void *lbl_803DE2B8;
extern u8 lbl_803DE2BC[];
extern void *lbl_803DE2C4;
extern void *lbl_803DE2C8;

void *fn_80275058(u16 key)
{
    *(u16 *)(lbl_803DE2B0 + 4) = key;
    lbl_803DE2B8 = sndBSearch(lbl_803DE2B0, lbl_803C0278, lbl_803DE28A, 8, fn_80275048);
    if (lbl_803DE2B8 == 0) {
        return 0;
    }
    return *(void **)lbl_803DE2B8;
}

/*
 * Look up the sample-map table used by nested sample groups.
 */
void *fn_802750B8(u16 key)
{
    *(u16 *)(lbl_803DE2BC + 4) = key;
    lbl_803DE2C4 = sndBSearch(lbl_803DE2BC, lbl_803C4278, lbl_803DE28C, 8, fn_80275048);
    if (lbl_803DE2C4 == 0) {
        return 0;
    }
    return *(void **)lbl_803DE2C4;
}

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
 * Look up a scene/sample list and return its entry count through outCount.
 */
void *fn_80275128(u16 key, u16 *outCount)
{
    u8 *searchKey = lbl_803C5678 + 0x4c20;

    *(u16 *)(searchKey + 4) = key;
    lbl_803DE2C8 =
        sndBSearch(searchKey, lbl_803C4278 + 0x800, lbl_803DE28E, 0xc, fn_80275118);
    if (lbl_803DE2C8 == 0) {
        return 0;
    }
    *outCount = *(u16 *)((u8 *)lbl_803DE2C8 + 6);
    return *(void **)lbl_803DE2C8;
}

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
 * Search each FX sample-list bucket for the requested FX id.
 */
void *fn_802751B8(u16 key)
{
    u32 i;
    u16 *bucket;
    void *entry;
    u8 *searchKey;

    i = 0;
    bucket = (u16 *)(lbl_803C5678 + 0x4800);
    searchKey = lbl_803C5678 + 0x4c2c;
    *(u16 *)searchKey = key;
    while (i < lbl_803DE292) {
        entry = sndBSearch(searchKey, *(void **)(bucket + 2), bucket[1], 10, fn_802751A8);
        if (entry != 0) {
            return entry;
        }
        bucket += 4;
        i++;
    }
    return 0;
}

/*
 * fn_80275260 - handler (~228 instructions). Stubbed.
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
