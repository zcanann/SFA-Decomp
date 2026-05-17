#include "ghidra_import.h"

extern void *memset(void *dst, int val, u32 n);
extern void DCFlushRangeNoSync(void *p, u32 n);
extern void salFree(int p);

extern u8 *dspCmdBuffer;
extern u8 *dspVoice;
extern u8 *dspITDBuffer;
extern u8 *dspSurround;
extern u8 *dspCmdList;
extern u8 lbl_803CC1E0[][0xbc];
extern u8 salMaxStudioNum;
extern u8 salNumVoices;

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
    memset(dspCmdBuffer, 0, 0x100);
    DCFlushRangeNoSync(dspCmdBuffer, 0x100);
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
    salFree((int)dspCmdBuffer);
    offset = 0;
    for (i = 0; (u8)i < salNumVoices; i++) {
        salFree(*(int *)(dspVoice + offset));
        salFree(*(int *)(dspVoice + offset + 4));
        offset += 0xf4;
    }
    for (i = 0; (u8)i < salMaxStudioNum; i++) {
        salFree(*(int *)(&lbl_803CC1E0[i][0]));
        salFree(*(int *)(&lbl_803CC1E0[i][0x28]));
    }
    salFree((int)dspITDBuffer);
    salFree((int)dspVoice);
    salFree((int)dspSurround);
    salFree((int)dspCmdList);
    return 1;
}

/*
 * fn_8027BEBC - voice-buffer init with several memset/flush calls
 * (~264 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027BEBC(u8 idx, u8 a, int b)
{
    u8 *studio;
    u32 idx8;

    idx8 = idx;
    studio = lbl_803CC1E0[idx8];

    memset(*(void **)(studio + 0x28), 0, 0x3c00);
    DCFlushRangeNoSync(*(void **)(studio + 0x28), 0x3c00);

    memset(*(void **)(studio + 0x00), 0, 0x36);
    *(u32 *)(studio + 0x0c) = 0;
    *(u32 *)(studio + 0x08) = 0;
    *(u32 *)(studio + 0x04) = 0;
    *(u32 *)(studio + 0x18) = 0;
    *(u32 *)(studio + 0x14) = 0;
    *(u32 *)(studio + 0x10) = 0;
    *(u32 *)(studio + 0x24) = 0;
    *(u32 *)(studio + 0x20) = 0;
    *(u32 *)(studio + 0x1c) = 0;
    DCFlushRangeNoSync(*(void **)(studio + 0x00), 0x36);

    memset(*(void **)(studio + 0x30), 0, 0x780);
    DCFlushRangeNoSync(*(void **)(studio + 0x30), 0x780);

    memset(*(void **)(studio + 0x3c), 0, 0x780);
    DCFlushRangeNoSync(*(void **)(studio + 0x3c), 0x780);

    *(u32 *)(studio + 0x48) = 0;
    *(u32 *)(studio + 0x4c) = 0;
    studio[0x50] = 1;
    studio[0x51] = a;
    studio[0x52] = 0;
    *(u32 *)(studio + 0x54) = b;
    *(u32 *)(studio + 0xb0) = 0;
    *(u32 *)(studio + 0xac) = 0;
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
int fn_8027BFE4(u16 *active, u16 *direction, u16 *current, u16 target, u16 *stepFlags, u16 mask)
{
    int delta;
    int step;

    if (target != *current) {
        delta = (s16)target - (s16)*current;
        delta = (s16)delta;
        if ((delta >= 0x20) && (delta < 0xa0)) {
            step = (s16)(delta >> 5);
            if (step < 5) {
                stepFlags[step] |= mask;
            }
            *direction = 1;
            *current += step << 5;
            return 1;
        }
        if ((delta <= -0x20) && (delta > -0xa0)) {
            step = (s16)(-delta >> 5);
            if (step < 5) {
                stepFlags[step] |= mask;
            }
            *direction = 0xffff;
            *current -= step << 5;
            return 1;
        }
        if ((target == 0) && (delta > -0x20)) {
            *current = 0;
            *active = 0;
        }
    }
    *direction = 0;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_8027C0D8 - large voice param updater (~696 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027C0D8(int accum, int *voiceRef)
{
    int value;
    int clamped;
    int voice;

    *(u8 *)((int)voiceRef + 0xed) = 0;
    clamped = 0x7fffff;
    *(u16 *)(*voiceRef + 0xe) = 0;
    voice = *voiceRef;

    *(int *)(accum + 4) += *(s16 *)(voice + 0x52);
    value = *(int *)(accum + 4);
    if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
        clamped = -0x7fffff;
    }
    *(int *)(accum + 4) = clamped;

    clamped = 0x7fffff;
    *(int *)(accum + 8) += *(s16 *)(voice + 0x58);
    value = *(int *)(accum + 8);
    if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
        clamped = -0x7fffff;
    }
    *(int *)(accum + 8) = clamped;

    if ((*(u16 *)(voice + 0xc) & 4) != 0) {
        clamped = 0x7fffff;
        *(int *)(accum + 0xc) += *(s16 *)(voice + 0x5e);
        value = *(int *)(accum + 0xc);
        if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
            clamped = -0x7fffff;
        }
        *(int *)(accum + 0xc) = clamped;
    }

    if ((*(u16 *)(voice + 0xc) & 1) != 0) {
        clamped = 0x7fffff;
        *(int *)(accum + 0x10) += *(s16 *)(voice + 0x54);
        value = *(int *)(accum + 0x10);
        if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
            clamped = -0x7fffff;
        }
        *(int *)(accum + 0x10) = clamped;

        clamped = 0x7fffff;
        *(int *)(accum + 0x14) += *(s16 *)(voice + 0x5a);
        value = *(int *)(accum + 0x14);
        if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
            clamped = -0x7fffff;
        }
        *(int *)(accum + 0x14) = clamped;

        if ((*(u16 *)(voice + 0xc) & 0x14) != 0) {
            clamped = 0x7fffff;
            *(int *)(accum + 0x18) += *(s16 *)(voice + 0x60);
            value = *(int *)(accum + 0x18);
            if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
                clamped = -0x7fffff;
            }
            *(int *)(accum + 0x18) = clamped;
        }
    }

    if ((*(u16 *)(voice + 0xc) & 0x12) != 0) {
        clamped = 0x7fffff;
        *(int *)(accum + 0x1c) += *(s16 *)(voice + 0x56);
        value = *(int *)(accum + 0x1c);
        if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
            clamped = -0x7fffff;
        }
        *(int *)(accum + 0x1c) = clamped;

        clamped = 0x7fffff;
        *(int *)(accum + 0x20) += *(s16 *)(voice + 0x5c);
        value = *(int *)(accum + 0x20);
        if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
            clamped = -0x7fffff;
        }
        *(int *)(accum + 0x20) = clamped;

        if ((*(u16 *)(voice + 0xc) & 4) != 0) {
            clamped = 0x7fffff;
            *(int *)(accum + 0x24) += *(s16 *)(voice + 0x62);
            value = *(int *)(accum + 0x24);
            if ((value < 0x800000) && (clamped = value, value < -0x7fffff)) {
                clamped = -0x7fffff;
            }
            *(int *)(accum + 0x24) = clamped;
        }
    }
}
#pragma dont_inline reset

/*
 * fn_8027C390 - large voice routing (~252 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027C390(int *items, int left, int right)
{
    int pivot;
    int middle;
    int scanCount;
    int *leftPtr;
    int *scanPtr;
    int *swapPtr;
    int split;
    u32 midpoint;

    if (left < right) {
        midpoint = left + right;
        leftPtr = items + left;
        pivot = *leftPtr;
        swapPtr = items + (((int)midpoint >> 1) + ((int)midpoint < 0 && (midpoint & 1) != 0));
        middle = left + 1;
        *leftPtr = *swapPtr;
        scanCount = (right + 1) - middle;
        *swapPtr = pivot;
        scanPtr = items + middle;
        swapPtr = leftPtr;
        split = left;
        if (middle <= right) {
            do {
                if (*(u32 *)(*scanPtr + 0x1c) < *(u32 *)(*leftPtr + 0x1c)) {
                    pivot = swapPtr[1];
                    split++;
                    swapPtr++;
                    *swapPtr = *scanPtr;
                    *scanPtr = pivot;
                }
                scanPtr++;
                scanCount--;
            } while (scanCount != 0);
        }
        pivot = *leftPtr;
        swapPtr = items + split;
        *leftPtr = *swapPtr;
        *swapPtr = pivot;
        fn_8027C390(items, left, split - 1);
        fn_8027C390(items, split + 1, right);
    }
}
#pragma dont_inline reset
