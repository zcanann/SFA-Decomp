#include "ghidra_import.h"

extern int gSynthQueuedVoices;
extern int gSynthAllocatedVoices;

/*
 * fn_8026C488 — large voice scheduler (~2800 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8026C488(int a, int b)
{
    (void)a; (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_8026CF78 — voice unlink helper (~232 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026CF78(u8 idx)
{
    (void)idx;
}
#pragma dont_inline reset

/*
 * Move a voice node from the queued list to the head of the allocated
 * list and mark it active.
 *
 * EN v1.1 Address: 0x8026D060, size 100b
 */
void fn_8026D060(int node)
{
    if (*(int *)(node + 4) != 0) {
        *(int *)(*(int *)(node + 4) + 0) = *(int *)(node + 0);
    } else {
        gSynthQueuedVoices = *(int *)(node + 0);
    }
    if (*(int *)(node + 0) != 0) {
        *(int *)(*(int *)(node + 0) + 4) = *(int *)(node + 4);
    }
    *(int *)(node + 0) = gSynthAllocatedVoices;
    if (gSynthAllocatedVoices != 0) {
        *(int *)(gSynthAllocatedVoices + 4) = node;
    }
    *(int *)(node + 4) = 0;
    gSynthAllocatedVoices = node;
    *(u8 *)(node + 8) = 2;
}

extern u8 gSynthVoices[];
extern void fn_8027A0CC(int p);
extern void synthRecycleVoiceCallbacks(int voice);

/*
 * fn_8026D0C4 — voice handle lookup + cleanup with callbacks.
 *
 * EN v1.0 Address: 0x8026D0C4
 * EN v1.0 Size: 436b
 */
void fn_8026D0C4(int handle)
{
    u32 key;
    int found;
    int i;

    key = (u32)handle & 0x7fffffffu;

    found = gSynthQueuedVoices;
    while (found != 0) {
        if ((u32)*(int *)((u8 *)found + 0xc) == key) {
            found = *(u8 *)((u8 *)found + 9) | (handle & 0x80000000);
            goto done;
        }
        found = *(int *)found;
    }

    found = gSynthAllocatedVoices;
    while (found != 0) {
        if ((u32)*(int *)((u8 *)found + 0xc) == key) {
            found = *(u8 *)((u8 *)found + 9) | (handle & 0x80000000);
            goto done;
        }
        found = *(int *)found;
    }
    found = -1;
done:

    if ((u32)(found + 1) == 0xffff) return;

    if ((found & 0x80000000) == 0) {
        u8 *voice = gSynthVoices + found * 0x1868;
        if (*(u8 *)(voice + 8) != 1) return;

        /* Unlink from queued list */
        if (*(int *)(voice + 4) != 0) {
            *(int *)(*(int *)(voice + 4) + 0) = *(int *)(voice + 0);
        } else {
            gSynthQueuedVoices = *(int *)(voice + 0);
        }
        if (*(int *)(voice + 0) != 0) {
            *(int *)(*(int *)(voice + 0) + 4) = *(int *)(voice + 4);
        }

        /* Push to allocated list head */
        *(int *)(voice + 0) = gSynthAllocatedVoices;
        if (gSynthAllocatedVoices != 0) {
            *(int *)(gSynthAllocatedVoices + 4) = (int)voice;
        }
        *(int *)(voice + 4) = 0;
        gSynthAllocatedVoices = (int)voice;
        *(u8 *)(voice + 8) = 2;

        /* Walk two callback lists */
        {
            u8 *base = voice;
            for (i = 0; i < 2; i++) {
                int *cb = *(int **)(base + 0xe64);
                while (cb != 0) {
                    fn_8027A0CC(*(int *)((u8 *)cb + 8));
                    cb = (int *)*cb;
                }
                base += 4;
            }
        }
        {
            int *cb2 = *(int **)(voice + 0xe6c);
            while (cb2 != 0) {
                fn_8027A0CC(*(int *)((u8 *)cb2 + 8));
                cb2 = (int *)*cb2;
            }
        }
        synthRecycleVoiceCallbacks((int)voice);
    } else {
        u32 idx = (u32)found & 0x7fffffffu;
        u8 *voice = gSynthVoices + idx * 0x1868;
        if (*(u8 *)(voice + 8) == 0) return;
        *(u8 *)(voice + 0xeda) |= 8;
    }
}

/*
 * fn_8026D278 — voice search and modify (~464 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D278(int handle, int args)
{
    (void)handle; (void)args;
}
#pragma dont_inline reset

/*
 * fn_8026D448 — voice flag setter (~220 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D448(int handle, int args)
{
    (void)handle; (void)args;
}
#pragma dont_inline reset

/*
 * fn_8026D524 — voice param multi-set (~268 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D524(int handle, int a, int b, int c)
{
    (void)handle; (void)a; (void)b; (void)c;
}
#pragma dont_inline reset
