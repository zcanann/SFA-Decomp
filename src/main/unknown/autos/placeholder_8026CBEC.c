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

/*
 * fn_8026D0C4 — voice cleanup with callbacks (~436 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D0C4(int handle)
{
    (void)handle;
}
#pragma dont_inline reset

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
