#include "ghidra_import.h"

extern int fn_80271178(int handle, int mode, int flag);
extern u8 *lbl_803DE268;
extern int lbl_803DE278;
extern int lbl_803DE27C;

/*
 * fn_8026FC8C - voice handler (~608 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026FC8C(void) {}
#pragma dont_inline reset

/*
 * fn_8026FEEC - voice handler (~664 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8026FEEC(u32 sampleId, u8 key, u8 velocity, u32 flags, u32 volume, u32 pan, u32 param_7,
                u32 param_8, u32 param_9, u32 param_10, u32 param_11, u8 auxIndex, u32 param_13,
                u32 studio, u8 studioAux)
{
    (void)sampleId;
    (void)key;
    (void)velocity;
    (void)flags;
    (void)volume;
    (void)pan;
    (void)param_7;
    (void)param_8;
    (void)param_9;
    (void)param_10;
    (void)param_11;
    (void)auxIndex;
    (void)param_13;
    (void)studio;
    (void)studioAux;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_80270184 - large voice handler (~1972 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270184(void) {}
#pragma dont_inline reset

/*
 * fn_80270938 - large voice handler (~1712 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270938(void) {}
#pragma dont_inline reset

/*
 * fn_80270FE8 - voice handler (~400 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270FE8(void) {}
#pragma dont_inline reset

/*
 * fn_80271178 - internal helper used by the wrappers below (~336
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
void fn_80271398(void **head, void (*cb)(int idx))
{
    void *cur = *head;
    while (cur != 0) {
        void *next = *(void **)cur;
        *(u8 *)((u8 *)cur + 0x9) = 0xff;
        {
            int idx = *(u8 *)((u8 *)cur + 0x8);
            if (*(u8 *)(lbl_803DE268 + idx * 0x404 + 0x11c) == 0) {
                cb(idx);
            }
        }
        cur = next;
    }
    *head = 0;
}

/*
 * fn_8027142C - list-walker variant (~108 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027142C(void) {}
#pragma dont_inline reset

/*
 * fn_80271498 - list-walker variant (~792 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80271498(void) {}
#pragma dont_inline reset

/*
 * fn_802717B0 - voice handler (~188 instructions). Stubbed.
 */
typedef struct SynthFxSampleInfo {
    u8 pad00[2];
    u16 sampleId;
    u8 velocity;
    u8 key;
    u8 defaultVolume;
    u8 defaultPan;
    u8 flags;
    u8 auxIndex;
} SynthFxSampleInfo;

extern SynthFxSampleInfo *fn_802751B8(u32 fxId);

int fn_802717B0(u32 fxId, u32 volume, u32 pan, u32 studio, u8 studioAux)
{
    SynthFxSampleInfo *sampleInfo;
    u32 handle;

    handle = 0xFFFFFFFF;
    sampleInfo = fn_802751B8(fxId);
    if (sampleInfo != (SynthFxSampleInfo *)0x0) {
        if ((volume & 0xff) == 0xff) {
            volume = sampleInfo->defaultVolume;
        }
        if ((pan & 0xff) == 0xff) {
            pan = sampleInfo->defaultPan;
        }
        handle = fn_8026FEEC(sampleInfo->sampleId, sampleInfo->key, sampleInfo->velocity,
                             sampleInfo->flags | 0x80, volume, pan, 0xff, 0xff, 0, 0, 0xff,
                             sampleInfo->auxIndex, 0, studio, studioAux);
    }
    return handle;
}
