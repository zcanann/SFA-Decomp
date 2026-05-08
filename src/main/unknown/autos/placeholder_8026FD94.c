#include "ghidra_import.h"

typedef struct SynthDelayedNode {
    struct SynthDelayedNode *next;
    struct SynthDelayedNode *prev;
    u8 voiceIndex;
    u8 bucketIndex;
    u8 pad[2];
} SynthDelayedNode;

typedef struct SynthDelayStorageLocal {
    u32 studioChannelScales[9][0x10];
    SynthDelayedNode *bucketHeads[0x20][3];
} SynthDelayStorageLocal;

extern SynthDelayStorageLocal gSynthDelayStorage;
extern u8 gSynthDelayBucketCursor;
extern void fn_80271178(SynthDelayedNode *fade, int mode, u32 delay);
extern void fn_8026D0C4(u32 handle);
extern void fn_8026D278(u32 handle);
extern void fn_8026D630(u32 handle, u32 mixValue0, u32 mixValue1);
extern void fn_80278418(u32 delta);
extern int fn_8028324C(void);
extern u16 fn_80282858(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
extern u16 fn_80282914(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
extern void fn_80283F34(void);
extern u8 gSynthInitialized;
extern u8 lbl_803BD364[];
extern u8 lbl_803BD9A4[];
extern u8 lbl_803BD9C4[];
extern u8 lbl_803BD9E4[];
extern u8 lbl_803BDA04[];
extern u32 lbl_803DE25C;
extern u32 lbl_803DE260;
extern u8 lbl_803DE23C;
extern u8 lbl_803DE244;
extern u8 lbl_803DE24C;
extern u8 lbl_803DE254;
extern u8 *lbl_803DE268;
extern int lbl_803DE278;
extern int lbl_803DE27C;
extern f32 lbl_803E77D0;

typedef void (*SynthAuxCallback)(int active, u16 *samples, u32 user);

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
void fn_80270184(int idx) { (void)idx; }
#pragma dont_inline reset

/*
 * fn_80270938 - large voice handler (~1712 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270938(int idx) { (void)idx; }
#pragma dont_inline reset

/*
 * fn_80270FE8 - voice handler (~400 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80270FE8(int idx) { (void)idx; }
#pragma dont_inline reset

/*
 * Queue one of a fade's embedded delayed-action nodes into the 32-bucket
 * scheduler ring.
 *
 * EN v1.1 Address: 0x80271178, size 336b
 */
void fn_80271178(SynthDelayedNode *fade, int mode, u32 delay)
{
    u32 bucket;
    SynthDelayStorageLocal *storage;
    SynthDelayedNode *node;
    SynthDelayedNode **head;

    bucket = gSynthDelayBucketCursor + (delay >> 8);
    bucket &= 0x1f;
    storage = &gSynthDelayStorage;
    head = &storage->bucketHeads[bucket][0];
    switch (mode) {
    case 0:
        node = fade;
        if (node->bucketIndex != 0xff) {
            if (node->bucketIndex == bucket) {
                return;
            }
            if (node->next != 0) {
                node->next->prev = node->prev;
            }
            if (node->prev == 0) {
                storage->bucketHeads[node->bucketIndex][0] = node->next;
            } else {
                node->prev->next = node->next;
            }
        }
        break;
    case 1:
        node = fade + 1;
        if (node->bucketIndex != 0xff) {
            if (node->bucketIndex == bucket) {
                return;
            }
            if (node->next != 0) {
                node->next->prev = node->prev;
            }
            if (node->prev == 0) {
                storage->bucketHeads[node->bucketIndex][2] = node->next;
            } else {
                node->prev->next = node->next;
            }
        }
        head = &storage->bucketHeads[bucket][2];
        break;
    case 2:
        node = fade + 2;
        if (node->bucketIndex != 0xff) {
            return;
        }
        head = &storage->bucketHeads[bucket][1];
        break;
    default:
        return;
    }
    node->bucketIndex = bucket;
    node->next = *head;
    if (*head != 0) {
        (*head)->prev = node;
    }
    node->prev = 0;
    *head = node;
}

/*
 * Reset four pos/timer fields on the handle, then advance both
 * channels (modes 0 and 1).
 *
 * EN v1.1 Address: 0x802712C8, size 100b
 */
void fn_802712C8(SynthDelayedNode *fade)
{
    {
        int a = lbl_803DE278;
        int b = lbl_803DE27C;
        *(int *)((u8 *)fade + 0x24) = a;
        *(int *)((u8 *)fade + 0x28) = b;
    }
    {
        int a = lbl_803DE278;
        int b = lbl_803DE27C;
        *(int *)((u8 *)fade + 0x2c) = a;
        *(int *)((u8 *)fade + 0x30) = b;
    }
    fn_80271178(fade, 0, 0);
    fn_80271178(fade, 1, 0);
}

/*
 * Advance both channels (modes 0 and 1) of the handle.
 *
 * EN v1.1 Address: 0x8027132C, size 68b
 */
void fn_8027132C(SynthDelayedNode *fade)
{
    fn_80271178(fade, 0, 0);
    fn_80271178(fade, 1, 0);
}

/*
 * Wrapper for fn_80271178(handle, 2, 0).
 *
 * EN v1.1 Address: 0x80271370, size 40b
 */
void fn_80271370(SynthDelayedNode *fade)
{
    fn_80271178(fade, 2, 0);
}

/*
 * Walk a voice linked-list, marking each entry's slot 9 as 0xff and
 * invoking the callback for entries whose voice's 0x11c field is 0.
 *
 * EN v1.1 Address: 0x80271398, size 148b
 */
#pragma dont_inline on
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
#pragma dont_inline reset

/*
 * Dispatch a completed fade action based on its type byte.
 *
 * EN v1.1 Address: 0x8027142C, size 108b
 */
void fn_8027142C(u8 *fade)
{
    u8 action;

    action = fade[0x2c];
    switch (action) {
    case 1:
        fn_8026D278(*(u32 *)(fade + 0x28));
        break;
    case 2:
        fn_8026D0C4(*(u32 *)(fade + 0x28));
        break;
    case 3:
        fn_8026D630(*(u32 *)(fade + 0x28), 0, 0);
        break;
    }
}

/*
 * Periodic synth tick: drains delayed-action buckets, advances fade ramps,
 * runs AUX callbacks, and advances the global synth timer.
 *
 * EN v1.1 Address: 0x80271498, size 792b
 */
void fn_80271498(u32 delta)
{
    u32 bucket;
    u32 fadeIndex;
    u32 mask;
    f32 *fade;
    u32 i;
    u32 channel;
    u16 auxSamplesA[8];
    u16 auxSamplesB[6];

    if (gSynthInitialized != 0) {
        fn_80278418(delta);
        bucket = gSynthDelayBucketCursor;
        fn_80271398((void **)&gSynthDelayStorage.bucketHeads[bucket][0], fn_80270184);
        fn_80271398((void **)&gSynthDelayStorage.bucketHeads[bucket][1], fn_80270FE8);
        fn_80271398((void **)&gSynthDelayStorage.bucketHeads[bucket][2], fn_80270938);
        gSynthDelayBucketCursor = (gSynthDelayBucketCursor + 1) & 0x1f;
        if (fn_8028324C() == 0) {
            if ((lbl_803DE260 | lbl_803DE25C) != 0) {
                fade = (f32 *)lbl_803BD364;
                mask = 1;
                for (fadeIndex = 0; fadeIndex < 0x20; fadeIndex++) {
                    if ((lbl_803DE260 & mask) != 0) {
                        fade[0] = fade[1] - fade[3] * (fade[1] - fade[2]);
                        fade[3] = fade[3] - fade[4];
                        if (fade[3] <= lbl_803E77D0) {
                            fade[0] = fade[1];
                            fn_8027142C((u8 *)fade);
                            lbl_803DE260 &= ~mask;
                            if ((lbl_803DE260 == 0) && (lbl_803DE25C == 0)) {
                                break;
                            }
                        }
                    }
                    if ((lbl_803DE25C & mask) != 0) {
                        fade[5] = fade[6] - fade[8] * (fade[6] - fade[7]);
                        fade[8] = fade[8] - fade[9];
                        if (fade[8] <= lbl_803E77D0) {
                            fade[5] = fade[6];
                            lbl_803DE25C &= ~mask;
                            if ((lbl_803DE25C == 0) && (lbl_803DE260 == 0)) {
                                break;
                            }
                        }
                    }
                    mask <<= 1;
                    fade += 12;
                }
            }
            for (i = 0; i < 8; i++) {
                if ((&lbl_803DE254)[i] != 0xff) {
                    for (channel = 0; channel < 4; channel++) {
                        auxSamplesA[channel] =
                            fn_80282858(i & 0xff, channel & 0xff, (&lbl_803DE254)[i],
                                         (&lbl_803DE24C)[i]);
                    }
                    (*(SynthAuxCallback *)(lbl_803BD9C4 + i * 4))(1, auxSamplesA,
                                                                   *(u32 *)(lbl_803BD9A4 + i * 4));
                }
                if ((&lbl_803DE244)[i] != 0xff) {
                    for (channel = 0; channel < 4; channel++) {
                        auxSamplesB[channel] =
                            fn_80282914(i & 0xff, channel & 0xff, (&lbl_803DE244)[i],
                                         (&lbl_803DE23C)[i]);
                    }
                    (*(SynthAuxCallback *)(lbl_803BDA04 + i * 4))(1, auxSamplesB,
                                                                   *(u32 *)(lbl_803BD9E4 + i * 4));
                }
            }
        }
        fn_80283F34();
        {
            u32 oldLo = lbl_803DE27C;
            lbl_803DE27C += delta;
            lbl_803DE278 += (lbl_803DE27C < oldLo);
        }
    }
}

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
