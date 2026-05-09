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
extern void audioFn_80271178(SynthDelayedNode *fade, int mode, u32 delay);
extern void fn_8026D0C4(u32 handle);
extern void fn_8026D278(u32 handle);
extern void fn_8026D630(u32 handle, u32 mixValue0, u32 mixValue1);
extern void fn_80278418(u32 delta);
extern u8 hwGetTimeOffset(void);
extern u16 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
extern u16 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
extern void hwFrameDone(void);
extern u8 lbl_803BCD90[];
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

extern u8 *dataGetKeymap(u32 sampleId);
extern u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
extern int audioFn_8026f630(u32 key, u32 slot, u32 channel, u32 voiceGroup, u32 *outFlags);
extern int audioLayerFn_8026f8b8(u32 sampleId, int key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                       u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11,
                       u32 param_12, u32 param_13, u32 param_14, u32 param_15, u32 param_16);
extern int audioFn_80278b94(u32 sampleId, int key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                       u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11,
                       u32 param_12, u32 param_13, u32 param_14, u32 param_15, u32 param_16);
extern u32 vidGetInternalId(u32 handle);

/*
 * Resolve an indirection-table sample entry, then dispatch the resolved
 * sample or nested sample group.
 */
int audioKeymapFn_8026fc8c(u32 sampleId, s16 key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11, u32 param_12,
                u32 param_13, u32 param_14, u32 param_15, u32 param_16)
{
    u8 *table;
    u8 *entry;
    u16 resolvedSample;
    u32 adjustedPan;
    s32 adjustedKey;
    u32 allow;
    int handle;
    u32 outFlags;

    table = dataGetKeymap(sampleId);
    if (table != 0) {
        entry = table + ((flags & 0x7f) * 8);
        if (*(s16 *)entry != -1) {
            resolvedSample = *(u16 *)entry;
            if ((resolvedSample & 0xc000) != 0x4000) {
                if ((entry[3] & 0x80) == 0) {
                    adjustedPan = (entry[3] - 0x40) + (pan & 0xff);
                    if ((s32)adjustedPan < 0) {
                        adjustedPan = 0;
                    } else if ((s32)adjustedPan < 0x80) {
                        adjustedPan &= 0xff;
                    } else {
                        adjustedPan = 0x7f;
                    }
                } else {
                    adjustedPan = 0x80;
                }
                adjustedKey = (flags & 0x7f) + *(s8 *)(entry + 2);
                if (adjustedKey >= 0x80) {
                    adjustedKey = 0x7f;
                } else if (adjustedKey < 0) {
                    adjustedKey = 0;
                }
                key = key + *(s16 *)(entry + 4);
                if (key >= 0x100) {
                    key = 0xff;
                } else if (key < 0) {
                    key = 0;
                }
                if ((resolvedSample & 0xc000) == 0) {
                    if ((u16)inpGetMidiCtrl(0x41, param_8, param_9) < 0x1f81) {
                        handle = -1;
                        allow = 1;
                    } else {
                        handle = audioFn_8026f630(adjustedKey & 0x7f, param_8, param_9, param_13,
                                             &outFlags);
                        allow = __cntlzw(outFlags) >> 5;
                    }
                    if (allow == 0) {
                        return -1;
                    }
                    if (handle != -1) {
                        return handle;
                    }
                    return audioFn_80278b94(resolvedSample, key & 0xff, velocity, baseSample,
                                       adjustedKey | (flags & 0x80), volume, adjustedPan, param_8,
                                       param_9, param_10, param_11, param_12, param_13 & 0xff,
                                       param_14, param_15, param_16);
                }
                return audioLayerFn_8026f8b8(resolvedSample, key, velocity, baseSample,
                                   adjustedKey | (flags & 0x80), volume, adjustedPan, param_8,
                                   param_9, param_10, param_11, param_12, param_13 & 0xff,
                                   param_14, param_15, param_16);
            }
        }
    }
    return -1;
}

/*
 * Start a sample/FX id, handling direct samples, table-expanded sample
 * groups, and already-linked voice chains.
 */
int audioFn_8026feec(u32 sampleId, u8 key, u8 velocity, u32 flags, u32 volume, u32 pan, u32 param_7,
                u32 param_8, u32 param_9, u32 param_10, u32 param_11, u8 auxIndex, u32 param_13,
                u32 studio, u8 studioAux)
{
    u32 sampleClass;
    int handle;
    u32 voice;
    u8 *slot;
    u32 outFlags;

    key = key + param_13;
    sampleClass = sampleId & 0xc000;
    if (sampleClass == 0x4000) {
        handle = audioKeymapFn_8026fc8c(sampleId, key, velocity, sampleId, flags, volume, pan, param_7,
                             param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                             studioAux);
        if (handle != -1) {
            voice = vidGetInternalId(handle);
            while (voice != 0xffffffff) {
                slot = lbl_803DE268 + ((voice & 0xff) * 0x404);
                slot[0x11c] = 0;
                voice = *(u32 *)(slot + 0xec);
            }
        }
    } else {
        if (sampleClass == 0) {
            if ((u16)inpGetMidiCtrl(0x41, param_7, param_8) < 0x1f81) {
                handle = -1;
                sampleClass = 1;
            } else {
                handle = audioFn_8026f630(flags & 0x7f, param_7, param_8, 1, &outFlags);
                sampleClass = __cntlzw(outFlags) >> 5;
            }
            if (sampleClass == 0) {
                return -1;
            }
            if (handle != -1) {
                return handle;
            }
            return audioFn_80278b94(sampleId, key, velocity, sampleId, flags, volume, pan, param_7,
                               param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                               studioAux);
        }
        if (sampleClass == 0x8000) {
            handle = audioLayerFn_8026f8b8(sampleId, key, velocity, sampleId, flags, volume, pan, param_7,
                                 param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                                 studioAux);
            if (handle == -1) {
                return -1;
            }
            voice = vidGetInternalId(handle);
            while (voice != 0xffffffff) {
                slot = lbl_803DE268 + ((voice & 0xff) * 0x404);
                slot[0x11c] = 0;
                voice = *(u32 *)(slot + 0xec);
            }
            return handle;
        }
        handle = -1;
    }
    return handle;
}

/*
 * audioFn_80270184 - large voice handler (~1972 instructions). Stubbed.
 */
#pragma dont_inline on
void audioFn_80270184(int idx) { (void)idx; }
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
void audioFn_80271178(SynthDelayedNode *fade, int mode, u32 delay)
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
    audioFn_80271178(fade, 0, 0);
    audioFn_80271178(fade, 1, 0);
}

/*
 * Advance both channels (modes 0 and 1) of the handle.
 *
 * EN v1.1 Address: 0x8027132C, size 68b
 */
void audioFn_8027132c(SynthDelayedNode *fade)
{
    audioFn_80271178(fade, 0, 0);
    audioFn_80271178(fade, 1, 0);
}

/*
 * Wrapper for audioFn_80271178(handle, 2, 0).
 *
 * EN v1.1 Address: 0x80271370, size 40b
 */
void fn_80271370(SynthDelayedNode *fade)
{
    audioFn_80271178(fade, 2, 0);
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
void audioFn_80271498(u32 delta)
{
    u8 *stateBase;
    SynthDelayStorageLocal *storage;
    u32 bucket;
    u32 fadeIndex;
    u32 mask;
    f32 *fade;
    f32 zeroThreshold;
    f32 fadeDelta;
    u32 i;
    u32 channel;
    u16 auxSamplesA[8];
    u16 auxSamplesB[6];

    stateBase = lbl_803BCD90;
    if (*(u32 *)(stateBase + 0x3c4) != 0) {
        storage = (SynthDelayStorageLocal *)stateBase;
        fn_80278418(delta);
        bucket = gSynthDelayBucketCursor;
        fn_80271398((void **)&storage->bucketHeads[bucket][0], audioFn_80270184);
        fn_80271398((void **)&storage->bucketHeads[bucket][1], fn_80270FE8);
        fn_80271398((void **)&storage->bucketHeads[bucket][2], fn_80270938);
        gSynthDelayBucketCursor = (gSynthDelayBucketCursor + 1) & 0x1f;
        if (hwGetTimeOffset() == 0) {
            if ((lbl_803DE260 | lbl_803DE25C) != 0) {
                zeroThreshold = lbl_803E77D0;
                fade = (f32 *)(stateBase + 0x5d4);
                mask = 1;
                for (fadeIndex = 0; fadeIndex < 0x20; fadeIndex++) {
                    if ((lbl_803DE260 & mask) != 0) {
                        fadeDelta = fade[3] * (fade[1] - fade[2]);
                        fade[0] = fade[1] - fadeDelta;
                        fade[3] = fade[3] - fade[4];
                        if (fade[3] <= zeroThreshold) {
                            fade[0] = fade[1];
                            fn_8027142C((u8 *)fade);
                            lbl_803DE260 &= ~mask;
                            if ((lbl_803DE260 == 0) && (lbl_803DE25C == 0)) {
                                break;
                            }
                        }
                    }
                    if ((lbl_803DE25C & mask) != 0) {
                        fadeDelta = fade[8] * (fade[6] - fade[7]);
                        fade[5] = fade[6] - fadeDelta;
                        fade[8] = fade[8] - fade[9];
                        if (fade[8] <= zeroThreshold) {
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
                            inpGetAuxA(i & 0xff, channel & 0xff, (&lbl_803DE254)[i],
                                         (&lbl_803DE24C)[i]);
                    }
                    (*(SynthAuxCallback *)(stateBase + 0xc34 + i * 4))(
                        1, auxSamplesA, *(u32 *)(stateBase + 0xc14 + i * 4));
                }
                if ((&lbl_803DE244)[i] != 0xff) {
                    for (channel = 0; channel < 4; channel++) {
                        auxSamplesB[channel] =
                            inpGetAuxB(i & 0xff, channel & 0xff, (&lbl_803DE244)[i],
                                         (&lbl_803DE23C)[i]);
                    }
                    (*(SynthAuxCallback *)(stateBase + 0xc74 + i * 4))(
                        1, auxSamplesB, *(u32 *)(stateBase + 0xc54 + i * 4));
                }
            }
        }
        hwFrameDone();
        {
            u32 carry = CARRY4(lbl_803DE27C, delta);
            lbl_803DE27C += delta;
            lbl_803DE278 += carry;
        }
    }
}

/*
 * audioGetSfxFn_802717b0 - voice handler (~188 instructions). Stubbed.
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

extern SynthFxSampleInfo *audioGetSoundEffectById(u32 fxId);

int audioGetSfxFn_802717b0(u32 fxId, u32 volume, u32 pan, u32 studio, u8 studioAux)
{
    SynthFxSampleInfo *sampleInfo;
    u32 handle;

    handle = 0xFFFFFFFF;
    sampleInfo = audioGetSoundEffectById(fxId);
    if (sampleInfo != (SynthFxSampleInfo *)0x0) {
        if ((volume & 0xff) == 0xff) {
            volume = sampleInfo->defaultVolume;
        }
        if ((pan & 0xff) == 0xff) {
            pan = sampleInfo->defaultPan;
        }
        handle = audioFn_8026feec(sampleInfo->sampleId, sampleInfo->key, sampleInfo->velocity,
                             sampleInfo->flags | 0x80, volume, pan, 0xff, 0xff, 0, 0, 0xff,
                             sampleInfo->auxIndex, 0, studio, studioAux);
    }
    return handle;
}
