#include "ghidra_import.h"
#include "main/audio/synth_virtual_sample.h"
#include "main/unknown/autos/placeholder_80271BFC.h"

extern void voiceKill(u8 voiceIdx);
extern void macSampleEndNotify(void);
extern u32 hwGetVirtualSampleID(int slot);
extern void sndConvertMs(u32 *p);

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD364[];
extern u8 gSynthInitialized;
extern u32 synthMasterFaderActiveFlags;
extern u8 *synthVoice;
extern f32 lbl_803E7798;
extern f32 lbl_803E77A8;
extern f32 lbl_803E77D4;

#define SYNTH_FADE_COUNT 0x20
#define SYNTH_FADE_TABLE_OFFSET 0x5d4
#define SYNTH_FADE_SELECTOR_ACTION_2 0xfa
#define SYNTH_FADE_SELECTOR_ACTION_3 0xfb
#define SYNTH_FADE_SELECTOR_ACTION_0 0xfd
#define SYNTH_FADE_SELECTOR_ACTION_1 0xfe
#define SYNTH_FADE_SELECTOR_ACTION_0_OR_1 0xff
#define SYNTH_FADE_TYPE_ACTION_0 0
#define SYNTH_FADE_TYPE_ACTION_1 1
#define SYNTH_FADE_TYPE_ACTION_2 2
#define SYNTH_FADE_TYPE_ACTION_3 3
#define SYNTH_FADE_ACTION_DISABLED 4
#define SYNTH_INVALID_LINK_ID 0xffffffff
#define SYNTH_VOICE_SLOT_SIZE 0x404

typedef struct SynthFade {
    f32 current;
    f32 target;
    f32 start;
    f32 progress;
    f32 progressStep;
    f32 auxCurrent;
    f32 auxTarget;
    f32 auxStart;
    f32 auxProgress;
    f32 auxProgressStep;
    u32 handle;
    u8 delayAction;
    u8 type;
    u8 pad[2];
} SynthFade;

extern void synthDispatchFadeAction(SynthFade *fade);

/*
 * Route synth fade commands to one slot or to the broadcast pseudo-slots
 * 0xfa through 0xff.
 */
void synthVolume(u32 volume, u32 timeMs, u32 target, u8 action, u32 handle)
{
    u32 convertedTime;
    u32 targetIndex;
    u32 i;
    u32 matchState;
    f32 targetVolume;
    f32 fadePos;
    f32 fadeStepBase;
    u8 *stateBase;
    SynthFade *fade;

    stateBase = lbl_803BCD90;
    if ((convertedTime = timeMs & 0xffff) != 0) {
        sndConvertMs(&convertedTime);
    }

    targetIndex = target & 0xff;
    if (targetIndex == SYNTH_FADE_SELECTOR_ACTION_0) {
        matchState = SYNTH_FADE_TYPE_ACTION_0;
    } else if (targetIndex < SYNTH_FADE_SELECTOR_ACTION_0) {
        if (targetIndex == SYNTH_FADE_SELECTOR_ACTION_3) {
            matchState = SYNTH_FADE_TYPE_ACTION_3;
        } else {
            if (targetIndex > SYNTH_FADE_SELECTOR_ACTION_2) {
                targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
                fadePos = lbl_803E77A8;
                fadeStepBase = lbl_803E77D4;
                fade = (SynthFade *)(stateBase + SYNTH_FADE_TABLE_OFFSET);
                for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++) {
                    if ((fade->type == SYNTH_FADE_TYPE_ACTION_2) ||
                        (fade->type == SYNTH_FADE_TYPE_ACTION_3)) {
                        fade->delayAction = action;
                        fade->handle = SYNTH_INVALID_LINK_ID;
                        if (convertedTime != 0) {
                            fade->start = fade->current;
                            fade->target = targetVolume;
                            fade->progress = fadePos;
                            fade->progressStep = fadeStepBase / (f32)convertedTime;
                        } else {
                            fade->target = targetVolume;
                            fade->current = targetVolume;
                            if (fade->handle != SYNTH_INVALID_LINK_ID) {
                                synthDispatchFadeAction(fade);
                            }
                        }
                        synthMasterFaderActiveFlags |= 1U << i;
                    }
                }
                return;
            }
            if (targetIndex < SYNTH_FADE_SELECTOR_ACTION_2) {
                goto single_slot;
            }
            matchState = SYNTH_FADE_TYPE_ACTION_2;
        }
    } else {
        if (targetIndex == SYNTH_FADE_SELECTOR_ACTION_0_OR_1) {
            targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
            fadePos = lbl_803E77A8;
            fadeStepBase = lbl_803E77D4;
            fade = (SynthFade *)(stateBase + SYNTH_FADE_TABLE_OFFSET);
            for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++) {
                if ((fade->type == SYNTH_FADE_TYPE_ACTION_0) ||
                    (fade->type == SYNTH_FADE_TYPE_ACTION_1)) {
                    fade->delayAction = action;
                    fade->handle = SYNTH_INVALID_LINK_ID;
                    if (convertedTime != 0) {
                        fade->start = fade->current;
                        fade->target = targetVolume;
                        fade->progress = fadePos;
                        fade->progressStep = fadeStepBase / (f32)convertedTime;
                    } else {
                        fade->target = targetVolume;
                        fade->current = targetVolume;
                        if (fade->handle != SYNTH_INVALID_LINK_ID) {
                            synthDispatchFadeAction(fade);
                        }
                    }
                    synthMasterFaderActiveFlags |= 1U << i;
                }
            }
            return;
        }
        if (targetIndex > SYNTH_FADE_SELECTOR_ACTION_1) {
            goto single_slot;
        }
        matchState = SYNTH_FADE_TYPE_ACTION_1;
    }

    targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
    fadePos = lbl_803E77A8;
    fadeStepBase = lbl_803E77D4;
    fade = (SynthFade *)(stateBase + SYNTH_FADE_TABLE_OFFSET);
    for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++) {
        if (fade->type == matchState) {
            fade->delayAction = action;
            fade->handle = SYNTH_INVALID_LINK_ID;
            if (convertedTime != 0) {
                fade->start = fade->current;
                fade->target = targetVolume;
                fade->progress = fadePos;
                fade->progressStep = fadeStepBase / (f32)convertedTime;
            } else {
                fade->target = targetVolume;
                fade->current = targetVolume;
                if (fade->handle != SYNTH_INVALID_LINK_ID) {
                    synthDispatchFadeAction(fade);
                }
            }
            synthMasterFaderActiveFlags |= 1U << i;
        }
    }
    return;

single_slot:
    fade = (SynthFade *)(stateBase + SYNTH_FADE_TABLE_OFFSET + targetIndex * sizeof(SynthFade));
    fade->delayAction = action;
    fade->handle = handle;
    if (convertedTime != 0) {
        fade->start = fade->current;
        fade->target = lbl_803E7798 * (f32)(volume & 0xff);
        fade->progress = lbl_803E77A8;
        fade->progressStep = lbl_803E77D4 / (f32)convertedTime;
    } else {
        targetVolume = lbl_803E7798 * (f32)(volume & 0xff);
        fade->target = targetVolume;
        fade->current = targetVolume;
        if (fade->handle != SYNTH_INVALID_LINK_ID) {
            synthDispatchFadeAction(fade);
        }
    }
    synthMasterFaderActiveFlags |= 1U << targetIndex;
}

/*
 * Voice "is loud" predicate: returns 1 if voice is active (state != 4),
 * the global active mask has its bit set, AND its current volume
 * (offset 0x5dc) > target volume (offset 0x5d8). Otherwise 0.
 *
 * EN v1.0 Address: 0x80271970
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80271F5C
 * EN v1.1 Size: 84b
 */
int synthIsFadeOutActive(u8 voiceIdx)
{
    u8 *v = lbl_803BCD90 + voiceIdx * sizeof(SynthFade);
    if (((v[SYNTH_FADE_TABLE_OFFSET + 0x2d] != SYNTH_FADE_ACTION_DISABLED) &&
         ((synthMasterFaderActiveFlags & (1U << voiceIdx)) != 0)) &&
        (*(f32 *)(v + SYNTH_FADE_TABLE_OFFSET + 8) >
         *(f32 *)(v + SYNTH_FADE_TABLE_OFFSET + 4))) {
        return 1;
    }
    return 0;
}

/*
 * Set a single byte field on a voice slot.
 *
 * EN v1.1 Address: 0x80271FB0
 * EN v1.1 Size: 40b
 */
void synthSetMusicVolumeType(u32 voiceIdx, u8 value)
{
    if (gSynthInitialized == 0) {
        return;
    }
    ((SynthFade *)lbl_803BD364)[voiceIdx & 0xff].type = value;
}

/*
 * Voice command dispatcher: runs different actions per command code.
 *   0 -> validate current sample and mark the slot active
 *   1 -> voiceKill
 *   2 -> claim virtual sample slot
 *   3 -> simple vacate via hwGetVirtualSampleID + synthHandleVirtualSampleDone
 *
 * EN v1.0 Address: 0x802719B0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80271FD8
 * EN v1.1 Size: 204b
 */
int synthHWMessageHandler(int mode, u32 arg)
{
    u32 result = 0;

    switch (mode) {
    case 0: {
        u8 *entry;
        u32 offset;
        offset = (arg & 0xff) * SYNTH_VOICE_SLOT_SIZE;
        entry = synthVoice + offset;
        if (entry[0x11c] != 0) {
            break;
        }
        synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
        entry = synthVoice + offset;
        if (arg != *(u32 *)(entry + 0xf4)) {
            break;
        }
        macSampleEndNotify();
        break;
    }
    case 1:
        voiceKill(arg & 0xff);
        break;
    case 2:
        result = synthClaimVirtualSampleSlot(arg & 0xff);
        break;
    case 3: {
        synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
        break;
    }
    }
    return result;
}
