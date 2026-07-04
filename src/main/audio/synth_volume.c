#include "main/dll/synthfade_struct.h"
#include "main/audio/inp_ctrl.h"
#include "main/audio/voice_manage.h"

extern void macSampleEndNotify(void);
extern u32 hwGetVirtualSampleID(int slot);
extern u8 lbl_803BCD90[];
u8 lbl_803BD364[0x600];
extern u8 gSynthInitialized;
extern u32 synthMasterFaderActiveFlags;
extern u8* synthVoice;
extern f32 lbl_803E7798;
extern f32 lbl_803E77A8;
extern f32 lbl_803E77D4;

#define SYNTH_FADE_COUNT 0x20
#define SYNTH_FADE_TABLE_OFFSET 0x5d4
#define SYNTH_FADE_SELECTOR_ACTION_2 0xfa
#define SYNTH_FADE_SELECTOR_ACTION_2_OR_3 0xfc
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

extern void synthDispatchFadeAction(SynthFade* fade);

/*
 * Route synth fade commands to one slot or to the broadcast pseudo-slots
 * 0xfa through 0xff.
 */
void synthVolume(u8 volume, u16 timeMs, u8 target, u8 action, u32 handle)
{
    u32 convertedTime;
    u32 i;
    u8 matchState;
    f32 targetVolume;
    f32 fadeStepBase;
    f32 fadePos;
    u8* stateBase;
    SynthFade* fade;

    stateBase = lbl_803BCD90;
    if ((convertedTime = timeMs) != 0)
    {
        sndConvertMs(&convertedTime);
    }

    switch (target)
    {
    case SYNTH_FADE_SELECTOR_ACTION_0_OR_1:
        fadePos = lbl_803E77A8;
        fadeStepBase = lbl_803E77D4;
        targetVolume = lbl_803E7798 * volume;
        fade = (SynthFade*)(stateBase + SYNTH_FADE_TABLE_OFFSET);
        for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++)
        {
            if (fade->type == SYNTH_FADE_TYPE_ACTION_0 ||
                fade->type == SYNTH_FADE_TYPE_ACTION_1)
            {
                u32 fadeTime = convertedTime;
                fade->delayAction = action;
                fade->handle = SYNTH_INVALID_LINK_ID;
                if (fadeTime != 0)
                {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->progress = fadePos;
                    fade->progressStep = fadeStepBase / fadeTime;
                }
                else
                {
                    fade->current = fade->target = targetVolume;
                    if (fade->handle != SYNTH_INVALID_LINK_ID)
                    {
                        synthDispatchFadeAction(fade);
                    }
                }
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    case SYNTH_FADE_SELECTOR_ACTION_2_OR_3:
        fadePos = lbl_803E77A8;
        fadeStepBase = lbl_803E77D4;
        targetVolume = lbl_803E7798 * volume;
        fade = (SynthFade*)(stateBase + SYNTH_FADE_TABLE_OFFSET);
        for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++)
        {
            if (fade->type == SYNTH_FADE_TYPE_ACTION_2 ||
                fade->type == SYNTH_FADE_TYPE_ACTION_3)
            {
                u32 fadeTime = convertedTime;
                fade->delayAction = action;
                fade->handle = SYNTH_INVALID_LINK_ID;
                if (fadeTime != 0)
                {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->progress = fadePos;
                    fade->progressStep = fadeStepBase / fadeTime;
                }
                else
                {
                    fade->current = fade->target = targetVolume;
                    if (fade->handle != SYNTH_INVALID_LINK_ID)
                    {
                        synthDispatchFadeAction(fade);
                    }
                }
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    case SYNTH_FADE_SELECTOR_ACTION_2:
        matchState = SYNTH_FADE_TYPE_ACTION_2;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_3:
        matchState = SYNTH_FADE_TYPE_ACTION_3;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_0:
        matchState = SYNTH_FADE_TYPE_ACTION_0;
        goto setup_type;

    case SYNTH_FADE_SELECTOR_ACTION_1:
        matchState = SYNTH_FADE_TYPE_ACTION_1;

    setup_type:
        fadePos = lbl_803E77A8;
        fadeStepBase = lbl_803E77D4;
        targetVolume = lbl_803E7798 * volume;
        fade = (SynthFade*)(stateBase + SYNTH_FADE_TABLE_OFFSET);
        for (i = 0; i < SYNTH_FADE_COUNT; i++, fade++)
        {
            if (fade->type == matchState)
            {
                u32 fadeTime = convertedTime;
                fade->delayAction = action;
                fade->handle = SYNTH_INVALID_LINK_ID;
                if (fadeTime != 0)
                {
                    fade->start = fade->current;
                    fade->target = targetVolume;
                    fade->progress = fadePos;
                    fade->progressStep = fadeStepBase / fadeTime;
                }
                else
                {
                    fade->current = fade->target = targetVolume;
                    if (fade->handle != SYNTH_INVALID_LINK_ID)
                    {
                        synthDispatchFadeAction(fade);
                    }
                }
                synthMasterFaderActiveFlags |= 1U << i;
            }
        }
        return;

    default:
        {
            u32 fadeTime = convertedTime;
            fade = (SynthFade*)(stateBase + SYNTH_FADE_TABLE_OFFSET) + target;
            fade->delayAction = action;
            fade->handle = handle;
            if (fadeTime != 0)
            {
                fade->start = fade->current;
                fade->target = lbl_803E7798 * volume;
                fade->progress = lbl_803E77A8;
                fade->progressStep = lbl_803E77D4 / fadeTime;
            }
            else
            {
                fade->current = fade->target = lbl_803E7798 * volume;
                if (fade->handle != SYNTH_INVALID_LINK_ID)
                {
                    synthDispatchFadeAction(fade);
                }
            }
            synthMasterFaderActiveFlags |= 1U << target;
            return;
        }
    }
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
    u8* v = lbl_803BCD90 + voiceIdx * sizeof(SynthFade);
    if (((v[SYNTH_FADE_TABLE_OFFSET + 0x2d] != SYNTH_FADE_ACTION_DISABLED) &&
            ((synthMasterFaderActiveFlags & (1U << voiceIdx)) != 0)) &&
        (*(f32*)(v + SYNTH_FADE_TABLE_OFFSET + 8) >
            *(f32*)(v + SYNTH_FADE_TABLE_OFFSET + 4)))
    {
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
    if (gSynthInitialized == 0)
    {
        return;
    }
    lbl_803BD364[(voiceIdx & 0xff) * sizeof(SynthFade) + 0x2d] = value;
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

    switch (mode)
    {
    case 0:
        {
            if (*((synthVoice + 0x11c) + (arg & 0xff) * SYNTH_VOICE_STRIDE) != 0)
            {
                break;
            }
            synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
            if (arg != *(u32*)((u8*)(synthVoice + 0xf4) + (arg & 0xff) * SYNTH_VOICE_STRIDE))
            {
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
    case 3:
        {
            synthHandleVirtualSampleDone(hwGetVirtualSampleID(arg & 0xff));
            break;
        }
    }
    return result;
}
