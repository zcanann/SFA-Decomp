#include "src/audio/synth_internal.h"

#define SYNTH_FADE_COUNT 0x20
#define SYNTH_FADE_SELECTOR_ACTION_2 0xFA
#define SYNTH_FADE_SELECTOR_ACTION_3 0xFB
#define SYNTH_FADE_SELECTOR_ACTION_2_OR_3 0xFC
#define SYNTH_FADE_SELECTOR_ACTION_0 0xFD
#define SYNTH_FADE_SELECTOR_ACTION_1 0xFE
#define SYNTH_FADE_SELECTOR_ACTION_0_OR_1 0xFF
#define SYNTH_FADE_ACTION_DISABLED 4
#define SYNTH_INVALID_LINK_ID 0xFFFFFFFF
#define SYNTH_FADE_SCALE sSynthFadeScale
#define SYNTH_FADE_ONE sSynthFadeUnit
#define SYNTH_FADE_TIME_SCALE sSynthFadeTimeScale

#define SYNTH_APPLY_FADE(fade, fadeIndex, fadeHandle)      \
    do {                                                   \
        (fade)->delayAction = action;                      \
        (fade)->handle = (fadeHandle);                     \
                                                           \
        if (fadeTime != 0) {                               \
            (fade)->start = (fade)->current;               \
            (fade)->target = target;                       \
            (fade)->progress = SYNTH_FADE_ONE;             \
            (fade)->progressStep = SYNTH_FADE_TIME_SCALE / (f32)fadeTime; \
        } else {                                           \
            (fade)->target = target;                       \
            (fade)->current = target;                      \
                                                           \
            if ((fade)->handle != SYNTH_INVALID_LINK_ID) { \
                synthDispatchDelayedAction(fade);          \
            }                                              \
        }                                                  \
                                                           \
        gSynthFadeMask |= 1 << (fadeIndex);                \
    } while (0)

void synthCopyVoiceSlotMixState(SynthVoiceSlot* dst, SynthVoiceSlot* src) {
    synthCopyControllerValue(7, dst, src);
    synthCopyControllerValue(10, dst, src);
    synthCopyControllerValue(0x5B, dst, src);
    synthCopyControllerValue(0x80, dst, src);
    synthCopyControllerValue(0x84, dst, src);
}

s32 synthTriggerCallback(u32 callbackId) {
    u32 linkId;
    s32 handled;

    handled = 0;
    if (gSynthInitialized != 0) {
        for (linkId = synthLookupCallbackLinkId(callbackId); linkId != SYNTH_INVALID_LINK_ID;
             linkId = gSynthVoiceSlots[linkId & 0xFF].callbackNext) {
            SynthVoiceSlot* slot;

            slot = &gSynthVoiceSlots[linkId & 0xFF];
            if (linkId == slot->callbackLinkId) {
                synthReleaseVoiceSlot(slot);
                handled = 1;
            }
        }
    }

    return handled;
}

void synthSetFade(u8 value, u16 time, u8 selector, u8 action, u32 handle) {
    SynthFade* fadeTable;
    u32 fadeIndex;
    u32 fadeTime;
    u8 actionFilter;
    SynthFade* fade;
    f32 target;

    fadeTime = time;
    if (fadeTime != 0) {
        synthScaleFadeTime((s32*)&fadeTime);
    }

    fadeTable = gSynthFades;
    target = (f32)value * SYNTH_FADE_SCALE;

    if (selector == SYNTH_FADE_SELECTOR_ACTION_0_OR_1) {
apply_actions_0_or_1:
        fade = fadeTable;
        for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++) {
            if (fade->type == 0 || fade->type == 1) {
                SYNTH_APPLY_FADE(fade, fadeIndex, SYNTH_INVALID_LINK_ID);
            }
        }
        return;
    }

    if (selector == SYNTH_FADE_SELECTOR_ACTION_2_OR_3) {
apply_actions_2_or_3:
        fade = fadeTable;
        for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++) {
            if (fade->type == 2 || fade->type == 3) {
                SYNTH_APPLY_FADE(fade, fadeIndex, SYNTH_INVALID_LINK_ID);
            }
        }
        return;
    }

    if (selector == SYNTH_FADE_SELECTOR_ACTION_0) {
        actionFilter = 0;
    } else if (selector < SYNTH_FADE_SELECTOR_ACTION_0) {
        if (selector == SYNTH_FADE_SELECTOR_ACTION_3) {
            actionFilter = 3;
        } else if (selector >= SYNTH_FADE_SELECTOR_ACTION_2_OR_3) {
            goto apply_actions_2_or_3;
        } else if (selector >= SYNTH_FADE_SELECTOR_ACTION_2) {
            actionFilter = 2;
        } else {
            fade = &fadeTable[selector];
            SYNTH_APPLY_FADE(fade, selector, handle);
            return;
        }
    } else if (selector < SYNTH_FADE_SELECTOR_ACTION_0_OR_1) {
        actionFilter = 1;
    } else {
        fade = &fadeTable[selector];
        SYNTH_APPLY_FADE(fade, selector, handle);
        return;
    }

    fade = fadeTable;
    for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++) {
        if (fade->type == actionFilter) {
            SYNTH_APPLY_FADE(fade, fadeIndex, handle);
        }
    }
    return;
}

u32 synthIsFadeActive(u32 fadeIndex) {
    SynthFade* fade;
    u8 maskedFadeIndex;

    maskedFadeIndex = fadeIndex;
    fade = &gSynthFades[maskedFadeIndex];

    if (fade->type != SYNTH_FADE_ACTION_DISABLED) {
        if ((gSynthFadeMask & (1 << maskedFadeIndex)) != 0) {
            if (fade->target > fade->start) {
                return 1;
            }
        }
    }

    return 0;
}

void synthSetFadeAction(u32 fadeIndex, u8 action) {
    if (gSynthInitialized == 0) {
        return;
    }

    gSynthFades[fadeIndex & 0xFF].type = action;
}

#undef SYNTH_APPLY_FADE
