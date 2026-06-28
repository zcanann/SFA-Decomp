#include "src/main/audio/synth_internal.h"

#ifndef SYNTH_VOICE_STRIDE
#define SYNTH_VOICE_STRIDE 0x404
#endif

/*
 * Scalar fields of the global synth state block (lbl_803BCD90) named for
 * readability. Only the constant-offset scalars are modelled here; the
 * fade table, delay-bucket ring, and aux arrays are still addressed raw
 * off the byte base. Used via inline cast so the base stays a u8*.
 */
typedef struct SynthGlobalState
{
    u8 pad000[0x200];
    u32 dspDmaSize;
    u8 pad204[0x1bc];
    u32 sampleRate;
    u8 pad3c4[0x600];
    f32 auxMixA;
    u8 pad9c8[0x2c];
    f32 auxMixB;
    u8 pad9f8[0x1d9];
    u8 initialized;
    u8 padbd2[0xc34 - 0xbd2];
    u32 auxASend[8];
    u8 padc54[0xc74 - 0xc54];
    u32 auxBSend[8];
    u8 auxPairState[8][2];
    u32 auxMixSlot[16];
} SynthGlobalState;

/* global.h is incompatible here (u32 = unsigned long vs unsigned int), so
 * pin the field offsets with self-contained compile-time checks. */
#define SYNTH_CTRL_OFFSETOF(t, m) ((u32) & (((t*)0)->m))
typedef char synth_ctrl_assert_dspDmaSize[SYNTH_CTRL_OFFSETOF(SynthGlobalState, dspDmaSize) == 0x200 ? 1 : -1];
typedef char synth_ctrl_assert_sampleRate[SYNTH_CTRL_OFFSETOF(SynthGlobalState, sampleRate) == 0x3c0 ? 1 : -1];
typedef char synth_ctrl_assert_auxMixA[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxMixA) == 0x9c4 ? 1 : -1];
typedef char synth_ctrl_assert_auxMixB[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxMixB) == 0x9f4 ? 1 : -1];
typedef char synth_ctrl_assert_initialized[SYNTH_CTRL_OFFSETOF(SynthGlobalState, initialized) == 0xbd1 ? 1 : -1];
typedef char synth_ctrl_assert_auxASend[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxASend) == 0xc34 ? 1 : -1];
typedef char synth_ctrl_assert_auxBSend[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxBSend) == 0xc74 ? 1 : -1];
typedef char synth_ctrl_assert_auxPairState[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxPairState) == 0xc94 ? 1 : -1];
typedef char synth_ctrl_assert_auxMixSlot[SYNTH_CTRL_OFFSETOF(SynthGlobalState, auxMixSlot) == 0xca4 ? 1 : -1];

#define SYNTH_FADE_SCALE sSynthFadeScale
#define SYNTH_FADE_ONE sSynthFadeUnit
#define SYNTH_FADE_TIME_SCALE sSynthFadeTimeScale

extern void* salMalloc(u32 size);
extern void memset(void* dst, int value, u32 size);
extern void inpInit(void);
extern void macInit(void);
extern void vidInit(void);
extern void voiceInitPriorityTables(void);
extern void voiceInitRegistrationTables(void);
extern void synthHWMessageHandler(void);

extern u8 lbl_803BCD90[];
extern u32 synthRealTimeLo;
extern u32 synthRealTimeHi;
extern u32 synthFlags;
extern u32 synthMessageCallback;
extern u32 synthMasterFaderActiveFlags;
extern u32 synthMasterFaderPauseActiveFlags;
extern u8* synthVoice;
extern u8 synthAuxAIndex[8];
extern u8 synthAuxBIndex[8];
extern f32 lbl_803E77D0;
extern f32 lbl_803E77A8;

#define SYNTH_APPLY_FADE(fade, fadeIndex, fadeHandle)      \
    do {                                                   \
        (fade)->delayAction = action;                      \
        (fade)->handle = (fadeHandle);                     \
                                                           \
        if (fadeTime != 0) {                               \
            (fade)->start = (fade)->current;               \
            (fade)->target = target;                       \
            (fade)->progress = SYNTH_FADE_ONE;             \
            (fade)->progressStep = SYNTH_FADE_TIME_SCALE / fadeTime; \
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

extern void sndBegin(void);
extern void sndEnd(void);
extern void salFree(void* ptr);

void synthInit(u32 sampleRate, u32 voiceCount)
{
    u8* state;
    u32 voiceIndex;
    u32 voiceOffset;
    u32 fadeIndex;
    u32 auxIndex;
    u32* delayBucket;

    state = lbl_803BCD90;
    voiceOffset = 0;
    synthRealTimeLo = 0;
    synthRealTimeHi = 0;
    ((SynthGlobalState*)state)->sampleRate = sampleRate;
    ((SynthGlobalState*)state)->dspDmaSize = 0x1800;
    synthFlags = 0;
    synthMessageCallback = 0;

    synthVoice = salMalloc(voiceCount * SYNTH_VOICE_STRIDE);
    memset(synthVoice, 0, voiceCount * SYNTH_VOICE_STRIDE);

    for (voiceIndex = 0; voiceIndex < voiceCount; voiceIndex++, voiceOffset += SYNTH_VOICE_STRIDE)
    {
        u8 lowIndex;

        lowIndex = voiceIndex;
        *(u32*)(synthVoice + voiceOffset + 0xF4) = SYNTH_INVALID_LINK_ID;
        *(u32*)(synthVoice + voiceOffset + 0x114) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x118) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x110) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x10C) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x121) = 0xFF;
        *(u32*)(synthVoice + voiceOffset + 0x154) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x192) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x190) = 0x80;
        *(u8*)(synthVoice + voiceOffset + 0x191) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x180) = 0x400000;
        *(u32*)(synthVoice + voiceOffset + 0x170) = 0x400000;
        *(u32*)(synthVoice + voiceOffset + 0x184) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x174) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x1A0) = 0;
        *(u32*)(synthVoice + voiceOffset + 0x1A4) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x1B8) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x1B9) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x11C) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x11E) = 0x17;
        *(u8*)(synthVoice + voiceOffset + 0x104) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x193) = 1;
        *(u32*)(synthVoice + voiceOffset + 0x1C0) = 0;
        *(u16*)(synthVoice + voiceOffset + 0x1C4) = 0;
        *(u16*)(synthVoice + voiceOffset + 0x1C6) = 0x7FFF;
        *(u32*)(synthVoice + voiceOffset + 0x1CC) = 0;
        *(u16*)(synthVoice + voiceOffset + 0x1D0) = 0;
        *(u16*)(synthVoice + voiceOffset + 0x1D2) = 0x7FFF;
        *(u32*)(synthVoice + voiceOffset + 0x13C) = 0x6400;
        *(u8*)(synthVoice + voiceOffset + 0x131) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x11F) = 0;
        *(u8*)(synthVoice + voiceOffset + 0x08) = lowIndex;
        *(u8*)(synthVoice + voiceOffset + 0x09) = 0xFF;
        *(u8*)(synthVoice + voiceOffset + 0x14) = lowIndex;
        *(u8*)(synthVoice + voiceOffset + 0x15) = 0xFF;
        *(u8*)(synthVoice + voiceOffset + 0x20) = lowIndex;
        *(u8*)(synthVoice + voiceOffset + 0x21) = 0xFF;
    }

    {
        SynthFade* fade = (SynthFade*)(state + 0x5D4);
        f32 auxCurrent = lbl_803E77A8;
        f32 fadeCurrent = lbl_803E77D0;
        u32 pass;

        for (pass = 0; pass < 2; pass++)
        {
            fade[0].current = fadeCurrent;
            fade[0].auxCurrent = auxCurrent;
            fade[0].type = SYNTH_FADE_ACTION_DISABLED;
            fade[1].current = fadeCurrent;
            fade[1].auxCurrent = auxCurrent;
            fade[1].type = SYNTH_FADE_ACTION_DISABLED;
            fade[2].current = fadeCurrent;
            fade[2].auxCurrent = auxCurrent;
            fade[2].type = SYNTH_FADE_ACTION_DISABLED;
            fade[3].current = fadeCurrent;
            fade[3].auxCurrent = auxCurrent;
            fade[3].type = SYNTH_FADE_ACTION_DISABLED;
            fade[4].current = fadeCurrent;
            fade[4].auxCurrent = auxCurrent;
            fade[4].type = SYNTH_FADE_ACTION_DISABLED;
            fade[5].current = fadeCurrent;
            fade[5].auxCurrent = auxCurrent;
            fade[5].type = SYNTH_FADE_ACTION_DISABLED;
            fade[6].current = fadeCurrent;
            fade[6].auxCurrent = auxCurrent;
            fade[6].type = SYNTH_FADE_ACTION_DISABLED;
            fade[7].current = fadeCurrent;
            fade[7].auxCurrent = auxCurrent;
            fade[7].type = SYNTH_FADE_ACTION_DISABLED;
            fade[8].current = fadeCurrent;
            fade[8].auxCurrent = auxCurrent;
            fade[8].type = SYNTH_FADE_ACTION_DISABLED;
            fade[9].current = fadeCurrent;
            fade[9].auxCurrent = auxCurrent;
            fade[9].type = SYNTH_FADE_ACTION_DISABLED;
            fade[10].current = fadeCurrent;
            fade[10].auxCurrent = auxCurrent;
            fade[10].type = SYNTH_FADE_ACTION_DISABLED;
            fade[11].current = fadeCurrent;
            fade[11].auxCurrent = auxCurrent;
            fade[11].type = SYNTH_FADE_ACTION_DISABLED;
            fade[12].current = fadeCurrent;
            fade[12].auxCurrent = auxCurrent;
            fade[12].type = SYNTH_FADE_ACTION_DISABLED;
            fade[13].current = fadeCurrent;
            fade[13].auxCurrent = auxCurrent;
            fade[13].type = SYNTH_FADE_ACTION_DISABLED;
            fade[14].current = fadeCurrent;
            fade[14].auxCurrent = auxCurrent;
            fade[14].type = SYNTH_FADE_ACTION_DISABLED;
            fade[15].current = fadeCurrent;
            fade[15].auxCurrent = auxCurrent;
            fade[15].type = SYNTH_FADE_ACTION_DISABLED;
            fade += 16;
        }
    }

    synthMasterFaderActiveFlags = 0;
    synthMasterFaderPauseActiveFlags = 0;
    ((SynthGlobalState*)state)->initialized = 1;
    for (fadeIndex = 0; fadeIndex < 8; fadeIndex++)
    {
        *(u8*)(state + 0xA51 + fadeIndex * sizeof(SynthFade)) = 0;
    }
    {
        f32 auxCurrent = lbl_803E77A8;

        ((SynthGlobalState*)state)->auxMixA = auxCurrent;
        ((SynthGlobalState*)state)->auxMixB = auxCurrent;
    }

    inpInit();

    for (auxIndex = 0; auxIndex < 8; auxIndex++)
    {
        ((SynthGlobalState*)state)->auxASend[auxIndex] = 0;
        synthAuxAIndex[auxIndex] = 0xFF;
        ((SynthGlobalState*)state)->auxBSend[auxIndex] = 0;
        synthAuxBIndex[auxIndex] = 0xFF;
        ((SynthGlobalState*)state)->auxPairState[auxIndex][1] = 0;
        ((SynthGlobalState*)state)->auxPairState[auxIndex][0] = 0;
    }

    macInit();
    vidInit();
    voiceInitPriorityTables();

    for (auxIndex = 0; auxIndex < 16; auxIndex++)
    {
        ((SynthGlobalState*)state)->auxMixSlot[auxIndex] = 0;
    }

    voiceInitRegistrationTables();

    delayBucket = (u32*)(state + 0x240);
    for (auxIndex = 0; (u8)auxIndex < 0x20; auxIndex += 8)
    {
        delayBucket[0] = 0;
        delayBucket[1] = 0;
        delayBucket[2] = 0;
        delayBucket[3] = 0;
        delayBucket[4] = 0;
        delayBucket[5] = 0;
        delayBucket[6] = 0;
        delayBucket[7] = 0;
        delayBucket[8] = 0;
        delayBucket[9] = 0;
        delayBucket[10] = 0;
        delayBucket[11] = 0;
        delayBucket[12] = 0;
        delayBucket[13] = 0;
        delayBucket[14] = 0;
        delayBucket[15] = 0;
        delayBucket[16] = 0;
        delayBucket[17] = 0;
        delayBucket[18] = 0;
        delayBucket[19] = 0;
        delayBucket[20] = 0;
        delayBucket[21] = 0;
        delayBucket[22] = 0;
        delayBucket[23] = 0;
        delayBucket += 24;
    }

    gSynthDelayBucketCursor = 0;
    hwSetMesgCallback(synthHWMessageHandler);
}

void synthCopyVoiceSlotMixState(McmdVoiceState* dst, McmdVoiceState* src)
{
    synthCopyControllerValue(7, dst, src);
    synthCopyControllerValue(10, dst, src);
    synthCopyControllerValue(0x5B, dst, src);
    synthCopyControllerValue(0x80, dst, src);
    synthCopyControllerValue(0x84, dst, src);
}

s32 synthTriggerCallback(u32 callbackId)
{
    u32 linkId;
    s32 handled;

    handled = 0;
    if (gSynthInitialized != 0)
    {
        for (linkId = synthLookupCallbackLinkId(callbackId); linkId != SYNTH_INVALID_LINK_ID;
             linkId = lbl_803DEEE8[linkId & 0xFF].callbackNext)
        {
            McmdVoiceState* slot;

            slot = &lbl_803DEEE8[linkId & 0xFF];
            if (linkId == slot->callbackLinkId)
            {
                synthReleaseVoiceSlot(slot);
                handled = 1;
            }
        }
    }

    return handled;
}

void synthSetFade(u8 value, u16 time, u8 selector, u8 action, u32 handle)
{
    SynthFade* fadeTable;
    u32 fadeIndex;
    u32 fadeTime;
    u8 actionFilter;
    SynthFade* fade;
    f32 target;

    fadeTime = time;
    if (fadeTime != 0)
    {
        synthScaleFadeTime((s32*)&fadeTime);
    }

    fadeTable = gSynthFades;
    target = value * SYNTH_FADE_SCALE;

    if (selector == SYNTH_FADE_SELECTOR_ACTION_0_OR_1)
    {
    apply_actions_0_or_1:
        fade = fadeTable;
        for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++)
        {
            if (fade->type == 0 || fade->type == 1)
            {
                SYNTH_APPLY_FADE(fade, fadeIndex, SYNTH_INVALID_LINK_ID);
            }
        }
        return;
    }

    if (selector == SYNTH_FADE_SELECTOR_ACTION_2_OR_3)
    {
    apply_actions_2_or_3:
        fade = fadeTable;
        for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++)
        {
            if (fade->type == 2 || fade->type == 3)
            {
                SYNTH_APPLY_FADE(fade, fadeIndex, SYNTH_INVALID_LINK_ID);
            }
        }
        return;
    }

    if (selector == SYNTH_FADE_SELECTOR_ACTION_0)
    {
        actionFilter = 0;
    }
    else if (selector < SYNTH_FADE_SELECTOR_ACTION_0)
    {
        if (selector == SYNTH_FADE_SELECTOR_ACTION_3)
        {
            actionFilter = 3;
        }
        else if (selector >= SYNTH_FADE_SELECTOR_ACTION_2_OR_3)
        {
            goto apply_actions_2_or_3;
        }
        else if (selector >= SYNTH_FADE_SELECTOR_ACTION_2)
        {
            actionFilter = 2;
        }
        else
        {
            fade = &fadeTable[selector];
            SYNTH_APPLY_FADE(fade, selector, handle);
            return;
        }
    }
    else if (selector < SYNTH_FADE_SELECTOR_ACTION_0_OR_1)
    {
        actionFilter = 1;
    }
    else
    {
        fade = &fadeTable[selector];
        SYNTH_APPLY_FADE(fade, selector, handle);
        return;
    }

    fade = fadeTable;
    for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++, fade++)
    {
        if (fade->type == actionFilter)
        {
            SYNTH_APPLY_FADE(fade, fadeIndex, handle);
        }
    }
    return;
}

u32 synthIsFadeActive(u32 fadeIndex)
{
    SynthFade* fade;
    u8 maskedFadeIndex;

    maskedFadeIndex = fadeIndex;
    fade = &gSynthFades[maskedFadeIndex];

    if (fade->type != SYNTH_FADE_ACTION_DISABLED)
    {
        if ((gSynthFadeMask & (1 << maskedFadeIndex)) != 0)
        {
            if (fade->target > fade->start)
            {
                return 1;
            }
        }
    }

    return 0;
}

void synthSetFadeAction(u32 fadeIndex, u8 action)
{
    if (gSynthInitialized == 0)
    {
        return;
    }

    gSynthFades[fadeIndex & 0xFF].type = action;
}

#undef SYNTH_APPLY_FADE

void synthExit(void)
{
    salFree(synthVoice);
}

void sndSeqStop(u32 handle)
{
    sndBegin();
    synthFreeHandle(handle);
    sndEnd();
}

void sndSeqSpeed(u32 handle, u32 speed)
{
    sndBegin();
    synthSetHandleValue16(handle, speed);
    sndEnd();
}

void sndSeqContinue(u32 handle)
{
    sndBegin();
    synthRestoreQueuedHandle(handle);
    sndEnd();
}

void sndSeqMute(u32 handle, u32 mute, u32 time)
{
    sndBegin();
    synthSetHandleMixData(handle, mute, time);
    sndEnd();
}
