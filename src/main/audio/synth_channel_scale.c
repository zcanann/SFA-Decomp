#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "main/audio/snd_synth_api.h"
#include "main/audio/voice_id.h"
#include "main/audio/voice_manage.h"
#include "main/audio/synth_config.h"
#include "main/audio/synth_job_queue.h"
#include "main/audio/synth_callback.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/synth_seq_dispatch.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"
#include "main/audio/synth_volume.h"
#include "src/main/audio/synth_internal.h"

extern f32 lbl_803E7780;
extern f32 lbl_803E7788;

/*
 * Per-sequence tick and event update pass.
 */
static inline f32 sal_fmod(f32 x, f32 y, f64 absy)
{
    s64 n;

    if (absy > __fabs(x))
    {
        return x;
    }
    n = (s64)(u64)(x / y);
    x = x - y * (f32)n;
    return x;
}

static inline void synthHandleKeyOffCallbacks(void)
{
    SynthCallbackLink* node;
    SynthCallbackLink* next;

    if (gSynthCurrentVoice->keyOffCheck == 0)
    {
        node = gSynthCurrentVoice->callbackLists[2];
        while (node != NULL)
        {
            next = node->next;
            if ((node->callbackId != 0xffffffff) && (sndFXCheck(node->callbackId) == 0xffffffff))
            {
                synthFreeCallback(node);
            }
            node = next;
        }
    }
    gSynthCurrentVoice->keyOffCheck = (gSynthCurrentVoice->keyOffCheck + 1) % 5;
}

static inline void synthSetTickDelta(SynthSequenceQueue* section, u32 deltaTime, f32 c0, f32 c1, f32 range,
                                     f64 absRange)
{
    f32 tickDelta = c0 * ((f32)section->bpm * deltaTime);
    tickDelta = tickDelta * (c1 * (f32)(u32)section->speed);

    section->tickDelta[section->timeIndex].low = sal_fmod(range * tickDelta, range, absRange);
    *(int*)&section->tickDelta[section->timeIndex].high = floorf(tickDelta);
}

static inline void synthHandleMasterTrack(u8 secIndex)
{
    SynthSequenceQueue* section;
    u32* evt;

    section = &gSynthCurrentVoice->section[secIndex];
    if (section->masterTrackBase != NULL)
    {
        while (*(evt = (u32*)section->masterTrackCursor) != 0xffffffff)
        {
            if (*evt > section->time[section->timeIndex].high)
            {
                break;
            }
            if ((((SynthArrangement*)gSynthCurrentVoice->arrbase)->info & 0x40000000) != 0)
            {
                synthSetStudioChannelScale((section->bpm = evt[1]) >> 10, gSynthCurrentVoiceSlotIndex, secIndex);
            }
            else
            {
                synthSetStudioChannelScale(evt[1], gSynthCurrentVoiceSlotIndex, secIndex);
                section->bpm = ((u32*)section->masterTrackCursor)[1] << 10;
            }
            section->masterTrackCursor += 8;
        }
    }
}

void seqHandle(u32 deltaTime)
{
    u32 tickSum;
    u32 sectionIndex;
    u32 timeIndex;
    u32 eventsActive;
    u32 callbacksActive;
    SynthVoice* song;
    SynthVoice* nextSong;
    f32 tickRateScale;
    f64 absoluteTickRange;
    f32 tickRange;
    f32 speedScale;

    if (deltaTime != 0)
    {
        tickRange = lbl_803E7788;
        song = gSynthQueuedVoices;
        absoluteTickRange = __fabs(tickRange);
        tickRateScale = lbl_803E7780;
        speedScale = 0.00390625f;
        for (; song != NULL; song = nextSong)
        {
            nextSong = song->next;
            gSynthCurrentVoice = song;
            gSynthCurrentVoiceSlotIndex = song->slotIndex;
            gSynthCurrentFadeOutState = synthIsFadeOutActive(song->defaultVolumeGroup);
            if (gSynthCurrentVoice->keyGroupMap == NULL)
            {
                synthHandleMasterTrack(0);
                synthSetTickDelta(gSynthCurrentVoice->section, deltaTime, tickRateScale, speedScale, tickRange,
                                  absoluteTickRange);
                eventsActive = synthProcessChannelEventQueue(0, deltaTime);
                callbacksActive = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (sectionIndex = 0; sectionIndex < 2; ++sectionIndex)
                {
                    tickSum = gSynthCurrentVoice->section[0].time[sectionIndex].low +
                              gSynthCurrentVoice->section[0].tickDelta[sectionIndex].low;
                    gSynthCurrentVoice->section[0].time[sectionIndex].low = tickSum & 0xffff;
                    tickSum = tickSum >> 16;
                    gSynthCurrentVoice->section[0].time[sectionIndex].high +=
                        tickSum + gSynthCurrentVoice->section[0].tickDelta[sectionIndex].high;
                }
            }
            else
            {
                eventsActive = 0;
                for (sectionIndex = 0; sectionIndex < 0x10; sectionIndex++)
                {
                    synthHandleMasterTrack(sectionIndex);
                    synthSetTickDelta(&gSynthCurrentVoice->section[sectionIndex], deltaTime, tickRateScale,
                                      speedScale, tickRange, absoluteTickRange);
                    eventsActive |= synthProcessChannelEventQueue(sectionIndex, deltaTime);
                }
                callbacksActive = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (sectionIndex = 0; sectionIndex < 16; sectionIndex++)
                {
                    for (timeIndex = 0; timeIndex < 2; ++timeIndex)
                    {
                        tickSum = gSynthCurrentVoice->section[sectionIndex].time[timeIndex].low +
                                  gSynthCurrentVoice->section[sectionIndex].tickDelta[timeIndex].low;
                        gSynthCurrentVoice->section[sectionIndex].time[timeIndex].low = tickSum & 0xffff;
                        tickSum = tickSum >> 16;
                        gSynthCurrentVoice->section[sectionIndex].time[timeIndex].high +=
                            tickSum + gSynthCurrentVoice->section[sectionIndex].tickDelta[timeIndex].high;
                    }
                }
            }
            if ((eventsActive == 0) && (callbacksActive == 0))
            {
                if (song->prev != NULL)
                {
                    song->prev->next = nextSong;
                }
                else
                {
                    gSynthQueuedVoices = nextSong;
                }
                if (nextSong != NULL)
                {
                    nextSong->prev = song->prev;
                }
                synthRecycleVoiceCallbacks(song);
                song->state = 0;
                song->prev = NULL;
                if ((song->next = gSynthFreeVoices) != NULL)
                {
                    gSynthFreeVoices->prev = song;
                }
                gSynthFreeVoices = song;
            }
        }
    }
}

/*
 * Initialize sequence instances, note priorities, and callback links.
 */
void seqInit(void)
{
    u16* note;
    SynthVoice* voice;
    SynthVoiceRuntime* runtime;
    SynthCallbackLink* prev;
    SynthCallbackLink* callback;
    u32 i;
    int j;

    runtime = SYNTH_VOICE_RUNTIME();
    gSynthQueuedVoices = NULL;
    gSynthAllocatedVoices = NULL;
    voice = &runtime->voices[0];
    note = runtime->voiceNotes[0];
    for (i = 0; i < 8; i++)
    {
        if (i == 0)
        {
            gSynthFreeVoices = voice;
            voice->prev = NULL;
        }
        else
        {
            (voice - 1)->next = voice;
            voice->prev = &SYNTH_VOICE_RUNTIME()->voices[i - 1];
        }
        voice->slotIndex = i;
        voice->state = 0;
        for (j = 0; j < 16; j++)
        {
            note[j] = 0xffff;
        }
        note += 16;
        voice++;
    }
    runtime->voices[i - 1].next = NULL;

    prev = NULL;
    callback = &runtime->callbacks[0];
    gSynthFreeCallbacks = callback;
    for (i = 0; i < 0x100; i++)
    {
        callback->prev = prev;
        if (prev != NULL)
        {
            prev->next = callback;
        }
        prev = callback;
        callback++;
    }
    prev->next = NULL;
    gSynthNextHandle = 0;
}
