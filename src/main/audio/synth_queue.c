#include "src/main/audio/synth_internal.h"

#pragma exceptions on

typedef struct SynthSeqRuntime
{
    u8 unk0000[0x1400];
    SynthVoice voices[SYNTH_MAX_VOICES];
} SynthSeqRuntime;

extern SynthSeqRuntime lbl_803AF550;

/* SynthVoice.state - which intrusive list the voice sits on */
#define SYNTH_VOICE_STATE_FREE 0      /* unallocated */
#define SYNTH_VOICE_STATE_QUEUED 1    /* on gSynthQueuedVoices; awaiting start */
#define SYNTH_VOICE_STATE_ALLOCATED 2 /* on gSynthAllocatedVoices; playing */

/* MusyX sequencer arrangement data (ARR). */
typedef struct SynthArrangement
{
    u32 trackTableOffset;
    u8 unk04[8];
    u32 masterTrackOffset;
    u32 info;
    u8 unk14[0x40];
    u32 trackSectionTableOffset;
} SynthArrangement;

typedef struct SynthSeqVolDef
{
    u8 track;
    u8 volGroup;
} SynthSeqVolDef;

typedef struct SynthPlayPara
{
    u32 flags;
    u32 trackMute[2];
    u16 speed;

    struct
    {
        u16 time;
        u8 target;
    } volume;

    u8 numSeqVolDef;
    SynthSeqVolDef* seqVolDef;
    u8 numFaded;
    u8* faded;
} SynthPlayPara;

typedef struct SynthMasterTrackEvent
{
    u32 time;
    u32 bpm;
} SynthMasterTrackEvent;

extern u8 lbl_803BD964[0x40];
extern u16 lbl_803BCC90[8][0x10];
extern int gSynthCurrentVoiceSlotIndex;
extern void fn_8026E864(void);
extern void synthVolume(u8 volume, u16 timeMs, u8 target, u8 action, u32 handle);
extern void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value);
extern void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
extern void inpResetChannelDefaults(u8 a, u8 b);

/*
 * Start playback of a sequence arrangement.
 */
extern int voiceKillById(u32 id);

typedef struct SynthPage
{
    u16 macro;
    u8 prio;
    u8 maxVoices;
    u8 index;
    u8 reserved;
} SynthPage;

static void BuildTransTab(u8* tab, SynthPage* page)
{
    u8 i;

    for (i = 0; i < 128; ++i)
    {
        tab[i] = 0xff;
    }

    for (i = 0; page->index != 0xFF; ++i, ++page)
    {
        tab[page->index] = i;
    }
}

u32 seqStartPlay(u8* norm, u8* drum, u8* midiSetup, u8* song, SynthPlayPara* para, u8 studio, u16 sgid)
{
    u8 seqId;
    SynthVoice* oldCSeq;
    u32 bpm;
    SynthVoice* nseq;
    u8* ms;
    long i;
    u32* tracktab;
    SynthArrangement* arr;

    ms = midiSetup;
    if ((nseq = gSynthFreeVoices) == 0)
    {
        return SYNTH_HANDLE_INVALID;
    }
    if ((gSynthFreeVoices = nseq->next) != 0)
    {
        gSynthFreeVoices->prev = 0;
    }
    if ((nseq->next = gSynthQueuedVoices) != 0)
    {
        gSynthQueuedVoices->prev = nseq;
    }
    nseq->prev = 0;
    gSynthQueuedVoices = nseq;
    nseq->state = SYNTH_VOICE_STATE_QUEUED;
    for (i = 0; i < 16; i++)
    {
        nseq->section[i].eventList = 0;
    }

    seqId = nseq->slotIndex;
    nseq->pendingStartActive = 0;
    nseq->normtab = norm;
    nseq->drumtab = drum;
    nseq->arrbase = song;
    nseq->groupId = sgid;

    BuildTransTab(nseq->normTrans, (SynthPage*)nseq->normtab);
    BuildTransTab(nseq->drumTrans, (SynthPage*)nseq->drumtab);

    nseq->currentStudio = seqId + 23;
    for (i = 0; i < 64; i++)
    {
        nseq->studioMap[i] = nseq->currentStudio;
    }

    nseq->defStudio = studio;
    if (para == 0)
    {
        nseq->immediateMixValue0 = -1;
        nseq->immediateMixValue1 = -1;
        for (i = 0; i < 16; i++)
        {
            nseq->section[i].speed = 0x100;
        }
        synthVolume(0x7F, 0, nseq->currentStudio, 0, -1);
    }
    else
    {
        if (para->flags & 1)
        {
            nseq->immediateMixValue0 = para->trackMute[0];
            nseq->immediateMixValue1 = para->trackMute[1];
        }
        else
        {
            nseq->immediateMixValue0 = -1;
            nseq->immediateMixValue1 = -1;
        }

        if (para->flags & 2)
        {
            for (i = 0; i < 16; i++)
            {
                nseq->section[i].speed = para->speed;
            }
        }
        else
        {
            for (i = 0; i < 16; i++)
            {
                nseq->section[i].speed = 0x100;
            }
        }

        if (para->flags & 8)
        {
            for (i = 0; i < para->numSeqVolDef; i++)
            {
                nseq->studioMap[para->seqVolDef[i].track] = para->seqVolDef[i].volGroup;
                synthSetMusicVolumeType(para->seqVolDef[i].volGroup, 0);
            }
        }

        if (para->flags & 4)
        {
            synthVolume(para->volume.target, para->volume.time, nseq->currentStudio, 0, -1);
            for (i = 0; i < para->numFaded; i++)
            {
                synthVolume(para->volume.target, para->volume.time, para->faded[i], 0, -1);
            }
        }
    }

    arr = (SynthArrangement*)song;
    if (arr->info & 0x80000000)
    {
        nseq->keyGroupMap = (u8*)(arr->trackSectionTableOffset + (u32)song);
    }
    else
    {
        nseq->keyGroupMap = 0;
    }

    bpm = arr->info & 0x0FFFFFFF;
    if (!(arr->info & 0x40000000))
    {
        bpm <<= 10;
    }

    for (i = 0; i < 16; i++)
    {
        nseq->section[i].bpm = bpm;
        synthSetStudioChannelScale(bpm >> 10, seqId, (u8)i);
        if (arr->masterTrackOffset != 0)
        {
            nseq->section[i].masterTrackBase = (u8*)(arr->masterTrackOffset + (u32)song);
            nseq->section[i].masterTrackCursor =
                nseq->section[i].masterTrackBase;
        }
        else
        {
            nseq->section[i].masterTrackBase = 0;
        }
        nseq->section[i].loopDisable = 0;
        nseq->section[i].loopCount = 0;
    }

    tracktab = (u32*)(arr->trackTableOffset + (u32)song);
    for (i = 0; i < 64; i++)
    {
        lbl_803BD964[i] = 0x7F;
        SYNTH_SEQUENCE_STATE(nseq, i)->stream = 0;
        if (tracktab[i] != 0)
        {
            SYNTH_TRACK_CURSOR(nseq, i)->current = SYNTH_TRACK_CURSOR(nseq, i)->base = (u8*)(tracktab[i] + (u32)song);
        }
        else
        {
            SYNTH_TRACK_CURSOR(nseq, i)->current = SYNTH_TRACK_CURSOR(nseq, i)->base = 0;
        }
    }

    nseq->callbackLists[0] = 0;
    nseq->callbackLists[1] = 0;
    nseq->callbackLists[2] = 0;

    for (i = 0; i < 16; i++)
    {
        inpResetMidiCtrl((u8)i, seqId, 1);
    }
    for (i = 0; i < 16; i++)
    {
        nseq->prgState[i].macId = 0xFFFF;
    }
    for (i = 0; i < 16; i++)
    {
        inpResetChannelDefaults((u8)i, seqId);
    }

    if (ms != 0)
    {
        for (i = 0; i < 16; i++)
        {
            u8 prg = ms[4];
            lbl_803BCC90[gSynthCurrentVoiceSlotIndex][(u8)i] = 0xFFFF;
            if ((u8)i != 9)
            {
                prg = nseq->normTrans[prg];
                if (prg != 0xFF)
                {
                    nseq->prgState[(u8)i].macId = *(u16*)(nseq->normtab + prg * 6);
                    nseq->prgState[(u8)i].priority = nseq->normtab[prg * 6 + 2];
                    nseq->prgState[(u8)i].maxVoices = nseq->normtab[prg * 6 + 3];
                }
            }
            else
            {
                prg = nseq->drumTrans[prg];
                if (prg != 0xFF)
                {
                    nseq->prgState[(u8)i].macId = *(u16*)(nseq->drumtab + prg * 6);
                    nseq->prgState[(u8)i].priority = nseq->drumtab[prg * 6 + 2];
                    nseq->prgState[(u8)i].maxVoices = nseq->drumtab[prg * 6 + 3];
                }
            }
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, i, seqId, ms[5]);
            inpSetMidiCtrl(MCMD_CTRL_PANNING, i, seqId, ms[6]);
            inpSetMidiCtrl(MCMD_CTRL_REVERB, i, seqId, ms[7]);
            inpSetMidiCtrl(MCMD_CTRL_POST_AUX_B, i, seqId, ms[8]);
            ms += 5;
        }
    }

    for (i = 0; i < 16; i++)
    {
        lbl_803BCC90[seqId][i] = 0xFFFF;
    }

    for (i = 0; i < 16; i++)
    {
        nseq->section[i].time[0].high = 0;
        nseq->section[i].time[0].low = 0;
        nseq->section[i].time[1].high = 0;
        nseq->section[i].time[1].low = 0;
        nseq->section[i].timeIndex = 0;
    }

    nseq->keyOffCheck = 0;

    if (para != 0 && (para->flags & 0x10) != 0)
    {
        synthQueueVoice(nseq);
    }

    oldCSeq = gSynthCurrentVoice;
    gSynthCurrentVoice = nseq;
    fn_8026E864();
    gSynthCurrentVoice = oldCSeq;
    return synthAssignHandle(seqId);
}

/*
 * Advance the master (tempo) track of one sequence section (HandleMasterTrack).
 */
void fn_8026CF78(int secIndex)
{
    SynthSequenceQueue* section;

    section = SYNTH_SEQUENCE_QUEUE(gSynthCurrentVoice, secIndex);
    if (section->masterTrackBase != 0)
    {
        while (((SynthMasterTrackEvent*)section->masterTrackCursor)->time != 0xFFFFFFFF)
        {
            if (*(volatile u32*)section->masterTrackCursor > section->time[section->timeIndex].high)
            {
                break;
            }

            if (((SynthArrangement*)gSynthCurrentVoice->arrbase)->info & 0x40000000)
            {
                synthSetStudioChannelScale(
                    (section->bpm = ((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm) >> 10,
                    gSynthCurrentVoiceSlotIndex, secIndex);
            }
            else
            {
                synthSetStudioChannelScale(((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm,
                                           gSynthCurrentVoiceSlotIndex, secIndex);
                section->bpm = ((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm << 10;
            }

            section->masterTrackCursor += 8;
        }
    }
}

/*
 * Move a voice node from the queued list to the head of the allocated
 * list and mark it active.
 */
void synthQueueVoice(SynthVoice* voice)
{
    if (voice->prev != 0)
    {
        voice->prev->next = voice->next;
    }
    else
    {
        gSynthQueuedVoices = voice->next;
    }
    if (voice->next != 0)
    {
        voice->next->prev = voice->prev;
    }
    if ((voice->next = gSynthAllocatedVoices) != 0)
    {
        gSynthAllocatedVoices->prev = voice;
    }
    voice->prev = 0;
    gSynthAllocatedVoices = voice;
    voice->state = SYNTH_VOICE_STATE_ALLOCATED;
}

/*
 * Move a queued handle to the allocated list after a delayed fade completes.
 */
void synthQueueHandle(u32 handle)
{
    u32 key;
    u32 found;
    u32 i;
    SynthVoice* voice;
    SynthVoice* sv;

    key = handle & 0x7fffffffu;

    sv = gSynthQueuedVoices;
    while (sv != 0)
    {
        if (sv->handle == key)
        {
            found = sv->slotIndex | (handle & 0x80000000);
            goto done;
        }
        sv = sv->next;
    }

    sv = gSynthAllocatedVoices;
    while (sv != 0)
    {
        if (sv->handle == key)
        {
            found = sv->slotIndex | (handle & 0x80000000);
            goto done;
        }
        sv = sv->next;
    }
    found = 0xffffffff;
done:

    if (found == 0xffffffff) return;

    if ((found & 0x80000000) == 0)
    {
        voice = &gSynthVoices[found];
        if (voice->state != SYNTH_VOICE_STATE_QUEUED) return;

        if (voice->prev != 0)
        {
            voice->prev->next = voice->next;
        }
        else
        {
            gSynthQueuedVoices = voice->next;
        }
        if (voice->next != 0)
        {
            voice->next->prev = voice->prev;
        }

        if ((voice->next = gSynthAllocatedVoices) != 0)
        {
            gSynthAllocatedVoices->prev = voice;
        }
        voice->prev = 0;
        gSynthAllocatedVoices = voice;
        voice->state = SYNTH_VOICE_STATE_ALLOCATED;

        {
            SynthVoice* base = voice;
            for (i = 0; i < 2; i++)
            {
                SynthCallbackLink* cb = base->callbackLists[0];
                while (cb != 0)
                {
                    voiceKillById(cb->callbackId);
                    cb = cb->next;
                }
                base = (SynthVoice*)((u8*)base + 4);
            }
        }
        {
            SynthCallbackLink* cb2 = voice->callbackLists[2];
            while (cb2 != 0)
            {
                voiceKillById(cb2->callbackId);
                cb2 = cb2->next;
            }
        }
        synthRecycleVoiceCallbacks(voice);
    }
    else
    {
        u32 idx = found & 0x7fffffffu;
        voice = &gSynthVoices[idx];
        if (voice->state == SYNTH_VOICE_STATE_FREE) return;
        voice->pendingUpdate.flags |= 8;
    }
}

/*
 * Stop a sequence voice, clean up callbacks, and return the voice to the
 * free list. Deferred handles clear the pending output word instead.
 */
void synthFreeHandle(u32 handle)
{
    SynthVoice* voice;
    SynthSeqRuntime* runtime;
    u32 found;
    u32 i;

    runtime = &lbl_803AF550;

    voice = gSynthQueuedVoices;
    while (voice != 0)
    {
        if (voice->handle == (handle & 0x7fffffffu))
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0)
    {
        if (voice->handle == (handle & 0x7fffffffu))
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if (found == 0xffffffff)
    {
        return;
    }

    if ((found & 0x80000000) == 0)
    {
        voice = &runtime->voices[found];
        switch (runtime->voices[found].state)
        {
        case SYNTH_VOICE_STATE_QUEUED:
            if (voice->prev != 0)
            {
                voice->prev->next = voice->next;
            }
            else
            {
                gSynthQueuedVoices = voice->next;
            }

            {
                SynthVoice* base;
                i = 0;
                base = voice;
                for (; i < 2; i++)
                {
                    SynthCallbackLink* cb = base->callbackLists[0];
                    while (cb != 0)
                    {
                        voiceKillById(cb->callbackId);
                        cb = cb->next;
                    }
                    base = (SynthVoice*)((u8*)base + 4);
                }
            }
            {
                SynthCallbackLink* cb = runtime->voices[found].callbackLists[2];
                while (cb != 0)
                {
                    voiceKillById(cb->callbackId);
                    cb = cb->next;
                }
            }
            synthRecycleVoiceCallbacks(voice);
            break;
        case SYNTH_VOICE_STATE_ALLOCATED:
            if (voice->prev != 0)
            {
                voice->prev->next = voice->next;
            }
            else
            {
                gSynthAllocatedVoices = voice->next;
            }
            break;
        }

        if (voice->next != 0)
        {
            voice->next->prev = voice->prev;
        }
        voice->state = SYNTH_VOICE_STATE_FREE;
        if (gSynthFreeVoices != 0)
        {
            gSynthFreeVoices->prev = voice;
        }
        voice->next = gSynthFreeVoices;
        voice->prev = 0;
        gSynthFreeVoices = voice;
    }
    else
    {
        if ((voice = &runtime->voices[found & 0x7fffffffu], runtime->voices[found & 0x7fffffffu].state) != SYNTH_VOICE_STATE_FREE)
        {
            voice->pendingUpdate.output = 0;
        }
    }
}

/*
 * Update sequence playback speed immediately, or queue it for a deferred
 * handle update.
 */
void synthSetHandleValue16(u32 handle, u32 speed)
{
    u32 key;
    u32 found;
    SynthVoiceRuntime* runtime;
    SynthVoice* voice;

    runtime = SYNTH_VOICE_RUNTIME();
    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0)
    {
        if (voice->handle == key)
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0)
    {
        if (voice->handle == key)
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if ((found & 0x80000000) == 0)
    {
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 0) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 1) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 2) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 3) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 4) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 5) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 6) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 7) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 8) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 9) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 10) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 11) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 12) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 13) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 14) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, found, 15) = speed;
    }
    else
    {
        u32 idx = found & 0x7fffffffu;
        SYNTH_RUNTIME_PENDING_FLAGS(runtime, idx) |= 0x20;
        SYNTH_RUNTIME_PENDING_VALUE16(runtime, idx) = speed;
    }
}

/*
 * Continue a stopped sequence voice by moving it from the allocated list
 * back to the queued list, or clear the deferred continue flag.
 */
void synthRestoreQueuedHandle(u32 handle)
{
    u32 key;
    u32 found;
    SynthVoice* voice;

    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0)
    {
        if (voice->handle == key)
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0)
    {
        if (voice->handle == key)
        {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if ((found & 0x80000000) == 0)
    {
        voice = &gSynthVoices[found];
        if (voice->state != SYNTH_VOICE_STATE_ALLOCATED)
        {
            return;
        }

        if (voice->prev != 0)
        {
            voice->prev->next = voice->next;
        }
        else
        {
            gSynthAllocatedVoices = voice->next;
        }
        if (voice->next != 0)
        {
            voice->next->prev = voice->prev;
        }

        if ((voice->next = gSynthQueuedVoices) != 0)
        {
            gSynthQueuedVoices->prev = voice;
        }
        voice->prev = 0;
        gSynthQueuedVoices = voice;
        voice->state = SYNTH_VOICE_STATE_QUEUED;
    }
    else
    {
        gSynthVoices[found & 0x7fffffffu].pendingUpdate.flags &= ~8;
    }
}

SynthVoice gSynthVoices[SYNTH_MAX_VOICES];
