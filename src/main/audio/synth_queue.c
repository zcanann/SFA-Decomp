#include "src/main/audio/synth_internal.h"
#include "main/audio/synth_seq_dispatch.h"
#include "main/audio/synth_volume.h"
#include "main/audio/inp_midi.h"
#include "main/audio/voice_manage.h"
#include "main/audio/synth_queue.h"

typedef union SynthSeqRuntime
{
    struct
    {
        u8 callbackStorage[0x1400];
        SynthVoice voices[SYNTH_MAX_VOICES];
    } data;
    u8 bytes[0x1400 + sizeof(SynthVoice) * SYNTH_MAX_VOICES];
} SynthSeqRuntime;

typedef struct SynthVoiceRuntimeView
{
    u8 callbackStorage[0x1400];
    SynthVoice voice;
} SynthVoiceRuntimeView;

/* SynthVoice.state - which intrusive list the voice sits on */
#define SYNTH_VOICE_STATE_FREE      0 /* unallocated */
#define SYNTH_VOICE_STATE_QUEUED    1 /* on gSynthQueuedVoices; awaiting start */
#define SYNTH_VOICE_STATE_ALLOCATED 2 /* on gSynthAllocatedVoices; playing */

static inline void BuildTransTab(u8* tab, SynthPage* page)
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

u32 seqStartPlay(SynthPage* norm, SynthPage* drum, SynthMidiSetup* midiSetup, u32* song,
                 SynthPlayParams* para, u8 studio, u16 sgid)
{
    u32 seqId;
    SynthVoice* prevCurSeq;
    u32 bpm;
    SynthVoice* seq;
    u8* midiData;
    long i;
    u32* trackOffsets;
    SynthArrangement* arrangement;
    u8 program;

    midiData = (u8*)midiSetup;
    if ((seq = gSynthFreeVoices) == 0)
    {
        return SYNTH_HANDLE_INVALID;
    }
    if ((gSynthFreeVoices = seq->next) != 0)
    {
        gSynthFreeVoices->prev = 0;
    }
    if ((seq->next = gSynthQueuedVoices) != 0)
    {
        gSynthQueuedVoices->prev = seq;
    }
    seq->prev = 0;
    gSynthQueuedVoices = seq;
    seq->state = SYNTH_VOICE_STATE_QUEUED;
    for (i = 0; i < 16; i++)
    {
        seq->section[i].eventList = 0;
    }

    seqId = seq->slotIndex;
    seq->pendingStartActive = 0;
    seq->normtab = norm;
    seq->drumtab = drum;
    seq->arrbase = (u8*)song;
    seq->groupId = sgid;

    BuildTransTab(seq->normTrans, seq->normtab);
    BuildTransTab(seq->drumTrans, seq->drumtab);

    seq->defaultVolumeGroup = seqId + 23;
    for (i = 0; i < 64; i++)
    {
        seq->trackVolumeGroup[i] = seq->defaultVolumeGroup;
    }

    seq->defStudio = studio;
    if (para == 0)
    {
        seq->immediateMixValue0 = -1;
        seq->immediateMixValue1 = -1;
        for (i = 0; i < 16; i++)
        {
            seq->section[i].speed = 0x100;
        }
        synthVolume(0x7F, 0, seq->defaultVolumeGroup, 0, -1);
    }
    else
    {
        if (para->flags & 1)
        {
            seq->immediateMixValue0 = para->trackMute[0];
            seq->immediateMixValue1 = para->trackMute[1];
        }
        else
        {
            seq->immediateMixValue0 = -1;
            seq->immediateMixValue1 = -1;
        }

        if (para->flags & 2)
        {
            for (i = 0; i < 16; i++)
            {
                seq->section[i].speed = para->speed;
            }
        }
        else
        {
            for (i = 0; i < 16; i++)
            {
                seq->section[i].speed = 0x100;
            }
        }

        if (para->flags & 8)
        {
            for (i = 0; i < para->numSeqVolumeDefinitions; i++)
            {
                seq->trackVolumeGroup[para->seqVolumeDefinitions[i].track] =
                    para->seqVolumeDefinitions[i].volumeGroup;
                synthSetMusicVolumeType(para->seqVolumeDefinitions[i].volumeGroup, 0);
            }
        }

        if (para->flags & 4)
        {
            synthVolume(para->volume.target, para->volume.time, seq->defaultVolumeGroup, 0, -1);
            for (i = 0; i < para->numFaded; i++)
            {
                synthVolume(para->volume.target, para->volume.time, para->faded[i], 0, -1);
            }
        }
    }

    arrangement = (SynthArrangement*)song;
    if (arrangement->info & 0x80000000)
    {
        seq->keyGroupMap = (u8*)(arrangement->trackSectionTableOffset + (u32)song);
    }
    else
    {
        seq->keyGroupMap = 0;
    }

    bpm = arrangement->info & 0x0FFFFFFF;
    if (!(arrangement->info & 0x40000000))
    {
        bpm <<= 10;
    }

    for (i = 0; i < 16; i++)
    {
        seq->section[i].bpm = bpm;
        synthSetStudioChannelScale(bpm >> 10, seqId, i);
        if (arrangement->masterTrackOffset != 0)
        {
            seq->section[i].masterTrackBase = (u8*)(arrangement->masterTrackOffset + (u32)song);
            seq->section[i].masterTrackCursor = seq->section[i].masterTrackBase;
        }
        else
        {
            seq->section[i].masterTrackBase = 0;
        }
        seq->section[i].loopDisable = 0;
        seq->section[i].loopCount = 0;
    }

    trackOffsets = (u32*)(arrangement->trackTableOffset + (u32)song);
    for (i = 0; i < 64; i++)
    {
        synthTrackVolume[i] = 0x7F;
        SYNTH_SEQUENCE_STATE(seq, i)->noteData = 0;
        if (trackOffsets[i] != 0)
        {
            SYNTH_TRACK_CURSOR(seq, i)->current = SYNTH_TRACK_CURSOR(seq, i)->base = (u8*)(trackOffsets[i] + (u32)song);
        }
        else
        {
            SYNTH_TRACK_CURSOR(seq, i)->current = SYNTH_TRACK_CURSOR(seq, i)->base = 0;
        }
    }

    seq->callbackLists[0] = 0;
    seq->callbackLists[1] = 0;
    seq->callbackLists[2] = 0;

    for (i = 0; i < 16; i++)
    {
        inpResetMidiCtrl((u8)i, seqId, 1);
    }
    for (i = 0; i < 16; i++)
    {
        seq->prgState[i].macId = 0xFFFF;
    }
    for (i = 0; i < 16; i++)
    {
        inpResetChannelDefaults((u8)i, seqId);
    }

    if (midiData != NULL)
    {
        for (i = 0; i < 16; i++)
        {
            program = midiData[4];
            gSynthVoiceNotes[gSynthCurrentVoiceSlotIndex][(u8)i] = 0xFFFF;
            if ((u8)i != 9)
            {
                program = seq->normTrans[program];
                if (program != 0xFF)
                {
                    seq->prgState[(u8)i].macId = *(u16*)((u8*)seq->normtab + program * 6);
                    seq->prgState[(u8)i].priority = ((u8*)seq->normtab)[program * 6 + 2];
                    seq->prgState[(u8)i].maxVoices = ((u8*)seq->normtab)[program * 6 + 3];
                }
            }
            else
            {
                program = seq->drumTrans[program];
                if (program != 0xFF)
                {
                    seq->prgState[(u8)i].macId = *(u16*)((u8*)seq->drumtab + program * 6);
                    seq->prgState[(u8)i].priority = ((u8*)seq->drumtab)[program * 6 + 2];
                    seq->prgState[(u8)i].maxVoices = ((u8*)seq->drumtab)[program * 6 + 3];
                }
            }
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, i, seqId, midiData[5]);
            inpSetMidiCtrl(MCMD_CTRL_PANNING, i, seqId, midiData[6]);
            inpSetMidiCtrl(MCMD_CTRL_REVERB, i, seqId, midiData[7]);
            inpSetMidiCtrl(MCMD_CTRL_POST_AUX_B, i, seqId, midiData[8]);
            midiData += sizeof(SynthMidiChannelSetup);
        }
    }

    for (i = 0; i < 16; i++)
    {
        gSynthVoiceNotes[seqId][i] = 0xFFFF;
    }

    for (i = 0; i < 16; i++)
    {
        seq->section[i].time[0].high = 0;
        seq->section[i].time[0].low = 0;
        seq->section[i].time[1].high = 0;
        seq->section[i].time[1].low = 0;
        seq->section[i].timeIndex = 0;
    }

    seq->keyOffCheck = 0;

    if (para != 0 && (para->flags & 0x10) != 0)
    {
        synthQueueVoice(seq);
    }

    prevCurSeq = gSynthCurrentVoice;
    gSynthCurrentVoice = seq;
    fn_8026E864();
    gSynthCurrentVoice = prevCurSeq;
    return synthAssignHandle(seqId);
}

/*
 * Advance the master (tempo) track of one sequence section (HandleMasterTrack).
 */
void seqHandleMasterTrack(u8 secIndex)
{
    SynthSequenceQueue* section;

    section = SYNTH_SEQUENCE_QUEUE(gSynthCurrentVoice, secIndex);
    if (section->masterTrackBase != 0)
    {
        while (((SynthMasterTrackEvent*)section->masterTrackCursor)->time != 0xFFFFFFFF)
        {
            if (((SynthMasterTrackEvent*)section->masterTrackCursor)->time > section->time[section->timeIndex].high)
            {
                break;
            }

            if (((SynthArrangement*)gSynthCurrentVoice->arrbase)->info & 0x40000000)
            {
                synthSetStudioChannelScale((section->bpm = ((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm) >>
                                               10,
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

static inline void synthKillVoiceCallbacks(SynthVoice* voice)
{
    SynthCallbackLink* callback;
    u32 i;

    for (i = 0; i < 2; i++)
    {
        for (callback = voice->callbackLists[i]; callback != 0; callback = callback->next)
        {
            voiceKillById(callback->callbackId);
        }
    }

    for (callback = voice->callbackLists[2]; callback != 0; callback = callback->next)
    {
        voiceKillById(callback->callbackId);
    }
}

/*
 * Move a queued handle to the allocated list after a delayed fade completes.
 */
void synthQueueHandle(u32 handle)
{
    u32 slot;
    SynthVoice* voice;

    slot = synthResolveHandleSlot(handle);

    if (slot == 0xffffffff)
        return;

    if ((slot & 0x80000000) == 0)
    {
        SynthVoice* target = &gSynthVoices[slot];
        if (target->state != SYNTH_VOICE_STATE_QUEUED)
            return;
        voice = target;

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
        synthKillVoiceCallbacks(voice);
        synthRecycleVoiceCallbacks(voice);
    }
    else
    {
        u32 idx = slot & 0x7fffffffu;
        voice = &gSynthVoices[idx];
        if (voice->state == SYNTH_VOICE_STATE_FREE)
            return;
        voice->pendingUpdate.flags |= 8;
    }
}

/*
 * Stop a sequence voice, clean up callbacks, and return the voice to the
 * free list. Deferred handles clear the pending output word instead.
 */
void synthFreeHandle(u32 handle)
{
    SynthSeqRuntime* runtime;
    SynthVoice* voice;
    u32 slot;
    u32 i;
    SynthVoiceRuntimeView* runtimeView;

    runtime = (SynthSeqRuntime*)(void*)gSynthCallbacks;

    slot = synthResolveHandleSlot(handle);

    if (slot == 0xffffffff)
    {
        return;
    }

    if ((slot & 0x80000000) == 0)
    {
        runtimeView = (SynthVoiceRuntimeView*)(runtime->bytes + slot * 6248);
        voice = &runtimeView->voice;
        switch (runtimeView->voice.state)
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
                i = 0;
                for (; i < 2; i++)
                {
                    SynthCallbackLink* callback = voice->callbackLists[i];
                    while (callback != 0)
                    {
                        voiceKillById(callback->callbackId);
                        callback = callback->next;
                    }
                }
            }
            {
                SynthCallbackLink* callback = runtime->data.voices[slot].callbackLists[2];
                while (callback != 0)
                {
                    voiceKillById(callback->callbackId);
                    callback = callback->next;
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
        if ((voice = &runtime->data.voices[slot & 0x7fffffffu],
             runtime->data.voices[slot & 0x7fffffffu].state) != SYNTH_VOICE_STATE_FREE)
        {
            voice->pendingUpdate.output = 0;
        }
    }
}

/*
 * Update sequence playback speed immediately, or queue it for a deferred
 * handle update.
 */
void synthSetHandleValue16(u32 handle, u16 speed)
{
    u32 slot;
    SynthSeqRuntime* runtime;
    SynthVoice* voice;

    runtime = (SynthSeqRuntime*)(void*)gSynthCallbacks;
    slot = synthResolveHandleSlot(handle);

    if ((slot & 0x80000000) == 0)
    {
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 0) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 1) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 2) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 3) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 4) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 5) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 6) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 7) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 8) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 9) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 10) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 11) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 12) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 13) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 14) = speed;
        SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, slot, 15) = speed;
    }
    else
    {
        u32 idx = slot & 0x7fffffffu;
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
    u32 slot;
    SynthVoice* voice;

    slot = synthResolveHandleSlot(handle);

    if ((slot & 0x80000000) == 0)
    {
        voice = &gSynthVoices[slot];
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
        gSynthVoices[slot & 0x7fffffffu].pendingUpdate.flags &= ~8;
    }
}

u16 gSynthVoiceNotes[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];
SynthVoice gSynthVoices[SYNTH_MAX_VOICES];
