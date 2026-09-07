#include "src/musyx/runtime/synth_internal.h"
#include "musyx/synth_delay.h"
#include <stddef.h>
#include "musyx/synth_seq_dispatch.h"
#include "musyx/synth_volume.h"
#include "musyx/inp_midi.h"
#include "musyx/voice_manage.h"
#include "musyx/synth_queue.h"
#include "musyx/synth_callback.h"
#include "musyx/synth_channel_scale.h"
#include "musyx/snd_synth_api.h"
#include "musyx/synth_control.h"
#include "musyx/synth_handle.h"
#include "musyx/snd_groups.h"
#include "musyx/synth_seq_events.h"
#include "types.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"
#include "musyx/synth_voice.h"
#include "musyx/mcmd.h"
#include "musyx/hw_init.h"
#include "musyx/voice_id.h"
#include "musyx/synth_config.h"
#include "musyx/synth_job_queue.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

SynthCallbackLink seqNote[SYNTH_CALLBACK_COUNT];
SynthVoice seqInstance[SYNTH_MAX_VOICES];
u16 seqMIDIPriority[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];

#define SYNTH_CALLBACK_ACTIVE_LIST_COUNT    2
#define SYNTH_CALLBACK_COMPLETED_LIST_INDEX 2

static void ClearNotes(void) {
    SynthCallbackLink* prev;
    SynthCallbackLink* callback;
    u32 i;

    prev = NULL;
    noteFree = &seqNote[0];
    for (i = 0; i < 0x100; i++) {
        callback = &seqNote[i];
        callback->prev = prev;
        if (prev != NULL) {
            prev->next = callback;
        }
        prev = callback;
    }
    prev->next = NULL;
}

void ResetNotes(SynthVoice* voice) {
    SynthCallbackLink* callback;

    s32 listIndex;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++) {
        if ((callback = voice->callbackLists[listIndex]) != 0) {
            while (callback->next != 0) {
                callback = callback->next;
            }

            if (noteFree != 0) {
                callback->next = noteFree;
                noteFree->prev = callback;
            }

            noteFree = voice->callbackLists[listIndex];
            voice->callbackLists[listIndex] = 0;
        }
    }

    if ((callback = voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]) != 0) {
        while (callback->next != 0) {
            callback = callback->next;
        }

        if (noteFree != 0) {
            callback->next = noteFree;
            noteFree->prev = callback;
        }

        noteFree = voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
        voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = 0;
    }
}

SynthCallbackLink* AllocateNote(s32 triggerValue, u8 controllerIndex) {
    SynthCallbackLink* callback;
    SynthCallbackLink* next;
    register SynthCallbackLink* current;
    register SynthCallbackLink* prev;

    if ((callback = noteFree) != 0) {
        noteFree = next = callback->next;
        if (next != 0) {
            noteFree->prev = 0;
        }

        callback->triggerValue = triggerValue;
        callback->controllerIndex = controllerIndex;
        prev = 0;
        callback->listIndex = cseq->section[controllerIndex].timeIndex;

        current = cseq->callbackLists[callback->listIndex];
        while (current != 0) {
            if (current->triggerValue > callback->triggerValue) {
                callback->next = current;
                callback->prev = prev;
                if (prev != 0) {
                    prev->next = callback;
                } else {
                    cseq->callbackLists[callback->listIndex] = callback;
                }
                current->prev = callback;
                return callback;
            }

            prev = current;
            current = current->next;
        }

        callback->prev = prev;
        if (prev != 0) {
            prev->next = callback;
        } else {
            cseq->callbackLists[callback->listIndex] = callback;
        }
        callback->next = 0;
    }

    return callback;
}

s32 HandleNotes(void) {
    SynthCallbackLink* callback;
    u32 listIndex;
    SynthCallbackLink* next;
    SynthCallbackLink* completed;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++) {
        if ((callback = cseq->callbackLists[listIndex]) != 0) {
            while (callback->triggerValue <= (s32)cseq->section[callback->controllerIndex].time[listIndex].high) {
                synthSendKeyOff(callback->callbackId);
                next = callback->next;
                cseq->callbackLists[listIndex] = next;
                if (next != 0) {
                    cseq->callbackLists[listIndex]->prev = 0;
                }

                completed = cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
                callback->next = completed;
                if (completed != 0) {
                    cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
                }
                cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
                if ((callback = cseq->callbackLists[listIndex]) == 0) {
                    break;
                }
            }
        }
    }

    return cseq->callbackLists[0] != 0 || cseq->callbackLists[1] != 0;
}

void KeyOffNotes(void) {
    SynthCallbackLink* callback;
    SynthCallbackLink* next;
    u32 listIndex;
    SynthCallbackLink* completed;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++) {
        callback = cseq->callbackLists[listIndex];
        while (callback != 0) {
            next = callback->next;
            synthSendKeyOff(callback->callbackId);
            completed = callback->next;
            cseq->callbackLists[listIndex] = completed;
            if (completed != 0) {
                cseq->callbackLists[listIndex]->prev = 0;
            }

            completed = cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
            callback->next = completed;
            if (completed != 0) {
                cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
            }
            cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
            callback = next;
        }
    }
}

void seqFreeKeyOffNote(SynthCallbackLink* callback) {
    if (callback->next != 0) {
        callback->next->prev = callback->prev;
    }

    if (callback->prev != 0) {
        callback->prev->next = callback->next;
    } else {
        cseq->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback->next;
    }

    {
        SynthCallbackLink* freeCallback = noteFree;
        callback->next = freeCallback;
        if (freeCallback != 0) {
            noteFree->prev = callback;
        }
    }

    callback->prev = 0;
    noteFree = callback;
}

u32 GetPublicId(s32 voiceIndex) {
    SynthVoice* queuedVoices;
    SynthVoice* allocatedVoices;
    u32 handle;
    SynthVoice* current;

    queuedVoices = seqActiveRoot;
    allocatedVoices = seqPausedRoot;
    do {
        handle = seq_next_id;
        seq_next_id = handle + 1;
        seq_next_id &= SYNTH_HANDLE_ID_MASK;

        for (current = queuedVoices; current != 0; current = current->next) {
            if (current->handle == handle) {
                handle = SYNTH_HANDLE_INVALID;
                break;
            }
        }

        for (current = allocatedVoices; current != 0; current = current->next) {
            if (current->handle == handle) {
                handle = SYNTH_HANDLE_INVALID;
                break;
            }
        }
    } while (handle == SYNTH_HANDLE_INVALID);

    seqInstance[voiceIndex].handle = handle;
    return handle;
}

u32 seqGetPrivateId(u32 seqId) {
    SynthVoice* voice;
    for (voice = seqActiveRoot; voice != 0; voice = voice->next) {
        if (voice->handle == (seqId & SYNTH_HANDLE_ID_MASK)) {
            return voice->slotIndex | (seqId & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    for (voice = seqPausedRoot; voice != 0; voice = voice->next) {
        if (voice->handle == (seqId & SYNTH_HANDLE_ID_MASK)) {
            return voice->slotIndex | (seqId & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    return SYNTH_HANDLE_INVALID;
}

/* Sequence state and its owning intrusive list. */
#define SYNTH_SEQUENCE_STATE_FREE   0 /* unallocated */
#define SYNTH_SEQUENCE_STATE_ACTIVE 1 /* on seqActiveRoot */
#define SYNTH_SEQUENCE_STATE_PAUSED 2 /* on seqPausedRoot */

static void StartPause(SynthVoice* voice);

static inline void BuildTransTab(u8* tab, SynthPage* page) {
    u8 i;

    for (i = 0; i < 128; ++i) {
        tab[i] = 0xff;
    }

    for (i = 0; page->index != 0xFF; ++i, ++page) {
        tab[page->index] = i;
    }
}

u32 seqStartPlay(SynthPage* norm, SynthPage* drum, SynthMidiSetup* midiSetup, u32* song, SynthPlayParams* para,
                 u8 studio, u16 sgid) {
    SynthVoice* prevCurSeq;
    u32 bpm;
    SynthVoice* seq;
    u32 seqId;
    long i;
    u32* trackOffsets;
    SynthArrangement* arrangement;
    u8 program;

    if ((seq = seqFreeRoot) == 0) {
        return SYNTH_HANDLE_INVALID;
    }
    if ((seqFreeRoot = seq->next) != 0) {
        seqFreeRoot->prev = 0;
    }
    if ((seq->next = seqActiveRoot) != 0) {
        seqActiveRoot->prev = seq;
    }
    seq->prev = 0;
    seqActiveRoot = seq;
    seq->state = SYNTH_SEQUENCE_STATE_ACTIVE;
    for (i = 0; i < 16; i++) {
        seq->section[i].eventList = 0;
    }

    seqId = seq->slotIndex;
    seq->syncActive = 0;
    seq->normtab = norm;
    seq->drumtab = drum;
    seq->arrbase = (u8*)song;
    seq->groupId = sgid;

    BuildTransTab(seq->normTrans, seq->normtab);
    BuildTransTab(seq->drumTrans, seq->drumtab);

    seq->defaultVolumeGroup = seqId + 23;
    for (i = 0; i < 64; i++) {
        seq->trackVolumeGroup[i] = seq->defaultVolumeGroup;
    }

    seq->defStudio = studio;
    if (para == 0) {
        seq->trackMute[0] = -1;
        seq->trackMute[1] = -1;
        for (i = 0; i < 16; i++) {
            seq->section[i].speed = 0x100;
        }
        synthVolume(0x7F, 0, seq->defaultVolumeGroup, 0, -1);
    } else {
        if (para->flags & 1) {
            seq->trackMute[0] = para->trackMute[0];
            seq->trackMute[1] = para->trackMute[1];
        } else {
            seq->trackMute[0] = -1;
            seq->trackMute[1] = -1;
        }

        if (para->flags & 2) {
            for (i = 0; i < 16; i++) {
                seq->section[i].speed = para->speed;
            }
        } else {
            for (i = 0; i < 16; i++) {
                seq->section[i].speed = 0x100;
            }
        }

        if (para->flags & 8) {
            for (i = 0; i < para->numSeqVolumeDefinitions; i++) {
                seq->trackVolumeGroup[para->seqVolumeDefinitions[i].track] = para->seqVolumeDefinitions[i].volumeGroup;
                synthSetMusicVolumeType(para->seqVolumeDefinitions[i].volumeGroup, 0);
            }
        }

        if (para->flags & 4) {
            synthVolume(para->volume.target, para->volume.time, seq->defaultVolumeGroup, 0, -1);
            for (i = 0; i < para->numFaded; i++) {
                synthVolume(para->volume.target, para->volume.time, para->faded[i], 0, -1);
            }
        }
    }

    arrangement = (SynthArrangement*)song;
    if (arrangement->info & 0x80000000) {
        seq->keyGroupMap = (u8*)(arrangement->trackSectionTableOffset + (u32)song);
    } else {
        seq->keyGroupMap = 0;
    }

    bpm = arrangement->info & 0x0FFFFFFF;
    if (!(arrangement->info & 0x40000000)) {
        bpm <<= 10;
    }

    for (i = 0; i < 16; i++) {
        seq->section[i].bpm = bpm;
        synthSetBpm(bpm >> 10, seqId, i);
        if (arrangement->masterTrackOffset != 0) {
            seq->section[i].masterTrackBase = (u8*)(arrangement->masterTrackOffset + (u32)song);
            seq->section[i].masterTrackCursor = seq->section[i].masterTrackBase;
        } else {
            seq->section[i].masterTrackBase = 0;
        }
        seq->section[i].loopDisable = 0;
        seq->section[i].loopCount = 0;
    }

    trackOffsets = (u32*)(arrangement->trackTableOffset + (u32)song);
    for (i = 0; i < 64; i++) {
        synthTrackVolume[i] = 0x7F;
        seq->pattern[i].noteData = 0;
        if (trackOffsets[i] != 0) {
            seq->track[i].current = seq->track[i].base = (u8*)(trackOffsets[i] + (u32)song);
        } else {
            seq->track[i].current = seq->track[i].base = 0;
        }
    }

    seq->callbackLists[0] = 0;
    seq->callbackLists[1] = 0;
    seq->callbackLists[2] = 0;

    for (i = 0; i < 16; i++) {
        inpResetMidiCtrl((u8)i, seqId, 1);
    }
    for (i = 0; i < 16; i++) {
        seq->prgState[i].macId = 0xFFFF;
    }
    for (i = 0; i < 16; i++) {
        inpResetChannelDefaults((u8)i, seqId);
    }

    if (midiSetup != NULL) {
        for (i = 0; i < 16; i++) {
            program = midiSetup->channel[i].program;
            seqMIDIPriority[curSeqId][(u8)i] = 0xFFFF;
            if ((u8)i != 9) {
                program = seq->normTrans[program];
                if (program != 0xFF) {
                    seq->prgState[(u8)i].macId = seq->normtab[program].macro;
                    seq->prgState[(u8)i].priority = seq->normtab[program].priority;
                    seq->prgState[(u8)i].maxVoices = seq->normtab[program].maxVoices;
                }
            } else {
                program = seq->drumTrans[program];
                if (program != 0xFF) {
                    seq->prgState[(u8)i].macId = seq->drumtab[program].macro;
                    seq->prgState[(u8)i].priority = seq->drumtab[program].priority;
                    seq->prgState[(u8)i].maxVoices = seq->drumtab[program].maxVoices;
                }
            }
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, i, seqId, midiSetup->channel[i].volume);
            inpSetMidiCtrl(MCMD_CTRL_PANNING, i, seqId, midiSetup->channel[i].panning);
            inpSetMidiCtrl(MCMD_CTRL_REVERB, i, seqId, midiSetup->channel[i].reverb);
            inpSetMidiCtrl(MCMD_CTRL_POST_AUX_B, i, seqId, midiSetup->channel[i].chorus);
        }
    }

    for (i = 0; i < 16; i++) {
        seqMIDIPriority[seqId][i] = 0xFFFF;
    }

    for (i = 0; i < 16; i++) {
        seq->section[i].time[0].high = 0;
        seq->section[i].time[0].low = 0;
        seq->section[i].time[1].high = 0;
        seq->section[i].time[1].low = 0;
        seq->section[i].timeIndex = 0;
    }

    seq->keyOffCheck = 0;

    if (para != 0 && (para->flags & 0x10) != 0) {
        StartPause(seq);
    }

    prevCurSeq = cseq;
    cseq = seq;
    InitTrackEvents();
    cseq = prevCurSeq;
    return GetPublicId(seqId);
}

/*
 * Advance the master (tempo) track of one sequence section (HandleMasterTrack).
 */
void HandleMasterTrack(u8 secIndex) {
    SynthSequenceQueue* section;

    section = &cseq->section[secIndex];
    if (section->masterTrackBase != 0) {
        while (((SynthMasterTrackEvent*)section->masterTrackCursor)->time != 0xFFFFFFFF) {
            if (((SynthMasterTrackEvent*)section->masterTrackCursor)->time > section->time[section->timeIndex].high) {
                break;
            }

            if (((SynthArrangement*)cseq->arrbase)->info & 0x40000000) {
                synthSetBpm((section->bpm = ((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm) >> 10, curSeqId,
                            secIndex);
            } else {
                synthSetBpm(((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm, curSeqId, secIndex);
                section->bpm = ((SynthMasterTrackEvent*)section->masterTrackCursor)->bpm << 10;
            }

            section->masterTrackCursor += 8;
        }
    }
}

static void StartPause(SynthVoice* voice) {
    if (voice->prev != 0) {
        voice->prev->next = voice->next;
    } else {
        seqActiveRoot = voice->next;
    }
    if (voice->next != 0) {
        voice->next->prev = voice->prev;
    }
    if ((voice->next = seqPausedRoot) != 0) {
        seqPausedRoot->prev = voice;
    }
    voice->prev = 0;
    seqPausedRoot = voice;
    voice->state = SYNTH_SEQUENCE_STATE_PAUSED;
}

static inline void KillNotes(SynthVoice* voice) {
    SynthCallbackLink* callback;
    u32 i;

    for (i = 0; i < 2; i++) {
        for (callback = voice->callbackLists[i]; callback != 0; callback = callback->next) {
            voiceKillSound(callback->callbackId);
        }
    }

    for (callback = voice->callbackLists[2]; callback != 0; callback = callback->next) {
        voiceKillSound(callback->callbackId);
    }
}

void seqPause(u32 seqId) {
    u32 slot;
    SynthVoice* voice;

    slot = seqGetPrivateIdInline(seqId);

    if (slot == 0xffffffff) {
        return;
    }

    if ((slot & 0x80000000) == 0) {
        SynthVoice* target = &seqInstance[slot];
        if (target->state != SYNTH_SEQUENCE_STATE_ACTIVE) {
            return;
        }
        voice = target;

        if (voice->prev != 0) {
            voice->prev->next = voice->next;
        } else {
            seqActiveRoot = voice->next;
        }
        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }

        if ((voice->next = seqPausedRoot) != 0) {
            seqPausedRoot->prev = voice;
        }
        voice->prev = 0;
        seqPausedRoot = voice;
        voice->state = SYNTH_SEQUENCE_STATE_PAUSED;
        KillNotes(voice);
        ResetNotes(voice);
    } else {
        u32 idx = slot & 0x7fffffffu;
        voice = &seqInstance[idx];
        if (voice->state == SYNTH_SEQUENCE_STATE_FREE) {
            return;
        }
        voice->syncCrossInfo.flags |= 8;
    }
}

void seqStop(u32 seqId) {
    SynthVoice* voice;
    u32 slot;

    slot = seqGetPrivateIdInline(seqId);

    if (slot == 0xffffffff) {
        return;
    }

    if ((slot & 0x80000000) == 0) {
        voice = &seqInstance[slot];
        switch (voice->state) {
        case SYNTH_SEQUENCE_STATE_ACTIVE:
            if (voice->prev != 0) {
                voice->prev->next = voice->next;
            } else {
                seqActiveRoot = voice->next;
            }

            KillNotes(voice);
            ResetNotes(voice);
            break;
        case SYNTH_SEQUENCE_STATE_PAUSED:
            if (voice->prev != 0) {
                voice->prev->next = voice->next;
            } else {
                seqPausedRoot = voice->next;
            }
            break;
        }

        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }
        voice->state = SYNTH_SEQUENCE_STATE_FREE;
        if (seqFreeRoot != 0) {
            seqFreeRoot->prev = voice;
        }
        voice->next = seqFreeRoot;
        voice->prev = 0;
        seqFreeRoot = voice;
    } else {
        if ((voice = &seqInstance[slot & 0x7fffffffu], seqInstance[slot & 0x7fffffffu].state) !=
            SYNTH_SEQUENCE_STATE_FREE) {
            voice->syncSeqIdPtr = 0;
        }
    }
}

void seqSpeed(u32 seqId, u16 speed) {
    u32 slot;

    slot = seqGetPrivateIdInline(seqId);

    if ((slot & 0x80000000) == 0) {
        u32 section;
        for (section = 0; section < SYNTH_VOICE_NOTE_COUNT; section++) {
            seqInstance[slot].section[section].speed = speed;
        }
    } else {
        u32 idx = slot & 0x7fffffffu;
        seqInstance[idx].syncCrossInfo.flags |= SND_CROSSFADE_SPEED;
        seqInstance[idx].syncCrossInfo.speed2 = speed;
    }
}

void seqContinue(u32 seqId) {
    u32 slot;
    SynthVoice* voice;

    slot = seqGetPrivateIdInline(seqId);

    if ((slot & 0x80000000) == 0) {
        voice = &seqInstance[slot];
        if (voice->state != SYNTH_SEQUENCE_STATE_PAUSED) {
            return;
        }

        if (voice->prev != 0) {
            voice->prev->next = voice->next;
        } else {
            seqPausedRoot = voice->next;
        }
        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }

        if ((voice->next = seqActiveRoot) != 0) {
            seqActiveRoot->prev = voice;
        }
        voice->prev = 0;
        seqActiveRoot = voice;
        voice->state = SYNTH_SEQUENCE_STATE_ACTIVE;
    } else {
        seqInstance[slot & 0x7fffffffu].syncCrossInfo.flags &= ~8;
    }
}

void seqMute(u32 seqId, u32 mask1, u32 mask2) {
    u32 slot;

    slot = seqGetPrivateIdInline(seqId);

    if (slot == SYNTH_HANDLE_INVALID) {
        return;
    }

    if ((slot & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
        seqInstance[slot].trackMute[0] = mask1;
        seqInstance[slot].trackMute[1] = mask2;
    } else {
        seqInstance[slot & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |= SND_CROSSFADE_TRACKMUTE;
        seqInstance[slot & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[0] = mask1;
        seqInstance[slot & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[1] = mask2;
    }
}

void seqVolume(u8 volume, u16 time, u32 seqId, u8 mode) {
    u8* trackVolume;
    SynthVoice* voice;
    u32 voiceIndex;
    u32 studioIndex;
    u32 pub_id;

    pub_id = seqId;
    studioIndex = seqGetPrivateIdInline(seqId);

    if (studioIndex != SYNTH_HANDLE_INVALID) {
        if ((studioIndex & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
            voice = &seqInstance[studioIndex];
            synthVolume(volume, time, voice->defaultVolumeGroup, mode, pub_id);
            trackVolume = voice->trackVolumeGroup;
            voiceIndex = 0;
            do {
                if (*trackVolume != voice->defaultVolumeGroup) {
                    synthVolume(volume, time, *trackVolume, 0, SYNTH_HANDLE_INVALID);
                }
                trackVolume++;
                voiceIndex++;
            } while (voiceIndex < SYNTH_SEQUENCE_TRACK_COUNT);
        } else {
            seqId = studioIndex & SYNTH_HANDLE_ID_MASK;
            switch (mode & 0xF) {
            case 0:
                seqInstance[seqId].syncCrossInfo.vol2 = volume;
                break;
            case 1:
                seqInstance[seqId].syncSeqIdPtr = 0;
                break;
            case 2:
                seqInstance[seqId].syncCrossInfo.flags |= SND_CROSSFADE_PAUSENEW;
                seqInstance[seqId].syncCrossInfo.vol2 = volume;
                break;
            case 3:
                seqInstance[seqId].syncCrossInfo.flags |= SND_CROSSFADE_MUTENEW;
                seqInstance[seqId].syncCrossInfo.vol2 = volume;
                break;
            }
        }
    }
}

static inline u32 resolveHandle(u32 handle) {
    SynthVoice* voice;

    for (voice = seqActiveRoot; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & SYNTH_HANDLE_ID_MASK)) {
            return voice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    for (voice = seqPausedRoot; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & SYNTH_HANDLE_ID_MASK)) {
            return voice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    return SYNTH_HANDLE_INVALID;
}

void seqCrossFade(SynthStartRequest* ci, u32* new_seqId, u8 irq_call) {
    SynthPlayParams params;
    u32 deadSlot2;
    u32 slot;
    u32 newHandle;
    u32 mixValue0;
    u32 mixValue1;
    u16 speed;
    u16 fadeTime;
    u8 flags;
    SynthVoice* pendingVoice;
    SynthStartRequest* pendingRequest;

    slot = resolveHandle(ci->seqId1);
    flags = ci->flags;
    if ((flags & SND_CROSSFADE_SYNC) != 0) {
        pendingVoice = &seqInstance[slot];
        pendingRequest = &pendingVoice->syncCrossInfo;
        *pendingRequest = *ci;
        pendingVoice->syncActive = 1;
        pendingVoice->syncSeqIdPtr = new_seqId;
        pendingRequest->flags &= ~SND_CROSSFADE_SYNC;
        *new_seqId = ci->seqId1 | SYNTH_HANDLE_QUEUED_FLAG;
        return;
    }

    if (irq_call != 0) {
        fadeTime = ci->time1 < 5 ? 5 : ci->time1;
        if ((flags & SND_CROSSFADE_PAUSE) != 0) {
            seqVolume(0, fadeTime, ci->seqId1, 2);
        } else if ((flags & SND_CROSSFADE_MUTE) != 0) {
            seqVolume(0, fadeTime, ci->seqId1, 3);
        } else {
            seqVolume(0, fadeTime, ci->seqId1, 1);
        }
    } else {
        if ((flags & SND_CROSSFADE_PAUSE) != 0) {
            sndSeqVolume(0, ci->time1, ci->seqId1, 2);
        } else if ((flags & SND_CROSSFADE_MUTE) != 0) {
            sndSeqVolume(0, ci->time1, ci->seqId1, 3);
        } else {
            sndSeqVolume(0, ci->time1, ci->seqId1, 1);
        }
    }

    if (new_seqId == 0) {
        return;
    }

    if ((ci->flags & SND_CROSSFADE_CONTINUE) != 0) {
        if ((slot = resolveHandle(ci->seqId2)) != SYNTH_HANDLE_INVALID) {
            if (irq_call != 0) {
                seqContinue(ci->seqId2);
                seqVolume(ci->vol2, ci->time2, ci->seqId2, 0);
                if ((ci->flags & SND_CROSSFADE_TRACKMUTE) != 0) {
                    newHandle = ci->seqId2;
                    mixValue1 = ci->trackMute2[1];
                    mixValue0 = ci->trackMute2[0];
                    newHandle = seqGetPrivateId(newHandle);
                    if (newHandle != SYNTH_HANDLE_INVALID) {
                        if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
                            seqInstance[newHandle].trackMute[0] = mixValue0;
                            seqInstance[newHandle].trackMute[1] = mixValue1;
                        } else {
                            seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |=
                                SND_CROSSFADE_TRACKMUTE;
                            seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[0] = mixValue0;
                            seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[1] = mixValue1;
                        }
                    }
                }
                if ((ci->flags & SND_CROSSFADE_SPEED) != 0) {
                    newHandle = ci->seqId2;
                    speed = ci->speed2;
                    newHandle = seqGetPrivateId(newHandle);
                    if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
                        u32 section;
                        for (section = 0; section < SYNTH_VOICE_NOTE_COUNT; section++) {
                            seqInstance[newHandle].section[section].speed = speed;
                        }
                    } else {
                        seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |= SND_CROSSFADE_SPEED;
                        seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.speed2 = speed;
                    }
                }
            } else {
                sndSeqContinue(ci->seqId2);
                sndSeqVolume(ci->vol2, ci->time2, ci->seqId2, 0);
                if ((ci->flags & SND_CROSSFADE_TRACKMUTE) != 0) {
                    sndSeqMute(ci->seqId2, ci->trackMute2[0], ci->trackMute2[1]);
                }
                if ((ci->flags & SND_CROSSFADE_SPEED) != 0) {
                    sndSeqSpeed(ci->seqId2, ci->speed2);
                }
            }
            *new_seqId = ci->seqId2;
            return;
        }
        *new_seqId = SYNTH_HANDLE_INVALID;
        return;
    }

    params.flags = 4;
    if ((ci->flags & SND_CROSSFADE_PAUSENEW) != 0) {
        params.flags |= 0x10;
    }
    if ((ci->flags & SND_CROSSFADE_SPEED) != 0) {
        params.flags |= 2;
        params.speed = ci->speed2;
    }
    if ((ci->flags & SND_CROSSFADE_TRACKMUTE) != 0) {
        params.flags |= 1;
        params.trackMute[0] = ci->trackMute2[0];
        params.trackMute[1] = ci->trackMute2[1];
    }
    params.volume.time = ci->time2;
    params.volume.target = ci->vol2;
    params.numFaded = 0;

    if (irq_call != 0) {
        newHandle = seqPlaySong(ci->gid2, ci->sid2, (void*)ci->arr2, &params, 1, ci->studio2);
        *new_seqId = newHandle;
        if ((newHandle != SYNTH_HANDLE_INVALID) && ((ci->flags & SND_CROSSFADE_MUTENEW) != 0)) {
            newHandle = seqGetPrivateId(*new_seqId);
            if (newHandle != SYNTH_HANDLE_INVALID) {
                if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
                    seqInstance[newHandle].trackMute[0] = 0;
                    seqInstance[newHandle].trackMute[1] = 0;
                } else {
                    seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |= SND_CROSSFADE_TRACKMUTE;
                    seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[0] = 0;
                    seqInstance[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[1] = 0;
                }
            }
        }
    } else {
        newHandle = sndSeqPlayEx(ci->gid2, ci->sid2, (void*)ci->arr2, &params, ci->studio2);
        *new_seqId = newHandle;
        if ((newHandle != SYNTH_HANDLE_INVALID) && ((ci->flags & SND_CROSSFADE_MUTENEW) != 0)) {
            sndSeqMute(*new_seqId, 0, 0);
        }
    }
}

/*
 * Parse a 1-or-2-byte unsigned event tag followed by a 1-or-2-byte signed
 * value. Returns the advanced read pointer, or NULL when the tag is the
 * sentinel 0x80 0x00.
 */
u8* GetStreamValue(u8* p, u16* tagOut, s16* valueOut) {
    s16 combined;
    s32 shift;
    u32 combinedValue;
    u8 high;
    u8 low;

    high = p[0];
    low = p[1];
    if (high == SYNTH_VARIABLE_PAIR_EXTENDED_FLAG && low == SYNTH_VARIABLE_PAIR_END_LOW) {
        return 0;
    }

    if ((high & SYNTH_VARIABLE_PAIR_EXTENDED_FLAG) != 0) {
        combinedValue = (u32)((high & SYNTH_VARIABLE_PAIR_VALUE_MASK) << 8);
        combinedValue = combinedValue | low;
        *tagOut = combinedValue;
        p += 2;
    } else {
        *tagOut = high;
        p += 1;
    }

    high = p[0];
    low = p[1];
    if ((high & SYNTH_VARIABLE_PAIR_EXTENDED_FLAG) != 0) {
        combinedValue = (u32)((high & SYNTH_VARIABLE_PAIR_VALUE_MASK) << 8);
        combinedValue = combinedValue | low;
        combined = combinedValue;
        shift = 1;
        combined <<= shift;
        combined >>= shift;
        *valueOut = combined;
        p += 2;
    } else {
        combined = high;
        shift = 9;
        combined <<= shift;
        combined >>= shift;
        *valueOut = combined;
        p += 1;
    }

    return p;
}

#define SYNTH_TRACK_COMMAND_END  0xFFFF
#define SYNTH_TRACK_COMMAND_JUMP 0xFFFE

#define TRACK_CMD(cursor) ((SynthTrackCommand*)(cursor)->current)

SynthSequenceEvent* GenerateNextTrackEvent(u8 channel) {
    u32 trackId;
    SynthTrackCursor* track;
    SynthSequenceEvent* ev;
    SynthSequenceState* pattern;
    u32 patternTime;
    u32 pitchTime;
    u32 modTime;

    trackId = channel;
    track = &cseq->track[channel];
    pattern = &cseq->pattern[trackId];

    if (track->current != 0) {
        ev = &cseq->channelEvents[trackId];
        ev->trackId = channel;
        ev->state = pattern;

        for (;;) {
            if (pattern->noteData == 0) {
            process_track_command:
                if (TRACK_CMD(track)->command == SYNTH_TRACK_COMMAND_END) {
                    track->current = 0;
                    return 0;
                }

                if (TRACK_CMD(track)->command == SYNTH_TRACK_COMMAND_JUMP) {
                    if (cseq->keyGroupMap == 0) {
                        if (cseq->section[0].loopDisable) {
                            track->current = 0;
                            return 0;
                        }
                    } else if (cseq->section[cseq->keyGroupMap[trackId]].loopDisable) {
                        track->current = 0;
                        return 0;
                    }

                    ev->type = 3;
                    ev->time = TRACK_CMD(track)->value0;
                    track->current = track->base + TRACK_CMD(track)->arg * sizeof(SynthTrackCommand);
                    return ev;
                }

                ev->type = 4;
                ev->time = TRACK_CMD(track)->value0;
                ev->data = track->current;
                track->current = TRACK_CMD(track) + 1;
                return ev;
            }

            pitchTime = pattern->pitchBend.nextTime;
            modTime = pattern->modulation.nextTime;

            for (;;) {
                patternTime = *(u16*)pattern->noteData + pattern->lastTime;
                if (patternTime < pitchTime) {
                    if (patternTime >= modTime) {
                        goto modulation_event;
                    }
                    if (pattern->noteData[2] == 0xFF && pattern->noteData[3] == 0xFF) {
                        pattern->noteData = 0;
                        goto process_track_command;
                    }

                    ev->data = pattern->noteData;
                    pattern->lastTime = patternTime;

                    if ((pattern->noteData[2] & 0x80) != 0) {
                        pattern->noteData += 4;
                    } else if ((pattern->noteData[2] | pattern->noteData[3]) == 0) {
                        pattern->noteData += 4;
                        continue;
                    } else {
                        pattern->noteData += 6;
                    }
                    ev->type = 0;
                    ev->time = patternTime + pattern->baseTime;
                } else if (pitchTime < modTime) {
                    ev->time = pitchTime + pattern->baseTime;
                    ev->type = 2;
                } else {
                modulation_event:
                    ev->time = modTime + pattern->baseTime;
                    ev->type = 1;
                }
                return ev;
            }
        }
    }

    return 0;
}

/*
 * Sorted-by-time insert into a channel event queue.
 */
void InsertGlobalEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event) {
    SynthSequenceEvent* current;
    SynthSequenceEvent* prev;

    prev = 0;
    current = queue->eventList;
    while (current != 0) {
        if (current->time > event->time) {
            event->next = current;
            event->prev = prev;
            if (prev != 0) {
                prev->next = event;
            } else {
                queue->eventList = event;
            }
            current->prev = event;
            return;
        }

        prev = current;
        current = current->next;
    }

    event->prev = prev;
    if (prev != 0) {
        prev->next = event;
    } else {
        queue->eventList = event;
    }
    event->next = 0;
}

typedef struct {
    u32 time;       // 0x0
    u8 prgChange;   // 0x4
    u8 velocity;    // 0x5
    u8 res[2];      // 0x6
    u16 pattern;    // 0x8
    s8 transpose;   // 0xa
    s8 velocityAdd; // 0xb
} SeqTrackEntry;    // size 0xc

typedef struct {
    u16 time;    // 0x0
    u8 key;      // 0x2
    u8 velocity; // 0x3
    u16 length;  // 0x4
} SeqNoteData;   // size 0x6

/* Standard MIDI controller (CC) numbers dispatched by the sequencer. */

/* Sequencer meta-command sub-codes (carried in the high nibble of a note event). */
#define SEQ_META_KEY_OFF       0x82
#define SEQ_META_START_PENDING 0x68
#define SEQ_META_LOOP_MARK     0x69
#define SEQ_META_LOOP_MARK_HI  0x6a
#define SEQ_META_RESET_CTRL    0x79
#define SEQ_META_ALL_NOTES_OFF 0x7b

/* Empty double-buffered time slot marker. */
#define SEQ_TIME_EMPTY 0x7fffffff

SynthVoice* seqActiveRoot;
SynthVoice* seqPausedRoot;
SynthVoice* seqFreeRoot;
u32 seq_next_id;
u8 curFadeOutState;
u32 curSeqId;
SynthCallbackLink* noteFree;
SynthVoice* cseq;

static inline void InitStream(SynthSequenceStream* stream, u32 streamDataOffset) {
    u16 delta;

    if (streamDataOffset != 0) {
        if ((stream->cursor = GetStreamValue((u8*)(streamDataOffset + (u32)cseq->arrbase), &delta, &stream->step)) !=
            0) {
            stream->nextTime = delta;
        } else {
            stream->nextTime = SEQ_TIME_EMPTY;
        }
    } else {
        stream->nextTime = SEQ_TIME_EMPTY;
    }
}

static inline u16 HandleStream(SynthSequenceStream* stream) {
    u16 delta;

    stream->value += stream->step;
    if (stream->cursor != 0) {
        if ((stream->cursor = GetStreamValue(stream->cursor, &delta, &stream->step)) != 0) {
            stream->nextTime += delta;
        } else {
            stream->nextTime = SEQ_TIME_EMPTY;
        }
    } else {
        stream->nextTime = SEQ_TIME_EMPTY;
    }
    return stream->value;
}

static inline void DoPrgChange(SynthVoice* voice, u8 program, u32 midi) {
    seqMIDIPriority[curSeqId][midi] = 0xFFFF;
    if (midi != 9) {
        program = voice->normTrans[program];
        if (program == 0xff) {
            return;
        }
        voice->prgState[midi].macId = voice->normtab[program].macro;
        voice->prgState[midi].priority = voice->normtab[program].priority;
        voice->prgState[midi].maxVoices = voice->normtab[program].maxVoices;
        return;
    }
    program = voice->drumTrans[program];
    if (program == 0xff) {
        return;
    }
    voice->prgState[midi].macId = voice->drumtab[program].macro;
    voice->prgState[midi].priority = voice->drumtab[program].priority;
    voice->prgState[midi].maxVoices = voice->drumtab[program].maxVoices;
}

/*
 * Dispatch a queued voice/MIDI channel event by type, then pull the next
 * event for the channel.
 */
SynthSequenceEvent* HandleEvent(SynthSequenceEvent* event, u8 voice, u32* flag) {
    SynthSequenceState* pa;
    SeqNoteData* pe;
    int velocity;
    int key;
    u32 midi;
    u16 macId;
    SynthCallbackLink* note;
    SeqTrackEntry* tEntry;
    SynthSequenceState* pattern;

    switch (event->type) {
    case 4: {
        SynthVoice* sv;
        u8* seq;
        SynthSeqPattern* pat;
        u8 prog;

        tEntry = (SeqTrackEntry*)event->data;
        sv = cseq;
        seq = sv->arrbase;
        pattern = &sv->pattern[event->trackId];
        pat =
            (SynthSeqPattern*)(*(u32*)(((SynthArrangement*)seq)->patternTableOffset + (u32)seq + tEntry->pattern * 4) +
                               (u32)seq);
        pattern->noteData = (u8*)(pat + 1);
        pattern->lastTime = 0;
        pattern->baseTime = tEntry->time;
        pattern->patternInfo = tEntry;
        InitStream(&pattern->pitchBend, pat->pitchBendOffset);
        pattern->pitchBend.value = 0x2000;
        InitStream(&pattern->modulation, pat->modulationOffset);
        pattern->modulation.value = 0;
        pattern->midi =
            *(u8*)(((SynthArrangement*)cseq->arrbase)->trackMidiTableOffset + (u32)cseq->arrbase + event->trackId);
        prog = tEntry->prgChange;
        if (prog != 0xff) {
            DoPrgChange(cseq, prog, pattern->midi);
        }
        if (tEntry->velocity != 0xff) {
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, pattern->midi, curSeqId & 0xff, tEntry->velocity);
        }
        break;
    }
    case 0:
        pe = (SeqNoteData*)event->data;
        pa = event->state;
        key = pe->key;
        velocity = pe->velocity;
        midi = pa->midi;

        if (key & 0x80) {
            switch (velocity) {
            case 0:
                DoPrgChange(cseq, key & 0x7f, midi);
                break;
            case 1:
                inpSetMidiCtrl(SEQ_META_KEY_OFF, midi, curSeqId & 0xff, key & 0x7f);
                break;
            default:
                if ((velocity & 0x80) == 0x80) {
                    switch (velocity & 0x7f) {
                    case SEQ_META_START_PENDING:
                        if (cseq->syncActive != 0) {
                            seqCrossFade(&cseq->syncCrossInfo, cseq->syncSeqIdPtr, 1);
                            cseq->syncActive = 0;
                        }
                        break;
                    case SEQ_META_LOOP_MARK:
                        seqMIDIPriority[curSeqId][midi] = key & 0x7f;
                        break;
                    case SEQ_META_LOOP_MARK_HI:
                        seqMIDIPriority[curSeqId][midi] = (key & 0x7f) + 0x80;
                        break;
                    case SEQ_META_RESET_CTRL:
                        inpResetMidiCtrl(midi, curSeqId & 0xff, 0);
                        break;
                    case SEQ_META_ALL_NOTES_OFF:
                        KeyOffNotes();
                        break;
                    default:
                        inpSetMidiCtrl(velocity & 0x7f, midi, curSeqId & 0xff, key & 0x7f);
                        break;
                    }
                }
                break;
            }
        } else {
            SynthVoice* sv = cseq;
            if (sv->trackMute[event->trackId / 32] & (1 << (event->trackId & 0x1f))) {
                if ((macId = sv->prgState[midi].macId) != 0xFFFF) {
                    key += ((SeqTrackEntry*)pa->patternInfo)->transpose;
                    key = key > 0x7f ? 0x7f : key < 0 ? 0 : key;
                    velocity += ((SeqTrackEntry*)pa->patternInfo)->velocityAdd;
                    velocity = velocity > 0x7f ? 0x7f : velocity < 0 ? 0 : velocity;
                    if ((note = AllocateNote(event->time + pe->length, voice)) != NULL) {
                        SynthVoice* sv2;
                        s16 mod;
                        u8 vt;
                        u8 tid;

                        mod = curFadeOutState != 0 ? -1 : 0;
                        sv2 = cseq;
                        tid = event->trackId;
                        vt = sv2->defStudio;
                        if ((note->callbackId = synthStartSound(
                                 macId, sv2->prgState[midi].priority, sv2->prgState[midi].maxVoices, key & 0xff,
                                 velocity & 0xff, 0x40, midi, curSeqId & 0xff, voice, 0, tid,
                                 sv2->trackVolumeGroup[tid], mod, vt, synthITDDefault[vt].music)) == 0xFFFFFFFF) {
                            if (note->next != 0) {
                                note->next->prev = note->prev;
                            }
                            if (note->prev != 0) {
                                note->prev->next = note->next;
                            } else {
                                cseq->callbackLists[note->listIndex] = note->next;
                            }
                            if ((note->next = noteFree) != 0) {
                                noteFree->prev = note;
                            }
                            note->prev = 0;
                            noteFree = note;
                        }
                    }
                }
            }
        }
        break;
    case 2:
        pa = event->state;
        inpSetMidiCtrl14(MCMD_CTRL_PITCH_BEND, pa->midi, curSeqId & 0xff, HandleStream(&pa->pitchBend));
        break;
    case 1:
        pa = event->state;
        inpSetMidiCtrl14(MCMD_CTRL_MODULATION, pa->midi, curSeqId & 0xff, HandleStream(&pa->modulation));
        break;
    case 3:
        *flag |= 1;
        return 0;
    }
    return GenerateNextTrackEvent(event->trackId);
}

/*
 * Queue each MIDI channel's initial event into its mapped sequence section.
 */
void InitTrackEvents(void) {
    u32 i;
    SynthSequenceEvent* event;

    if (cseq->keyGroupMap == 0) {
        for (i = 0; i < 0x40; i++) {
            event = GenerateNextTrackEvent((u8)i);
            if (event != 0) {
                InsertGlobalEvent(&cseq->section[0], event);
            }
        }
    } else {
        for (i = 0; i < 0x40; i++) {
            event = GenerateNextTrackEvent((u8)i);
            if (event != 0) {
                InsertGlobalEvent(&cseq->section[cseq->keyGroupMap[i]], event);
            }
        }
    }
}

/* Queue the next event for every MIDI channel mapped to one sequence section. */
static void InitTrackEventsSection(u8 sectionIndex) {
    u32 group;
    u32 i;
    SynthSequenceEvent* event;

    if (cseq->keyGroupMap == 0) {
        for (i = 0; i < 0x40; i++) {
            event = GenerateNextTrackEvent((u8)i);
            if (event != 0) {
                InsertGlobalEvent(&cseq->section[0], event);
            }
        }
    } else {
        group = sectionIndex & 0xff;
        for (i = 0; i < 0x40; i++) {
            if (group == cseq->keyGroupMap[i]) {
                event = GenerateNextTrackEvent((u8)i);
                if (event != 0) {
                    InsertGlobalEvent(&cseq->section[group], event);
                }
            }
        }
    }
}

static inline u32 GetNextEventTime(SynthSequenceQueue* section) {
    return section->eventList == NULL ? 0 : section->eventList->time;
}

static inline SynthSequenceEvent* GetGlobalEvent(SynthSequenceQueue* section) {
    SynthSequenceEvent* ev;

    ev = section->eventList;
    if (ev != NULL && (section->eventList = ev->next) != NULL) {
        section->eventList->prev = NULL;
    }
    return ev;
}

static inline f32 seq_fmod(f32 x, f32 y) {
    f32 ay;
    f32 ax;

    ay = __fabsf(y);
    ax = __fabsf(x);
    if (ay > ax) {
        return x;
    }
    return x - y * (f32)(s64)(u64)(x / y);
}

static inline void SetTickDelta(SynthSequenceQueue* section, u32 deltaTime) {
    f32 tickDelta;

    tickDelta = (1.f / 40960000.f) * ((f32)section->bpm * deltaTime);
    tickDelta *= (1.f / 256.f) * (f32)section->speed;
    section->tickDelta[section->timeIndex].low = seq_fmod(65536.f * tickDelta, 65536.f);
    section->tickDelta[section->timeIndex].high = (int)floorf(tickDelta);
}

u32 HandleTrackEvents(u8 voice, u32 param) {
    SynthSequenceQueue* vp;
    SynthSequenceEvent* event;
    SynthSequenceEvent* res;
    u32 flag;
    SynthTimeWord unusedTime;

    flag = 0;
    vp = &cseq->section[voice];
    while ((vp->eventList == NULL ? 0 : vp->eventList->time) <= vp->time[vp->timeIndex].high) {
        SynthSequenceEvent* ev = vp->eventList;
        if (ev != NULL && (vp->eventList = ev->next) != NULL) {
            vp->eventList->prev = NULL;
        }
        if ((event = ev) == NULL) {
            if (flag == 0) {
                return 0;
            }
            flag = 0;
            vp->timeIndex ^= 1;
            vp->time[vp->timeIndex].high = ((SynthArrangement*)cseq->arrbase)->loopPoint[voice];
            vp->time[vp->timeIndex].low = vp->time[vp->timeIndex ^ 1].low;
            {
                SynthSequenceQueue* section = &cseq->section[voice];
                if (section->masterTrackBase != NULL) {
                    section->masterTrackCursor = section->masterTrackBase;
                    HandleMasterTrack(voice);
                    SetTickDelta(&cseq->section[voice], param);
                }
            }
            vp->loopCount += 1;
            InitTrackEventsSection(voice);
            continue;
        }
        res = HandleEvent(event, voice, &flag);
        if (res != 0) {
            InsertGlobalEvent(vp, res);
        }
    }
    return 1;
}

/*
 * Per-sequence tick and event update pass.
 */
static inline f32 sal_fmod(f32 x, f32 y, f64 absy) {
    s64 n;

    if (absy > __fabs(x)) {
        return x;
    }
    n = (s64)(u64)(x / y);
    x = x - y * (f32)n;
    return x;
}

static inline void HandleKeyOffNotes(void) {
    SynthCallbackLink* node;
    SynthCallbackLink* next;

    if (cseq->keyOffCheck == 0) {
        node = cseq->callbackLists[2];
        while (node != NULL) {
            next = node->next;
            if ((node->callbackId != 0xffffffff) && (sndFXCheck(node->callbackId) == 0xffffffff)) {
                seqFreeKeyOffNote(node);
            }
            node = next;
        }
    }
    cseq->keyOffCheck = (cseq->keyOffCheck + 1) % 5;
}

static inline void SetTickDeltaInline(SynthSequenceQueue* section, u32 deltaTime, f32 c0, f32 c1, f32 range,
                                      f64 absRange) {
    f32 tickDelta = c0 * ((f32)section->bpm * deltaTime);
    tickDelta = tickDelta * (c1 * (f32)(u32)section->speed);

    section->tickDelta[section->timeIndex].low = sal_fmod(range * tickDelta, range, absRange);
    section->tickDelta[section->timeIndex].high = (s32)floorf(tickDelta);
}

static inline void HandleMasterTrackInline(u8 secIndex) {
    SynthSequenceQueue* section;
    u32* evt;

    section = &cseq->section[secIndex];
    if (section->masterTrackBase != NULL) {
        while (*(evt = (u32*)section->masterTrackCursor) != 0xffffffff) {
            if (*evt > section->time[section->timeIndex].high) {
                break;
            }
            if ((((SynthArrangement*)cseq->arrbase)->info & 0x40000000) != 0) {
                synthSetBpm((section->bpm = evt[1]) >> 10, curSeqId, secIndex);
            } else {
                synthSetBpm(evt[1], curSeqId, secIndex);
                section->bpm = ((u32*)section->masterTrackCursor)[1] << 10;
            }
            section->masterTrackCursor += 8;
        }
    }
}

void seqHandle(u32 deltaTime) {
    u32 tickSum;
    u32 sectionIndex;
    u32 timeIndex;
    u32 eventsActive;
    u32 callbacksActive;
    SynthVoice* song;
    SynthVoice* nextSong;
    f64 absoluteTickRange;
    f32 tickRange;

    if (deltaTime != 0) {
        tickRange = 65536.f;
        song = seqActiveRoot;
        absoluteTickRange = __fabs(tickRange);
        for (; song != NULL; song = nextSong) {
            nextSong = song->next;
            cseq = song;
            curSeqId = song->slotIndex;
            curFadeOutState = synthIsFadeOutActive(song->defaultVolumeGroup);
            if (cseq->keyGroupMap == NULL) {
                HandleMasterTrackInline(0);
                SetTickDeltaInline(cseq->section, deltaTime, (1.f / 40960000.f), 0.00390625f, tickRange,
                                   absoluteTickRange);
                eventsActive = HandleTrackEvents(0, deltaTime);
                callbacksActive = HandleNotes();
                HandleKeyOffNotes();
                for (sectionIndex = 0; sectionIndex < 2; ++sectionIndex) {
                    tickSum = cseq->section[0].time[sectionIndex].low + cseq->section[0].tickDelta[sectionIndex].low;
                    cseq->section[0].time[sectionIndex].low = tickSum & 0xffff;
                    tickSum = tickSum >> 16;
                    cseq->section[0].time[sectionIndex].high += tickSum + cseq->section[0].tickDelta[sectionIndex].high;
                }
            } else {
                eventsActive = 0;
                for (sectionIndex = 0; sectionIndex < 0x10; sectionIndex++) {
                    HandleMasterTrackInline(sectionIndex);
                    SetTickDeltaInline(&cseq->section[sectionIndex], deltaTime, (1.f / 40960000.f), 0.00390625f,
                                       tickRange, absoluteTickRange);
                    eventsActive |= HandleTrackEvents(sectionIndex, deltaTime);
                }
                callbacksActive = HandleNotes();
                HandleKeyOffNotes();
                for (sectionIndex = 0; sectionIndex < 16; sectionIndex++) {
                    for (timeIndex = 0; timeIndex < 2; ++timeIndex) {
                        tickSum = cseq->section[sectionIndex].time[timeIndex].low +
                                  cseq->section[sectionIndex].tickDelta[timeIndex].low;
                        cseq->section[sectionIndex].time[timeIndex].low = tickSum & 0xffff;
                        tickSum = tickSum >> 16;
                        cseq->section[sectionIndex].time[timeIndex].high +=
                            tickSum + cseq->section[sectionIndex].tickDelta[timeIndex].high;
                    }
                }
            }
            if ((eventsActive == 0) && (callbacksActive == 0)) {
                if (song->prev != NULL) {
                    song->prev->next = nextSong;
                } else {
                    seqActiveRoot = nextSong;
                }
                if (nextSong != NULL) {
                    nextSong->prev = song->prev;
                }
                ResetNotes(song);
                song->state = 0;
                song->prev = NULL;
                if ((song->next = seqFreeRoot) != NULL) {
                    seqFreeRoot->prev = song;
                }
                seqFreeRoot = song;
            }
        }
    }
}

/*
 * Initialize sequence instances, note priorities, and callback links.
 */
void seqInit(void) {
    u16* note;
    SynthVoice* voice;
    u32 i;
    int j;

    seqActiveRoot = NULL;
    seqPausedRoot = NULL;
    voice = &seqInstance[0];
    note = seqMIDIPriority[0];
    for (i = 0; i < 8; i++) {
        if (i == 0) {
            seqFreeRoot = voice;
            voice->prev = NULL;
        } else {
            (voice - 1)->next = voice;
            voice->prev = &seqInstance[i - 1];
        }
        voice->slotIndex = i;
        voice->state = 0;
        for (j = 0; j < 16; j++) {
            note[j] = 0xffff;
        }
        note += 16;
        voice++;
    }
    seqInstance[i - 1].next = NULL;

    ClearNotes();
    seq_next_id = 0;
}
