#include <stddef.h>
#include "src/musyx/runtime/synth_internal.h"
#include "musyx/synth_seq_dispatch.h"
#include "musyx/synth_volume.h"
#include "musyx/inp_midi.h"
#include "musyx/voice_manage.h"
#include "musyx/synth_queue.h"
#include "musyx/synth_callback.h"
#include "musyx/synth_channel_scale.h"

/* SynthVoice.state - which intrusive list the voice sits on */
#define SYNTH_VOICE_STATE_FREE      0 /* unallocated */
#define SYNTH_VOICE_STATE_QUEUED    1 /* on seqActiveRoot; awaiting start */
#define SYNTH_VOICE_STATE_ALLOCATED 2 /* on seqPausedRoot; playing */

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
    seq->state = SYNTH_VOICE_STATE_QUEUED;
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
    voice->state = SYNTH_VOICE_STATE_ALLOCATED;
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
        if (target->state != SYNTH_VOICE_STATE_QUEUED) {
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
        voice->state = SYNTH_VOICE_STATE_ALLOCATED;
        KillNotes(voice);
        ResetNotes(voice);
    } else {
        u32 idx = slot & 0x7fffffffu;
        voice = &seqInstance[idx];
        if (voice->state == SYNTH_VOICE_STATE_FREE) {
            return;
        }
        voice->syncCrossInfo.flags |= 8;
    }
}

void seqStop(u32 seqId) {
    SynthVoiceRuntime* runtime;
    SynthVoice* voice;
    u32 slot;
    u32 i;
    u8* slotBase;

    runtime = SYNTH_VOICE_RUNTIME();

    slot = seqGetPrivateIdInline(seqId);

    if (slot == 0xffffffff) {
        return;
    }

    if ((slot & 0x80000000) == 0) {
        slotBase = (u8*)runtime + slot * sizeof(SynthVoice);
        voice = (SynthVoice*)(slotBase + offsetof(SynthVoiceRuntime, voices));
        switch (((SynthVoice*)(slotBase + offsetof(SynthVoiceRuntime, voices)))->state) {
        case SYNTH_VOICE_STATE_QUEUED:
            if (voice->prev != 0) {
                voice->prev->next = voice->next;
            } else {
                seqActiveRoot = voice->next;
            }

            {
                for (i = 0; i < 2; i++) {
                    SynthCallbackLink* callback = voice->callbackLists[i];
                    while (callback != 0) {
                        voiceKillSound(callback->callbackId);
                        callback = callback->next;
                    }
                }
            }
            {
                SynthCallbackLink* callback = runtime->voices[slot].callbackLists[2];
                while (callback != 0) {
                    voiceKillSound(callback->callbackId);
                    callback = callback->next;
                }
            }
            ResetNotes(voice);
            break;
        case SYNTH_VOICE_STATE_ALLOCATED:
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
        voice->state = SYNTH_VOICE_STATE_FREE;
        if (seqFreeRoot != 0) {
            seqFreeRoot->prev = voice;
        }
        voice->next = seqFreeRoot;
        voice->prev = 0;
        seqFreeRoot = voice;
    } else {
        if ((voice = &runtime->voices[slot & 0x7fffffffu], runtime->voices[slot & 0x7fffffffu].state) !=
            SYNTH_VOICE_STATE_FREE) {
            voice->syncSeqIdPtr = 0;
        }
    }
}

void seqSpeed(u32 seqId, u16 speed) {
    u32 slot;
    SynthVoiceRuntime* runtime;

    runtime = SYNTH_VOICE_RUNTIME();
    slot = seqGetPrivateIdInline(seqId);

    if ((slot & 0x80000000) == 0) {
        u32 section;
        for (section = 0; section < SYNTH_VOICE_NOTE_COUNT; section++) {
            runtime->voices[slot].section[section].speed = speed;
        }
    } else {
        u32 idx = slot & 0x7fffffffu;
        runtime->voices[idx].syncCrossInfo.flags |= SND_CROSSFADE_SPEED;
        runtime->voices[idx].syncCrossInfo.speed2 = speed;
    }
}

void seqContinue(u32 seqId) {
    u32 slot;
    SynthVoice* voice;

    slot = seqGetPrivateIdInline(seqId);

    if ((slot & 0x80000000) == 0) {
        voice = &seqInstance[slot];
        if (voice->state != SYNTH_VOICE_STATE_ALLOCATED) {
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
        voice->state = SYNTH_VOICE_STATE_QUEUED;
    } else {
        seqInstance[slot & 0x7fffffffu].syncCrossInfo.flags &= ~8;
    }
}

u16 seqMIDIPriority[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];
SynthVoice seqInstance[SYNTH_MAX_VOICES];
