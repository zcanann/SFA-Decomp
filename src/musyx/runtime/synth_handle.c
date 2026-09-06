#include "src/musyx/runtime/synth_internal.h"
#include "musyx/snd_synth_api.h"
#include "musyx/synth_callback.h"
#include "musyx/synth_control.h"
#include "musyx/synth_handle.h"
#include "musyx/snd_groups.h"
#include "musyx/synth_volume.h"

#define SYNTH_VOICE_TRACK_VOLUME_GROUP_OFFSET ((u32) & (((SynthVoice*)0)->trackVolumeGroup))
#define SYNTH_RUNTIME_VOICES_OFFSET           ((u32) & (((SynthVoiceRuntime*)0)->voices))

void seqVolume(u8 volume, u16 time, u32 seqId, u8 mode) {
    SynthVoiceRuntime* runtime;
    u8* voiceBase;
    u8* voiceBytes;
    u8* voiceCursor;
    SynthVoice* voice;
    u32 voiceIndex;
    u32 studioIndex;
    u32 pub_id;

    runtime = SYNTH_VOICE_RUNTIME();
    pub_id = seqId;
    studioIndex = seqGetPrivateIdInline(seqId);

    if (studioIndex != SYNTH_HANDLE_INVALID) {
        if ((studioIndex & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
            voiceBase = (u8*)runtime + studioIndex * sizeof(SynthVoice);
            synthVolume(volume, time, ((SynthVoice*)(voiceBase + SYNTH_RUNTIME_VOICES_OFFSET))->defaultVolumeGroup,
                        mode, pub_id);
            voice = (SynthVoice*)(voiceBase + SYNTH_RUNTIME_VOICES_OFFSET);
            voiceBytes = (u8*)voice;
            voiceCursor = (u8*)voice;
            voiceIndex = 0;
            do {
                if (voiceBytes[SYNTH_VOICE_TRACK_VOLUME_GROUP_OFFSET] != voice->defaultVolumeGroup) {
                    synthVolume(volume, time, voiceCursor[SYNTH_VOICE_TRACK_VOLUME_GROUP_OFFSET], 0,
                                SYNTH_HANDLE_INVALID);
                }
                voiceBytes++;
                voiceCursor++;
                voiceIndex++;
            } while (voiceIndex < SYNTH_SEQUENCE_TRACK_COUNT);
        } else {
            seqId = studioIndex & SYNTH_HANDLE_ID_MASK;
            switch (mode & 0xF) {
            case 0:
                runtime->voices[seqId].syncCrossInfo.vol2 = volume;
                break;
            case 1:
                runtime->voices[seqId].syncSeqIdPtr = 0;
                break;
            case 2:
                runtime->voices[seqId].syncCrossInfo.flags |= SND_CROSSFADE_PAUSENEW;
                runtime->voices[seqId].syncCrossInfo.vol2 = volume;
                break;
            case 3:
                runtime->voices[seqId].syncCrossInfo.flags |= SND_CROSSFADE_MUTENEW;
                runtime->voices[seqId].syncCrossInfo.vol2 = volume;
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
    SynthVoiceRuntime* runtime;
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

    runtime = SYNTH_VOICE_RUNTIME();

    slot = resolveHandle(ci->seqId1);
    flags = ci->flags;
    if ((flags & SND_CROSSFADE_SYNC) != 0) {
        pendingVoice = (SynthVoice*)((u8*)runtime + slot * sizeof(SynthVoice));
        pendingRequest = (SynthStartRequest*)((u8*)pendingVoice + 0x22B4);
        *pendingRequest = *ci;
        *(u8*)((u8*)pendingVoice + 0x22E0) = 1;
        *(u32**)((u8*)pendingVoice + 0x22DC) = new_seqId;
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
                            runtime->voices[newHandle].trackMute[0] = mixValue0;
                            runtime->voices[newHandle].trackMute[1] = mixValue1;
                        } else {
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |=
                                SND_CROSSFADE_TRACKMUTE;
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[0] = mixValue0;
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[1] = mixValue1;
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
                            runtime->voices[newHandle].section[section].speed = speed;
                        }
                    } else {
                        runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |= SND_CROSSFADE_SPEED;
                        runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.speed2 = speed;
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
                    runtime->voices[newHandle].trackMute[0] = 0;
                    runtime->voices[newHandle].trackMute[1] = 0;
                } else {
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.flags |= SND_CROSSFADE_TRACKMUTE;
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[0] = 0;
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].syncCrossInfo.trackMute2[1] = 0;
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
