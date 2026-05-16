#include "src/main/audio/synth_internal.h"

#define SYNTH_VOICE_STUDIO_MAP_OFFSET ((u32)&(((SynthVoice*)0)->studioMap))

extern void synthVolume(u32 value0, u32 value1, u8 studio, u32 mode, u32 handle);
extern void sndSeqVolume(u32 value0, u16 value1, u32 handle, u32 mode);
extern void sndSeqMute(u32 handle, u32 value0, u32 value1);
extern void sndSeqContinue(u32 handle);
extern void sndSeqSpeed(u32 handle, u16 speed);
extern u32 synthResolveHandle(u32 handle);
extern u32 fn_8027B89C(u16 groupId, u16 sampleId, u32 seqId, void* params, u8 noLock, u8 studio);
extern u32 fn_8027B9DC(u16 groupId, u16 sampleId, u32 seqId, void* params, u8 studio);

#define SYNTH_START_FLAG_VOLUME_MODE2 0x01
#define SYNTH_START_FLAG_REUSE_HANDLE 0x02
#define SYNTH_START_FLAG_PENDING_START 0x04
#define SYNTH_START_FLAG_PARAM_14 0x08
#define SYNTH_START_FLAG_MUTE 0x10
#define SYNTH_START_FLAG_SPEED 0x20
#define SYNTH_START_FLAG_VOLUME_MODE3 0x40
#define SYNTH_START_FLAG_CLEAR_MUTE 0x80

typedef struct SynthStartParams {
    u32 flags;
    u32 muteValue;
    u32 muteTime;
    u16 speed;
    u16 volumeTime;
    u8 volume;
    u8 pad11[7];
    u8 active;
} SynthStartParams;

/*
 * sndSeqVolume backend. Resolves a sequence handle across queued and active
 * voices; active voices update immediately, queued voices cache a pending
 * studio-volume change until they are started.
 *
 * EN v1.0 Address: 0x8026D6E4, size 0x19C
 */
void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode) {
    SynthVoice* voice;
    SynthVoiceRuntime* runtime;
    u8* voiceBytes;
    u8* voiceCursor;
    u32 voiceIndex;
    u32 studioIndex;

    runtime = SYNTH_VOICE_RUNTIME();
    for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            studioIndex = (handle & 0x80000000) | voice->slotIndex;
            goto resolved;
        }
    }

    for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            studioIndex = (handle & 0x80000000) | voice->slotIndex;
            goto resolved;
        }
    }

    studioIndex = 0xFFFFFFFF;

resolved:
    if (studioIndex != 0xFFFFFFFF) {
        if ((studioIndex & 0x80000000) == 0) {
            synthVolume(value0, value1, runtime->voices[studioIndex].currentStudio, mode, handle);
            voice = &runtime->voices[studioIndex];
            voiceBytes = (u8*)voice;
            voiceCursor = (u8*)voice;
            voiceIndex = 0;
            do {
                if (voiceBytes[SYNTH_VOICE_STUDIO_MAP_OFFSET] != runtime->voices[studioIndex].currentStudio) {
                    synthVolume(value0, value1, voiceCursor[SYNTH_VOICE_STUDIO_MAP_OFFSET], 0, 0xFFFFFFFF);
                }
                voiceBytes++;
                voiceCursor++;
                voiceIndex++;
            } while (voiceIndex < SYNTH_SEQUENCE_TRACK_COUNT);
        } else {
            mode &= 0xF;
            voiceIndex = studioIndex & 0x7FFFFFFF;
            switch (mode) {
            case 0:
                runtime->voices[voiceIndex].pendingUpdate.studio = (u8)value0;
                break;
            case 1:
                runtime->voices[voiceIndex].pendingUpdate.output = 0;
                break;
            case 2:
                runtime->voices[voiceIndex].pendingUpdate.flags |= 8;
                runtime->voices[voiceIndex].pendingUpdate.studio = (u8)value0;
                break;
            case 3:
                runtime->voices[voiceIndex].pendingUpdate.flags |= 0x80;
                runtime->voices[voiceIndex].pendingUpdate.studio = (u8)value0;
                break;
            }
        }
    }
}

/*
 * Start or resume a sequence handle from a compact request packet. This is the
 * no-lock backend used by the sequence event runner when it needs to defer a
 * start until the current voice reaches the queued-start marker.
 */
void fn_8026D880(SynthStartRequest* request, u32* outHandle, u8 noLock) {
    SynthVoiceRuntime* runtime;
    SynthVoice* voice;
    SynthStartParams params;
    u32 handle;
    u32 slot;
    u32 resolvedHandle;
    u32 newHandle;
    u32 mixValue0;
    u32 mixValue1;
    u16 speed;
    u16 fadeTime;
    u8 flags;
    SynthVoice* pendingVoice;
    SynthStartRequest* pendingRequest;

    handle = request->handle;
    runtime = SYNTH_VOICE_RUNTIME();

    resolvedHandle = handle & 0x7FFFFFFF;
    for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == resolvedHandle) {
            slot = voice->slotIndex | (handle & 0x80000000);
            goto resolved_initial;
        }
    }

    for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == resolvedHandle) {
            slot = voice->slotIndex | (handle & 0x80000000);
            goto resolved_initial;
        }
    }

    slot = 0xFFFFFFFF;

resolved_initial:
    flags = request->flags;
    if ((flags & SYNTH_START_FLAG_PENDING_START) != 0) {
        pendingVoice = &runtime->voices[slot];
        pendingRequest = SYNTH_VOICE_PENDING_START_REQUEST(pendingVoice);
        pendingRequest->handle = request->handle;
        *(u32*)((u8*)pendingRequest + 0x04) = *(u32*)((u8*)request + 0x04);
        pendingRequest->reuseHandle = request->reuseHandle;
        *(u32*)((u8*)pendingRequest + 0x0C) = *(u32*)((u8*)request + 0x0C);
        pendingRequest->seqId = request->seqId;
        *(u32*)((u8*)pendingRequest + 0x14) = *(u32*)((u8*)request + 0x14);
        *(u32*)((u8*)pendingRequest + 0x18) = *(u32*)((u8*)request + 0x18);
        pendingRequest->mixValue0 = request->mixValue0;
        pendingRequest->mixValue1 = request->mixValue1;
        *(u32*)((u8*)pendingRequest + 0x24) = *(u32*)((u8*)request + 0x24);
        SYNTH_VOICE_PENDING_START_ACTIVE(pendingVoice) = 1;
        SYNTH_VOICE_PENDING_START_OUT_HANDLE(pendingVoice) = outHandle;
        pendingRequest->flags &= (u8)~SYNTH_START_FLAG_PENDING_START;
        *outHandle = request->handle | 0x80000000;
        return;
    }

    if (noLock != 0) {
        fadeTime = request->fadeTime;
        if (fadeTime < 5) {
            fadeTime = 5;
        }
        if ((flags & SYNTH_START_FLAG_VOLUME_MODE2) != 0) {
            synthUpdateHandle(0, fadeTime, handle, 2);
        } else if ((flags & SYNTH_START_FLAG_VOLUME_MODE3) != 0) {
            synthUpdateHandle(0, fadeTime, handle, 3);
        } else {
            synthUpdateHandle(0, fadeTime, handle, 1);
        }
    } else {
        if ((flags & SYNTH_START_FLAG_VOLUME_MODE2) != 0) {
            sndSeqVolume(0, request->fadeTime, handle, 2);
        } else if ((flags & SYNTH_START_FLAG_VOLUME_MODE3) != 0) {
            sndSeqVolume(0, request->fadeTime, handle, 3);
        } else {
            sndSeqVolume(0, request->fadeTime, handle, 1);
        }
    }

    if (outHandle == 0) {
        return;
    }

    if ((request->flags & SYNTH_START_FLAG_REUSE_HANDLE) != 0) {
        handle = request->reuseHandle;
        resolvedHandle = handle & 0x7FFFFFFF;
        for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next) {
            if (voice->handle == resolvedHandle) {
                slot = voice->slotIndex | (handle & 0x80000000);
                goto resolved_reuse;
            }
        }

        for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next) {
            if (voice->handle == resolvedHandle) {
                slot = voice->slotIndex | (handle & 0x80000000);
                goto resolved_reuse;
            }
        }

        slot = 0xFFFFFFFF;

resolved_reuse:
        if (slot == 0xFFFFFFFF) {
            *outHandle = 0xFFFFFFFF;
            return;
        }

        if (noLock != 0) {
            synthRestoreQueuedHandle(request->reuseHandle);
            synthUpdateHandle(request->volume, request->volumeTime, request->reuseHandle, 0);
            if ((request->flags & SYNTH_START_FLAG_MUTE) != 0) {
                mixValue1 = request->mixValue1;
                mixValue0 = request->mixValue0;
                newHandle = synthResolveHandle(request->reuseHandle);
                if (newHandle != 0xFFFFFFFF) {
                    if ((newHandle & 0x80000000) == 0) {
                        runtime->voices[newHandle].immediateMixValue0 = mixValue0;
                        runtime->voices[newHandle].immediateMixValue1 = mixValue1;
                    } else {
                        runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.flags |= 0x10;
                        runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.mixValue0 = mixValue0;
                        runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.mixValue1 = mixValue1;
                    }
                }
            }
            if ((request->flags & SYNTH_START_FLAG_SPEED) != 0) {
                speed = request->value16;
                newHandle = synthResolveHandle(request->reuseHandle);
                if ((newHandle & 0x80000000) == 0) {
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 0) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 1) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 2) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 3) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 4) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 5) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 6) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 7) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 8) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 9) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 10) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 11) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 12) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 13) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 14) = speed;
                    SYNTH_RUNTIME_CHANNEL_SPEED_VALUE(runtime, newHandle, 15) = speed;
                } else {
                    runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.flags |= 0x20;
                    runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.value16 = speed;
                }
            }
        } else {
            sndSeqContinue(request->reuseHandle);
            sndSeqVolume(request->volume, request->volumeTime, request->reuseHandle, 0);
            if ((request->flags & SYNTH_START_FLAG_MUTE) != 0) {
                sndSeqMute(request->reuseHandle, request->mixValue0, request->mixValue1);
            }
            if ((request->flags & SYNTH_START_FLAG_SPEED) != 0) {
                sndSeqSpeed(request->reuseHandle, request->value16);
            }
        }
        *outHandle = request->reuseHandle;
        return;
    }

    params.flags = 4;
    if ((request->flags & SYNTH_START_FLAG_PARAM_14) != 0) {
        params.flags = 0x14;
    }
    if ((request->flags & SYNTH_START_FLAG_SPEED) != 0) {
        params.flags |= 2;
        params.speed = request->value16;
    }
    if ((request->flags & SYNTH_START_FLAG_MUTE) != 0) {
        params.flags |= 1;
        params.muteValue = request->mixValue0;
        params.muteTime = request->mixValue1;
    }
    params.volumeTime = request->volumeTime;
    params.volume = request->volume;
    params.active = 0;

    if (noLock != 0) {
        newHandle = fn_8027B89C(request->groupId, request->sampleId, request->seqId, &params, 1, request->startStudio);
        *outHandle = newHandle;
        if ((newHandle != 0xFFFFFFFF) && ((request->flags & SYNTH_START_FLAG_CLEAR_MUTE) != 0)) {
            newHandle = synthResolveHandle(*outHandle);
            if (newHandle != 0xFFFFFFFF) {
                if ((newHandle & 0x80000000) == 0) {
                    runtime->voices[newHandle].immediateMixValue0 = 0;
                    runtime->voices[newHandle].immediateMixValue1 = 0;
                } else {
                    runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.flags |= 0x10;
                    runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.mixValue0 = 0;
                    runtime->voices[newHandle & 0x7FFFFFFF].pendingUpdate.mixValue1 = 0;
                }
            }
        }
    } else {
        newHandle = fn_8027B9DC(request->groupId, request->sampleId, request->seqId, &params, request->startStudio);
        *outHandle = newHandle;
        if ((newHandle != 0xFFFFFFFF) && ((request->flags & SYNTH_START_FLAG_CLEAR_MUTE) != 0)) {
            sndSeqMute(*outHandle, 0, 0);
        }
    }
}

/*
 * fn_8026DDB4: parse a 1-or-2-byte unsigned event tag (out into u16* at r4)
 * followed by a 1-or-2-byte signed value (sign-extended low 7 / 14 bits, out
 * into s16* at r5). Returns the advanced read pointer, or NULL when the tag
 * is the sentinel 0x80 0x00.
 */
u8* fn_8026DDB4(u8* p, u16* tagOut, s16* valueOut) {
    u8 b1;
    u8 b2;

    b1 = p[0];
    b2 = p[1];
    if (b1 == 0x80 && b2 == 0) {
        return 0;
    }

    if (b1 & 0x80) {
        *tagOut = (u16)(((b1 & 0x7F) << 8) | b2);
        p += 2;
    } else {
        *tagOut = (u16)b1;
        p += 1;
    }

    {
        u8 b3 = p[0];
        u8 b4 = p[1];
        int shift;
        s16 v;

        if (b3 & 0x80) {
            v = (s16)(u16)(((b3 & 0x7F) << 8) | b4);
            shift = 1;
            v = (s16)((s16)((s16)v << shift) >> shift);
            *valueOut = v;
            p += 2;
            return p;
        }

        v = (s16)(u16)b3;
        shift = 9;
        v = (s16)((s16)((s16)v << shift) >> shift);
        *valueOut = v;
        p += 1;
        return p;
    }
}
