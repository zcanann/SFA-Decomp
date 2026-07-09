#include "src/main/audio/synth_internal.h"
#pragma exceptions on

typedef struct SynthStartParams
{
    u32 flags;
    u32 muteValue;
    u32 muteTime;
    u16 speed;
    u16 volumeTime;
    u8 volume;
    u8 pad11[7];
    u8 active;
    u8 pad25[3];
} SynthStartParams;

#undef SYNTH_VOICE_RUNTIME
#define SYNTH_VOICE_RUNTIME() (&lbl_803AF550)

#define SYNTH_VOICE_STUDIO_MAP_OFFSET ((u32) & (((SynthVoice*)0)->studioMap))
#define SYNTH_RUNTIME_VOICES_OFFSET   ((u32) & (((SynthVoiceRuntime*)0)->voices))

#define SYNTH_START_FLAG_VOLUME_MODE2  0x01
#define SYNTH_START_FLAG_REUSE_HANDLE  0x02
#define SYNTH_START_FLAG_PENDING_START 0x04
#define SYNTH_START_FLAG_PARAM_14      0x08
#define SYNTH_START_FLAG_MUTE          0x10
#define SYNTH_START_FLAG_SPEED         0x20
#define SYNTH_START_FLAG_VOLUME_MODE3  0x40
#define SYNTH_START_FLAG_CLEAR_MUTE    0x80

extern SynthVoiceRuntime lbl_803AF550;
extern void synthVolume(u32 value0, u32 value1, u8 studio, u32 mode, u32 handle);
extern void sndSeqVolume(u32 value0, u16 value1, u32 handle, u32 mode);
extern void sndSeqMute(u32 handle, u32 value0, u32 value1);
extern void sndSeqContinue(u32 handle);
extern void sndSeqSpeed(u32 handle, u16 speed);
extern u32 synthResolveHandle(u32 handle);
extern u32 seqPlaySong(u16 groupId, u16 sampleId, u32 seqId, void* params, u8 noLock, u8 studio);
extern u32 sndSeqPlayEx(u16 groupId, u16 sampleId, u32 seqId, void* params, u8 studio);

/*
 * sndSeqVolume backend. Resolves a sequence handle across queued and active
 * voices; active voices update immediately, queued voices cache a pending
 * studio-volume change until they are started.
 */
void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode)
{
    SynthVoiceRuntime* runtime;
    u8* voiceBase;
    u8* voiceBytes;
    u8* voiceCursor;
    SynthVoice* voice;
    SynthVoice* walker;
    u32 voiceIndex;
    u32 studioIndex;
    u32 pubHandle;

    runtime = SYNTH_VOICE_RUNTIME();
    pubHandle = handle;
    for (walker = gSynthQueuedVoices; walker != 0; walker = walker->next)
    {
        if (walker->handle == (handle & SYNTH_HANDLE_ID_MASK))
        {
            studioIndex = (handle & SYNTH_HANDLE_QUEUED_FLAG) | walker->slotIndex;
            goto resolved;
        }
    }

    for (walker = gSynthAllocatedVoices; walker != 0; walker = walker->next)
    {
        if (walker->handle == (handle & SYNTH_HANDLE_ID_MASK))
        {
            studioIndex = (handle & SYNTH_HANDLE_QUEUED_FLAG) | walker->slotIndex;
            goto resolved;
        }
    }

    studioIndex = SYNTH_HANDLE_INVALID;

resolved:
    if (studioIndex != SYNTH_HANDLE_INVALID)
    {
        if ((studioIndex & SYNTH_HANDLE_QUEUED_FLAG) == 0)
        {
            voiceBase = (u8*)runtime + studioIndex * sizeof(SynthVoice);
            synthVolume(value0, value1, ((SynthVoice*)(voiceBase + SYNTH_RUNTIME_VOICES_OFFSET))->currentStudio, mode,
                        pubHandle);
            voice = (SynthVoice*)(voiceBase + SYNTH_RUNTIME_VOICES_OFFSET);
            voiceBytes = (u8*)voice;
            voiceCursor = (u8*)voice;
            voiceIndex = 0;
            do
            {
                if (voiceBytes[SYNTH_VOICE_STUDIO_MAP_OFFSET] != voice->currentStudio)
                {
                    synthVolume(value0, value1, voiceCursor[SYNTH_VOICE_STUDIO_MAP_OFFSET], 0, SYNTH_HANDLE_INVALID);
                }
                voiceBytes++;
                voiceCursor++;
                voiceIndex++;
            } while (voiceIndex < SYNTH_SEQUENCE_TRACK_COUNT);
        }
        else
        {
            handle = studioIndex & SYNTH_HANDLE_ID_MASK;
            switch (mode & 0xF)
            {
            case 0:
                runtime->voices[handle].pendingUpdate.studio = value0;
                break;
            case 1:
                runtime->voices[handle].pendingUpdate.output = 0;
                break;
            case 2:
                runtime->voices[handle].pendingUpdate.flags |= SYNTH_PENDING_FLAG_STUDIO_MODE2;
                runtime->voices[handle].pendingUpdate.studio = value0;
                break;
            case 3:
                runtime->voices[handle].pendingUpdate.flags |= SYNTH_PENDING_FLAG_STUDIO_MODE3;
                runtime->voices[handle].pendingUpdate.studio = value0;
                break;
            }
        }
    }
}

static inline u32 resolveHandle(u32 handle)
{
    SynthVoice* voice;

    for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next)
    {
        if (voice->handle == (handle & SYNTH_HANDLE_ID_MASK))
        {
            return voice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next)
    {
        if (voice->handle == (handle & SYNTH_HANDLE_ID_MASK))
        {
            return voice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    return SYNTH_HANDLE_INVALID;
}

/*
 * Start or resume a sequence handle from a compact request packet. This is the
 * no-lock backend used by the sequence event runner when it needs to defer a
 * start until the current voice reaches the queued-start marker.
 */
void synthStartHandleFromRequest(SynthStartRequest* request, u32* outHandle, u8 noLock)
{
    SynthVoiceRuntime* runtime;
    SynthStartParams params;
    u32 deadSlot0;
    u32 deadSlot1;
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

    slot = resolveHandle(request->handle);
    flags = request->flags;
    if ((flags & SYNTH_START_FLAG_PENDING_START) != 0)
    {
        pendingVoice = (SynthVoice*)((u8*)runtime + slot * sizeof(SynthVoice));
        pendingRequest = (SynthStartRequest*)((u8*)pendingVoice + 0x22B4);
        *pendingRequest = *request;
        *(u8*)((u8*)pendingVoice + 0x22E0) = 1;
        *(u32**)((u8*)pendingVoice + 0x22DC) = outHandle;
        pendingRequest->flags &= ~SYNTH_START_FLAG_PENDING_START;
        *outHandle = request->handle | SYNTH_HANDLE_QUEUED_FLAG;
        return;
    }

    if (noLock != 0)
    {
        fadeTime = request->fadeTime < 5 ? 5 : request->fadeTime;
        if ((flags & SYNTH_START_FLAG_VOLUME_MODE2) != 0)
        {
            synthUpdateHandle(0, fadeTime, request->handle, 2);
        }
        else if ((flags & SYNTH_START_FLAG_VOLUME_MODE3) != 0)
        {
            synthUpdateHandle(0, fadeTime, request->handle, 3);
        }
        else
        {
            synthUpdateHandle(0, fadeTime, request->handle, 1);
        }
    }
    else
    {
        if ((flags & SYNTH_START_FLAG_VOLUME_MODE2) != 0)
        {
            sndSeqVolume(0, request->fadeTime, request->handle, 2);
        }
        else if ((flags & SYNTH_START_FLAG_VOLUME_MODE3) != 0)
        {
            sndSeqVolume(0, request->fadeTime, request->handle, 3);
        }
        else
        {
            sndSeqVolume(0, request->fadeTime, request->handle, 1);
        }
    }

    if (outHandle == 0)
    {
        return;
    }

    if ((request->flags & SYNTH_START_FLAG_REUSE_HANDLE) != 0)
    {
        if ((slot = resolveHandle(request->reuseHandle)) != SYNTH_HANDLE_INVALID)
        {
            if (noLock != 0)
            {
                synthRestoreQueuedHandle(request->reuseHandle);
                synthUpdateHandle(request->volume, request->volumeTime, request->reuseHandle, 0);
                if ((request->flags & SYNTH_START_FLAG_MUTE) != 0)
                {
                    newHandle = request->reuseHandle;
                    mixValue1 = request->mixValue1;
                    mixValue0 = request->mixValue0;
                    newHandle = synthResolveHandle(newHandle);
                    if (newHandle != SYNTH_HANDLE_INVALID)
                    {
                        if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0)
                        {
                            runtime->voices[newHandle].immediateMixValue0 = mixValue0;
                            runtime->voices[newHandle].immediateMixValue1 = mixValue1;
                        }
                        else
                        {
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.flags |=
                                SYNTH_PENDING_FLAG_MIX_DATA;
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue0 = mixValue0;
                            runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue1 = mixValue1;
                        }
                    }
                }
                if ((request->flags & SYNTH_START_FLAG_SPEED) != 0)
                {
                    newHandle = request->reuseHandle;
                    speed = request->value16;
                    newHandle = synthResolveHandle(newHandle);
                    if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0)
                    {
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
                    }
                    else
                    {
                        runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.flags |=
                            SYNTH_PENDING_FLAG_SPEED;
                        runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.value16 = speed;
                    }
                }
            }
            else
            {
                sndSeqContinue(request->reuseHandle);
                sndSeqVolume(request->volume, request->volumeTime, request->reuseHandle, 0);
                if ((request->flags & SYNTH_START_FLAG_MUTE) != 0)
                {
                    sndSeqMute(request->reuseHandle, request->mixValue0, request->mixValue1);
                }
                if ((request->flags & SYNTH_START_FLAG_SPEED) != 0)
                {
                    sndSeqSpeed(request->reuseHandle, request->value16);
                }
            }
            *outHandle = request->reuseHandle;
            return;
        }
        *outHandle = SYNTH_HANDLE_INVALID;
        return;
    }

    params.flags = 4;
    if ((request->flags & SYNTH_START_FLAG_PARAM_14) != 0)
    {
        params.flags |= 0x10;
    }
    if ((request->flags & SYNTH_START_FLAG_SPEED) != 0)
    {
        params.flags |= 2;
        params.speed = request->value16;
    }
    if ((request->flags & SYNTH_START_FLAG_MUTE) != 0)
    {
        params.flags |= 1;
        params.muteValue = request->mixValue0;
        params.muteTime = request->mixValue1;
    }
    params.volumeTime = request->volumeTime;
    params.volume = request->volume;
    params.active = 0;

    if (noLock != 0)
    {
        newHandle = seqPlaySong(request->groupId, request->sampleId, request->seqId, &params, 1, request->startStudio);
        *outHandle = newHandle;
        if ((newHandle != SYNTH_HANDLE_INVALID) && ((request->flags & SYNTH_START_FLAG_CLEAR_MUTE) != 0))
        {
            newHandle = synthResolveHandle(*outHandle);
            if (newHandle != SYNTH_HANDLE_INVALID)
            {
                if ((newHandle & SYNTH_HANDLE_QUEUED_FLAG) == 0)
                {
                    runtime->voices[newHandle].immediateMixValue0 = 0;
                    runtime->voices[newHandle].immediateMixValue1 = 0;
                }
                else
                {
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.flags |=
                        SYNTH_PENDING_FLAG_MIX_DATA;
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue0 = 0;
                    runtime->voices[newHandle & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue1 = 0;
                }
            }
        }
    }
    else
    {
        newHandle = sndSeqPlayEx(request->groupId, request->sampleId, request->seqId, &params, request->startStudio);
        *outHandle = newHandle;
        if ((newHandle != SYNTH_HANDLE_INVALID) && ((request->flags & SYNTH_START_FLAG_CLEAR_MUTE) != 0))
        {
            sndSeqMute(*outHandle, 0, 0);
        }
    }
}

/*
 * Parse a 1-or-2-byte unsigned event tag followed by a 1-or-2-byte signed
 * value. Returns the advanced read pointer, or NULL when the tag is the
 * sentinel 0x80 0x00.
 */
u8* synthReadVariablePair(u8* p, u16* tagOut, s16* valueOut)
{
    s16 combined;
    s32 shift;
    u32 combinedValue;
    u8 high;
    u8 low;

    high = p[0];
    low = p[1];
    if (high == SYNTH_VARIABLE_PAIR_EXTENDED_FLAG && low == SYNTH_VARIABLE_PAIR_END_LOW)
    {
        return 0;
    }

    if ((high & SYNTH_VARIABLE_PAIR_EXTENDED_FLAG) != 0)
    {
        combinedValue = (u32)((high & SYNTH_VARIABLE_PAIR_VALUE_MASK) << 8);
        combinedValue = combinedValue | low;
        *tagOut = combinedValue;
        p += 2;
    }
    else
    {
        *tagOut = high;
        p += 1;
    }

    high = p[0];
    low = p[1];
    if ((high & SYNTH_VARIABLE_PAIR_EXTENDED_FLAG) != 0)
    {
        combinedValue = (u32)((high & SYNTH_VARIABLE_PAIR_VALUE_MASK) << 8);
        combinedValue = combinedValue | low;
        combined = combinedValue;
        shift = 1;
        combined <<= shift;
        combined >>= shift;
        *valueOut = combined;
        p += 2;
    }
    else
    {
        combined = high;
        shift = 9;
        combined <<= shift;
        combined >>= shift;
        *valueOut = combined;
        p += 1;
    }

    return p;
}
