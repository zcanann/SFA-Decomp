#include "src/main/audio/synth_internal.h"

void synthSetHandleMixData(u32 handle, u32 mixValue0, u32 mixValue1)
{
    SynthVoiceRuntime* runtime;
    SynthVoice* walker;
    u32 slot;
    u32 resolvedHandle;

    runtime = SYNTH_VOICE_RUNTIME();
    resolvedHandle = handle & SYNTH_HANDLE_ID_MASK;
    for (walker = gSynthQueuedVoices; walker != 0; walker = walker->next)
    {
        if (walker->handle == resolvedHandle)
        {
            slot = walker->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
            goto resolved;
        }
    }

    for (walker = gSynthAllocatedVoices; walker != 0; walker = walker->next)
    {
        if (walker->handle == resolvedHandle)
        {
            slot = walker->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
            goto resolved;
        }
    }

    slot = SYNTH_HANDLE_INVALID;

resolved:
    if (slot == SYNTH_HANDLE_INVALID)
    {
        return;
    }

    if ((slot & SYNTH_HANDLE_QUEUED_FLAG) == 0)
    {
        runtime->voices[slot].immediateMixValue0 = mixValue0;
        runtime->voices[slot].immediateMixValue1 = mixValue1;
    }
    else
    {
        runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.flags |= SYNTH_PENDING_FLAG_MIX_DATA;
        runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue0 = mixValue0;
        runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue1 = mixValue1;
    }
}
