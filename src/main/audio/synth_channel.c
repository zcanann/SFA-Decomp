#include "src/main/audio/synth_internal.h"

#define SYNTH_PENDING_FLAG_MIX_DATA 0x10

void synthSetHandleMixData(u32 handle, u32 mixValue0, u32 mixValue1)
{
  SynthVoiceRuntime *runtime;
  SynthVoice *queuedVoice;
  SynthVoice *allocatedVoice;
  u32 slot;
  u32 resolvedHandle;

  runtime = SYNTH_VOICE_RUNTIME();
  resolvedHandle = handle & SYNTH_HANDLE_ID_MASK;
  for (queuedVoice = gSynthQueuedVoices; queuedVoice != 0; queuedVoice = queuedVoice->next) {
    if (queuedVoice->handle == resolvedHandle) {
      slot = queuedVoice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
      goto found;
    }
  }

  for (allocatedVoice = gSynthAllocatedVoices; allocatedVoice != 0; allocatedVoice = allocatedVoice->next) {
    if (allocatedVoice->handle == resolvedHandle) {
      slot = allocatedVoice->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
      goto found;
    }
  }

  slot = SYNTH_HANDLE_INVALID;

found:
  if (slot == SYNTH_HANDLE_INVALID) {
    return;
  }

  if ((slot & SYNTH_HANDLE_QUEUED_FLAG) == 0) {
    runtime->voices[slot].immediateMixValue0 = mixValue0;
    runtime->voices[slot].immediateMixValue1 = mixValue1;
  } else {
    runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.flags |= SYNTH_PENDING_FLAG_MIX_DATA;
    runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue0 = mixValue0;
    runtime->voices[slot & SYNTH_HANDLE_ID_MASK].pendingUpdate.mixValue1 = mixValue1;
  }
}
