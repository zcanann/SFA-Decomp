#include "src/main/audio/synth_internal.h"

#define SYNTH_HANDLE_SLOT_INVALID 0xFFFFFFFF
#define SYNTH_PENDING_FLAG_MIX_DATA 0x10

void fn_8026D630(u32 handle, u32 mixValue0, u32 mixValue1)
{
  SynthVoiceRuntime *runtime;
  SynthVoice *queuedVoice;
  SynthVoice *allocatedVoice;
  u32 slot;
  u32 resolvedHandle;

  runtime = SYNTH_VOICE_RUNTIME();
  resolvedHandle = handle & 0x7FFFFFFF;
  for (queuedVoice = gSynthQueuedVoices; queuedVoice != 0; queuedVoice = queuedVoice->next) {
    if (queuedVoice->handle == resolvedHandle) {
      slot = queuedVoice->slotIndex | (handle & 0x80000000);
      goto found;
    }
  }

  for (allocatedVoice = gSynthAllocatedVoices; allocatedVoice != 0; allocatedVoice = allocatedVoice->next) {
    if (allocatedVoice->handle == resolvedHandle) {
      slot = allocatedVoice->slotIndex | (handle & 0x80000000);
      goto found;
    }
  }

  slot = SYNTH_HANDLE_SLOT_INVALID;

found:
  if (slot == SYNTH_HANDLE_SLOT_INVALID) {
    return;
  }

  if ((slot & 0x80000000) == 0) {
    runtime->voices[slot].immediateMixValue0 = mixValue0;
    runtime->voices[slot].immediateMixValue1 = mixValue1;
  } else {
    runtime->voices[slot & 0x7FFFFFFF].pendingUpdate.flags |= SYNTH_PENDING_FLAG_MIX_DATA;
    runtime->voices[slot & 0x7FFFFFFF].pendingUpdate.mixValue0 = mixValue0;
    runtime->voices[slot & 0x7FFFFFFF].pendingUpdate.mixValue1 = mixValue1;
  }
}
