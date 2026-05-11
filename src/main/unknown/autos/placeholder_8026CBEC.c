#include "src/main/audio/synth_internal.h"

/*
 * fn_8026C488 - large voice scheduler (~2800 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8026C488(int a, int b)
{
    (void)a; (void)b;
    return 0;
}
#pragma dont_inline reset

/*
 * fn_8026CF78 - voice unlink helper (~232 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026CF78(u8 idx)
{
    (void)idx;
}
#pragma dont_inline reset

/*
 * Move a voice node from the queued list to the head of the allocated
 * list and mark it active.
 *
 * EN v1.0 Address: 0x8026D060, size 100b
 */
void fn_8026D060(SynthVoice* voice)
{
    if (voice->prev != 0) {
        voice->prev->next = voice->next;
    } else {
        gSynthQueuedVoices = voice->next;
    }
    if (voice->next != 0) {
        voice->next->prev = voice->prev;
    }
    if ((voice->next = gSynthAllocatedVoices) != 0) {
        gSynthAllocatedVoices->prev = voice;
    }
    voice->prev = 0;
    gSynthAllocatedVoices = voice;
    voice->state = 2;
}

extern void voiceKillById(int p);

/*
 * fn_8026D0C4 - voice handle lookup + cleanup with callbacks.
 *
 * EN v1.0 Address: 0x8026D0C4
 * EN v1.0 Size: 436b
 */
void fn_8026D0C4(u32 handle)
{
    u32 key;
    u32 found;
    u32 i;
    SynthVoice* voice;

    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if (found == 0xffffffff) return;

    if ((found & 0x80000000) == 0) {
        voice = &gSynthVoices[found];
        if (voice->state != 1) return;

        /* Unlink from queued list */
        if (voice->prev != 0) {
            voice->prev->next = voice->next;
        } else {
            gSynthQueuedVoices = voice->next;
        }
        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }

        /* Push to allocated list head */
        if ((voice->next = gSynthAllocatedVoices) != 0) {
            gSynthAllocatedVoices->prev = voice;
        }
        voice->prev = 0;
        gSynthAllocatedVoices = voice;
        voice->state = 2;

        /* Walk two callback lists */
        {
            SynthVoice* base = voice;
            for (i = 0; i < 2; i++) {
                SynthCallbackLink* cb = base->callbackLists[0];
                while (cb != 0) {
                    voiceKillById(cb->callbackId);
                    cb = cb->next;
                }
                base = (SynthVoice*)((u8*)base + 4);
            }
        }
        {
            SynthCallbackLink* cb2 = voice->callbackLists[2];
            while (cb2 != 0) {
                voiceKillById(cb2->callbackId);
                cb2 = cb2->next;
            }
        }
        synthRecycleVoiceCallbacks(voice);
    } else {
        u32 idx = found & 0x7fffffffu;
        voice = &gSynthVoices[idx];
        if (voice->state == 0) return;
        voice->pendingUpdate.flags |= 8;
    }
}

/*
 * Stop a sequence voice, clean up callbacks, and return the voice to the
 * free list. Deferred handles clear the pending output word instead.
 *
 * EN v1.0 Address: 0x8026D278
 * EN v1.0 Size: 464b
 */
void fn_8026D278(u32 handle)
{
    u32 key;
    u32 found;
    u32 i;
    SynthVoiceRuntime* runtime;
    SynthVoice* voice;

    runtime = SYNTH_VOICE_RUNTIME();
    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if (found == 0xffffffff) {
        return;
    }

    if ((found & 0x80000000) == 0) {
        voice = &runtime->voices[found];
        switch (voice->state) {
            case 1:
                if (voice->prev != 0) {
                    voice->prev->next = voice->next;
                } else {
                    gSynthQueuedVoices = voice->next;
                }

                {
                    SynthVoice* base = voice;
                    for (i = 0; i < 2; i++) {
                        SynthCallbackLink* cb = base->callbackLists[0];
                        while (cb != 0) {
                            voiceKillById(cb->callbackId);
                            cb = cb->next;
                        }
                        base = (SynthVoice*)((u8*)base + 4);
                    }
                }
                {
                    SynthCallbackLink* cb = voice->callbackLists[2];
                    while (cb != 0) {
                        voiceKillById(cb->callbackId);
                        cb = cb->next;
                    }
                }
                synthRecycleVoiceCallbacks(voice);
                break;
            case 2:
                if (voice->prev != 0) {
                    voice->prev->next = voice->next;
                } else {
                    gSynthAllocatedVoices = voice->next;
                }
                break;
        }

        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }
        voice->state = 0;
        if (gSynthFreeVoices != 0) {
            gSynthFreeVoices->prev = voice;
        }
        voice->next = gSynthFreeVoices;
        voice->prev = 0;
        gSynthFreeVoices = voice;
    } else {
        voice = &runtime->voices[found & 0x7fffffffu];
        if (voice->state != 0) {
            voice->pendingUpdate.output = 0;
        }
    }
}

/*
 * Update sequence playback speed immediately, or queue it for a deferred
 * handle update.
 *
 * EN v1.0 Address: 0x8026D448
 * EN v1.0 Size: 220b
 */
void fn_8026D448(u32 handle, u32 speed)
{
    u32 key;
    u32 found;
    SynthVoiceRuntime* runtime;
    SynthVoice* voice;

    runtime = SYNTH_VOICE_RUNTIME();
    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if ((found & 0x80000000) == 0) {
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
    } else {
        u32 idx = found & 0x7fffffffu;
        SYNTH_RUNTIME_PENDING_FLAGS(runtime, idx) |= 0x20;
        SYNTH_RUNTIME_PENDING_VALUE16(runtime, idx) = speed;
    }
}

/*
 * Continue a stopped sequence voice by moving it from the allocated list
 * back to the queued list, or clear the deferred continue flag.
 *
 * EN v1.0 Address: 0x8026D524
 * EN v1.0 Size: 268b
 */
void fn_8026D524(u32 handle)
{
    u32 key;
    u32 found;
    SynthVoice* voice;

    key = handle & 0x7fffffffu;

    voice = gSynthQueuedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }

    voice = gSynthAllocatedVoices;
    while (voice != 0) {
        if (voice->handle == key) {
            found = voice->slotIndex | (handle & 0x80000000);
            goto done;
        }
        voice = voice->next;
    }
    found = 0xffffffff;
done:

    if ((found & 0x80000000) == 0) {
        voice = &gSynthVoices[found];
        if (voice->state != 2) {
            return;
        }

        if (voice->prev != 0) {
            voice->prev->next = voice->next;
        } else {
            gSynthAllocatedVoices = voice->next;
        }
        if (voice->next != 0) {
            voice->next->prev = voice->prev;
        }

        if ((voice->next = gSynthQueuedVoices) != 0) {
            gSynthQueuedVoices->prev = voice;
        }
        voice->prev = 0;
        gSynthQueuedVoices = voice;
        voice->state = 1;
    } else {
        voice = &gSynthVoices[found & 0x7fffffffu];
        voice->pendingUpdate.flags &= ~8;
    }
}
