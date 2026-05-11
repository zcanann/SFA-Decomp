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
 * fn_8026D278 - voice search and modify (~464 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D278(int handle, int args)
{
    (void)handle; (void)args;
}
#pragma dont_inline reset

/*
 * fn_8026D448 - voice flag setter (~220 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026D448(int handle, int args)
{
    (void)handle; (void)args;
}
#pragma dont_inline reset

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
