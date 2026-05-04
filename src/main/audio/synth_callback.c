#include "src/main/audio/synth_internal.h"
#include "src/main/audio/synth_voice_overlays.h"

#define SYNTH_CALLBACK_ACTIVE_LIST_COUNT 2
#define SYNTH_CALLBACK_COMPLETED_LIST_INDEX 2
#define SYNTH_CALLBACK_THRESHOLD(voice, index) \
    (*(s32*)&((voice)->unkEE0[0x62C + ((index) * 8)]))

void synthRecycleVoiceCallbacks(SynthVoice* voice) {
    SynthCallbackLink* callback;

    callback = voice->callbackLists[0];
    if (callback != 0) {
        while (callback->next != 0) {
            callback = callback->next;
        }

        if (gSynthFreeCallbacks != 0) {
            callback->next = gSynthFreeCallbacks;
            gSynthFreeCallbacks->prev = callback;
        }

        gSynthFreeCallbacks = voice->callbackLists[0];
        voice->callbackLists[0] = 0;
    }

    callback = voice->callbackLists[1];
    if (callback != 0) {
        while (callback->next != 0) {
            callback = callback->next;
        }

        if (gSynthFreeCallbacks != 0) {
            callback->next = gSynthFreeCallbacks;
            gSynthFreeCallbacks->prev = callback;
        }

        gSynthFreeCallbacks = voice->callbackLists[1];
        voice->callbackLists[1] = 0;
    }

    callback = voice->callbackLists[2];
    if (callback != 0) {
        while (callback->next != 0) {
            callback = callback->next;
        }

        if (gSynthFreeCallbacks != 0) {
            callback->next = gSynthFreeCallbacks;
            gSynthFreeCallbacks->prev = callback;
        }

        gSynthFreeCallbacks = voice->callbackLists[2];
        voice->callbackLists[2] = 0;
    }
}

SynthCallbackLink* synthAllocCallback(s32 triggerValue, u8 controllerIndex) {
    SynthCallbackLink* callback;
    SynthCallbackLink* current;
    SynthCallbackLink* prev;

    callback = gSynthFreeCallbacks;
    if (callback != 0) {
        gSynthFreeCallbacks = callback->next;
        if (gSynthFreeCallbacks != 0) {
            gSynthFreeCallbacks->prev = 0;
        }

        callback->triggerValue = triggerValue;
        callback->controllerIndex = controllerIndex;
        callback->listIndex =
            SYNTH_CALLBACK_CONTROLLER_STATE(gSynthCurrentVoice, controllerIndex)->listIndex;

        prev = 0;
        current = gSynthCurrentVoice->callbackLists[callback->listIndex];
        while (current != 0) {
            if (current->triggerValue > callback->triggerValue) {
                callback->next = current;
                callback->prev = prev;
                if (prev != 0) {
                    prev->next = callback;
                } else {
                    gSynthCurrentVoice->callbackLists[callback->listIndex] = callback;
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
            gSynthCurrentVoice->callbackLists[callback->listIndex] = callback;
        }
        callback->next = 0;
    }

    return callback;
}

s32 synthUpdateCallbacks(void) {
    s32 listIndex;
    SynthCallbackLink* callback;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++) {
        callback = gSynthCurrentVoice->callbackLists[listIndex];
        while (callback != 0) {
            if (callback->triggerValue > SYNTH_CALLBACK_THRESHOLD(gSynthCurrentVoice, listIndex)) {
                break;
            }

            synthTriggerCallback(callback->callbackId);
            gSynthCurrentVoice->callbackLists[listIndex] = callback->next;
            if (gSynthCurrentVoice->callbackLists[listIndex] != 0) {
                gSynthCurrentVoice->callbackLists[listIndex]->prev = 0;
            }

            callback->next = gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
            if (gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] != 0) {
                gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
            }
            gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
            callback = gSynthCurrentVoice->callbackLists[listIndex];
        }
    }

    return gSynthCurrentVoice->callbackLists[0] != 0 || gSynthCurrentVoice->callbackLists[1] != 0;
}

void synthFlushCallbacks(void) {
    s32 listIndex;
    SynthCallbackLink* callback;
    SynthCallbackLink* next;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++) {
        callback = gSynthCurrentVoice->callbackLists[listIndex];
        while (callback != 0) {
            next = callback->next;
            synthTriggerCallback(callback->callbackId);
            gSynthCurrentVoice->callbackLists[listIndex] = next;
            if (next != 0) {
                next->prev = 0;
            }

            callback->next = gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
            if (gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] != 0) {
                gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
            }
            gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
            callback = next;
        }
    }
}

void synthFreeCallback(SynthCallbackLink* callback) {
    SynthCallbackLink* freeCallback;

    if (callback->next != 0) {
        callback->next->prev = callback->prev;
    }

    if (callback->prev != 0) {
        callback->prev->next = callback->next;
    } else {
        gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback->next;
    }

    freeCallback = gSynthFreeCallbacks;
    callback->next = freeCallback;
    if (freeCallback != 0) {
        freeCallback->prev = callback;
    }

    callback->prev = 0;
    gSynthFreeCallbacks = callback;
}

u32 synthAssignHandle(s32 voiceIndex) {
    SynthVoice* current;
    u32 handle;

    do {
        handle = gSynthNextHandle;
        gSynthNextHandle = handle + 1;
        gSynthNextHandle &= 0x7FFFFFFF;

        for (current = gSynthAllocatedVoices; current != 0; current = current->next) {
            if (current->handle == handle) {
                handle = 0xFFFFFFFF;
                break;
            }
        }

        for (current = gSynthQueuedVoices; current != 0; current = current->next) {
            if (current->handle == handle) {
                handle = 0xFFFFFFFF;
                break;
            }
        }
    } while (handle == 0xFFFFFFFF);

    gSynthVoices[voiceIndex].handle = handle;
    return handle;
}

#pragma scheduling off
#pragma peephole off
u32 synthResolveHandle(u32 handle) {
    SynthVoice* voice;
    for (voice = gSynthAllocatedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            return voice->slotIndex | (handle & 0x80000000);
        }
    }

    for (voice = gSynthQueuedVoices; voice != 0; voice = voice->next) {
        if (voice->handle == (handle & 0x7FFFFFFF)) {
            return voice->slotIndex | (handle & 0x80000000);
        }
    }

    return 0xFFFFFFFF;
}
#pragma peephole reset
#pragma scheduling reset
