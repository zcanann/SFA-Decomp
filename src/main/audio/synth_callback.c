#include "src/main/audio/synth_voice_overlays.h"

#define SYNTH_CALLBACK_ACTIVE_LIST_COUNT 2
#define SYNTH_CALLBACK_COMPLETED_LIST_INDEX 2

void synthRecycleVoiceCallbacks(SynthVoice* voice)
{
    SynthCallbackLink* callback;

    s32 listIndex;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++)
    {
        if ((callback = voice->callbackLists[listIndex]) != 0)
        {
            while (callback->next != 0)
            {
                callback = callback->next;
            }

            if (gSynthFreeCallbacks != 0)
            {
                callback->next = gSynthFreeCallbacks;
                gSynthFreeCallbacks->prev = callback;
            }

            gSynthFreeCallbacks = voice->callbackLists[listIndex];
            voice->callbackLists[listIndex] = 0;
        }
    }

    if ((callback = voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]) != 0)
    {
        while (callback->next != 0)
        {
            callback = callback->next;
        }

        if (gSynthFreeCallbacks != 0)
        {
            callback->next = gSynthFreeCallbacks;
            gSynthFreeCallbacks->prev = callback;
        }

        gSynthFreeCallbacks = voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
        voice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = 0;
    }
}

SynthCallbackLink* synthAllocCallback(s32 triggerValue, u8 controllerIndex)
{
    SynthCallbackLink* callback;
    SynthCallbackLink* next;
    register SynthCallbackLink* current;
    register SynthCallbackLink* prev;

    if ((callback = gSynthFreeCallbacks) != 0)
    {
        gSynthFreeCallbacks = next = callback->next;
        if (next != 0)
        {
            gSynthFreeCallbacks->prev = 0;
        }

        callback->triggerValue = triggerValue;
        callback->controllerIndex = controllerIndex;
        prev = 0;
        {
            u8* ccsBase = (u8*)gSynthCurrentVoice + 0x1518;
            callback->listIndex =
                ((SynthCallbackControllerState*)(ccsBase + controllerIndex * 0x38))->listIndex;
        }

        current = gSynthCurrentVoice->callbackLists[callback->listIndex];
        while (current != 0)
        {
            if (current->triggerValue > callback->triggerValue)
            {
                callback->next = current;
                callback->prev = prev;
                if (prev != 0)
                {
                    prev->next = callback;
                }
                else
                {
                    gSynthCurrentVoice->callbackLists[callback->listIndex] = callback;
                }
                current->prev = callback;
                return callback;
            }

            prev = current;
            current = current->next;
        }

        callback->prev = prev;
        if (prev != 0)
        {
            prev->next = callback;
        }
        else
        {
            gSynthCurrentVoice->callbackLists[callback->listIndex] = callback;
        }
        callback->next = 0;
    }

    return callback;
}

s32 synthUpdateCallbacks(void)
{
    SynthCallbackLink* callback;
    u32 listIndex;
    SynthCallbackLink* next;
    SynthCallbackLink* completed;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++)
    {
        if ((callback = gSynthCurrentVoice->callbackLists[listIndex]) != 0)
        {
            goto checkThreshold;
            while (1)
            {
                synthSendKeyOff(callback->callbackId);
                next = callback->next;
                gSynthCurrentVoice->callbackLists[listIndex] = next;
                if (next != 0)
                {
                    gSynthCurrentVoice->callbackLists[listIndex]->prev = 0;
                }

                completed = gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
                callback->next = completed;
                if (completed != 0)
                {
                    gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
                }
                gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
                if ((callback = gSynthCurrentVoice->callbackLists[listIndex]) == 0)
                {
                    break;
                }
            checkThreshold:
                if (callback->triggerValue >
                    (s32)gSynthCurrentVoice->section[callback->controllerIndex].time[listIndex].high)
                {
                    break;
                }
            }
        }
    }

    return gSynthCurrentVoice->callbackLists[0] != 0 || gSynthCurrentVoice->callbackLists[1] != 0;
}

void synthFlushCallbacks(void)
{
    SynthCallbackLink* callback;
    SynthCallbackLink* next;
    u32 listIndex;
    SynthCallbackLink* completed;

    for (listIndex = 0; listIndex < SYNTH_CALLBACK_ACTIVE_LIST_COUNT; listIndex++)
    {
        callback = gSynthCurrentVoice->callbackLists[listIndex];
        while (callback != 0)
        {
            next = callback->next;
            synthSendKeyOff(callback->callbackId);
            completed = callback->next;
            gSynthCurrentVoice->callbackLists[listIndex] = completed;
            if (completed != 0)
            {
                gSynthCurrentVoice->callbackLists[listIndex]->prev = 0;
            }

            completed = gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX];
            callback->next = completed;
            if (completed != 0)
            {
                gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX]->prev = callback;
            }
            gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback;
            callback = next;
        }
    }
}

void synthFreeCallback(SynthCallbackLink* callback)
{
    if (callback->next != 0)
    {
        callback->next->prev = callback->prev;
    }

    if (callback->prev != 0)
    {
        callback->prev->next = callback->next;
    }
    else
    {
        gSynthCurrentVoice->callbackLists[SYNTH_CALLBACK_COMPLETED_LIST_INDEX] = callback->next;
    }

    {
        SynthCallbackLink* freeCallback = gSynthFreeCallbacks;
        callback->next = freeCallback;
        if (freeCallback != 0)
        {
            gSynthFreeCallbacks->prev = callback;
        }
    }

    callback->prev = 0;
    gSynthFreeCallbacks = callback;
}

u32 synthAssignHandle(s32 voiceIndex)
{
    SynthVoice* queuedVoices;
    SynthVoice* allocatedVoices;
    u32 handle;
    SynthVoice* current;

    queuedVoices = gSynthQueuedVoices;
    allocatedVoices = gSynthAllocatedVoices;
    do
    {
        handle = gSynthNextHandle;
        gSynthNextHandle = handle + 1;
        gSynthNextHandle &= SYNTH_HANDLE_ID_MASK;

        for (current = queuedVoices; current != 0; current = current->next)
        {
            if (current->handle == handle)
            {
                handle = SYNTH_HANDLE_INVALID;
                break;
            }
        }

        for (current = allocatedVoices; current != 0; current = current->next)
        {
            if (current->handle == handle)
            {
                handle = SYNTH_HANDLE_INVALID;
                break;
            }
        }
    }
    while (handle == SYNTH_HANDLE_INVALID);

    gSynthVoices[voiceIndex].handle = handle;
    return handle;
}

u32 synthResolveHandle(u32 handle)
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
