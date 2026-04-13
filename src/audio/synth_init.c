#include "src/audio/synth_internal.h"

void synthInitVoices(void) {
    SynthVoiceRuntime* runtime;
    SynthCallbackLink* callback;
    SynthCallbackLink* prevCallback;
    u16* note;
    SynthVoice* voice;
    u8 voiceIndex;
    s32 callbackIndex;

    runtime = SYNTH_VOICE_RUNTIME();
    gSynthAllocatedVoices = 0;
    gSynthQueuedVoices = 0;

    voice = &runtime->voices[0];
    note = &runtime->voiceNotes[0][0];
    for (voiceIndex = 0; voiceIndex < SYNTH_MAX_VOICES;) {
        if (voiceIndex == 0) {
            gSynthFreeVoices = voice;
            voice->prev = 0;
        } else {
            voice[-1].next = voice;
            voice->prev = &voice[-1];
        }
        voice->slotIndex = (u8)voiceIndex;
        voice->state = 0;

        note[0] = 0xFFFF;
        note[1] = 0xFFFF;
        note[2] = 0xFFFF;
        note[3] = 0xFFFF;
        note[4] = 0xFFFF;
        note[5] = 0xFFFF;
        note[6] = 0xFFFF;
        note[7] = 0xFFFF;
        note[8] = 0xFFFF;
        note[9] = 0xFFFF;
        note[10] = 0xFFFF;
        note[11] = 0xFFFF;
        note[12] = 0xFFFF;
        note[13] = 0xFFFF;
        note[14] = 0xFFFF;
        note[15] = 0xFFFF;

        voice++;
        note += SYNTH_VOICE_NOTE_COUNT;
        voiceIndex++;

        if (voiceIndex == 0) {
            gSynthFreeVoices = voice;
            voice->prev = 0;
        } else {
            voice[-1].next = voice;
            voice->prev = &voice[-1];
        }
        voice->slotIndex = voiceIndex;
        voice->state = 0;

        note[0] = 0xFFFF;
        note[1] = 0xFFFF;
        note[2] = 0xFFFF;
        note[3] = 0xFFFF;
        note[4] = 0xFFFF;
        note[5] = 0xFFFF;
        note[6] = 0xFFFF;
        note[7] = 0xFFFF;
        note[8] = 0xFFFF;
        note[9] = 0xFFFF;
        note[10] = 0xFFFF;
        note[11] = 0xFFFF;
        note[12] = 0xFFFF;
        note[13] = 0xFFFF;
        note[14] = 0xFFFF;
        note[15] = 0xFFFF;

        voice++;
        note += SYNTH_VOICE_NOTE_COUNT;
        voiceIndex++;
    }
    voice[-1].next = 0;

    gSynthFreeCallbacks = &runtime->callbacks[0];
    prevCallback = 0;
    for (callbackIndex = 0; callbackIndex < SYNTH_CALLBACK_COUNT; callbackIndex++) {
        callback = &runtime->callbacks[callbackIndex];
        callback->prev = prevCallback;
        if (prevCallback != 0) {
            prevCallback->next = callback;
        }
        prevCallback = callback;
    }
    prevCallback->next = 0;

    gSynthNextHandle = 0;
}
