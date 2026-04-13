#include "src/audio/synth_internal.h"
#include "src/audio/synth_voice_overlays.h"

void fn_8026EFC8(void) {
    SynthSequenceEvent* event;
    SynthSequenceQueue* queue;
    SynthVoice* voice;
    u8* keyGroupMap;
    u8 channel;

    voice = gSynthCurrentVoice;
    keyGroupMap = SYNTH_KEYGROUP_MAP(voice);
    if (keyGroupMap == 0) {
        queue = SYNTH_SEQUENCE_QUEUE(voice, 0);
        for (channel = 0; channel < SYNTH_SEQUENCE_TRACK_COUNT; channel++) {
            event = synthGetNextChannelEvent(channel);
            if (event != 0) {
                synthInsertChannelEvent(queue, event);
            }
        }
        return;
    }

    for (channel = 0; channel < SYNTH_SEQUENCE_TRACK_COUNT; channel++) {
        event = synthGetNextChannelEvent(channel);
        if (event != 0) {
            synthInsertChannelEvent(SYNTH_SEQUENCE_QUEUE(voice, keyGroupMap[channel]), event);
        }
    }
}

void fn_8026F070(u8 groupIndex) {
    SynthSequenceEvent* event;
    SynthSequenceQueue* queue;
    SynthVoice* voice;
    u8* keyGroupMap;
    u8 channel;

    voice = gSynthCurrentVoice;
    keyGroupMap = SYNTH_KEYGROUP_MAP(voice);
    if (keyGroupMap == 0) {
        queue = SYNTH_SEQUENCE_QUEUE(voice, 0);
        for (channel = 0; channel < SYNTH_SEQUENCE_TRACK_COUNT; channel++) {
            event = synthGetNextChannelEvent(channel);
            if (event != 0) {
                synthInsertChannelEvent(queue, event);
            }
        }
        return;
    }

    queue = SYNTH_SEQUENCE_QUEUE(voice, groupIndex);
    for (channel = 0; channel < SYNTH_SEQUENCE_TRACK_COUNT; channel++) {
        if (keyGroupMap[channel] == groupIndex) {
            event = synthGetNextChannelEvent(channel);
            if (event != 0) {
                synthInsertChannelEvent(queue, event);
            }
        }
    }
}
