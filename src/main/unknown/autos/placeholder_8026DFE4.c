#include "main/unknown/autos/placeholder_8026DFE4.h"

#define SYNTH_TRACK_COMMAND_END 0xFFFF
#define SYNTH_TRACK_COMMAND_JUMP 0xFFFE

SynthSequenceEvent* synthGetNextChannelEvent(u8 channel) {
    SynthSequenceEvent* event;
    SynthKeyGroupState* keyGroupState;
    SynthSequenceState* state;
    SynthTrackCommand* command;
    SynthTrackCursor* cursor;
    SynthVoice* voice;
    u8* keyGroupMap;
    u8* stream;
    u32 primaryLimit;
    u32 secondaryLimit;
    u32 channelIndex;
    u32 value;

    channelIndex = channel;
    voice = gSynthCurrentVoice;
    cursor = SYNTH_TRACK_CURSOR(voice, channelIndex);
    state = SYNTH_SEQUENCE_STATE(voice, channelIndex);
    if (cursor->current != 0) {
        event = SYNTH_CHANNEL_EVENT(voice, channelIndex);
        event->channel = channel;
        event->state = state;

        if (state->stream != 0) {
            goto handle_stream;
        }

handle_command:
        command = cursor->current;
        if (command->command == SYNTH_TRACK_COMMAND_END) {
            cursor->current = 0;
            return 0;
        }

        if (command->command == SYNTH_TRACK_COMMAND_JUMP) {
            keyGroupMap = SYNTH_KEYGROUP_MAP(voice);
            if (keyGroupMap == 0) {
                keyGroupState = SYNTH_KEYGROUP_STATE(voice, 0);
                if (keyGroupState->active != 0) {
                    cursor->current = 0;
                    return 0;
                }
            } else {
                keyGroupState = SYNTH_KEYGROUP_STATE(voice, keyGroupMap[channelIndex]);
                if (keyGroupState->active != 0) {
                    cursor->current = 0;
                    return 0;
                }
            }

            event->type = 3;
            event->value = command->value0;
            cursor->current = cursor->base + (command->arg * sizeof(SynthTrackCommand));
            return event;
        }

        event->type = 4;
        event->value = command->value0;
        event->eventData = command;
        cursor->current = command + 1;
        return event;

handle_stream:
        primaryLimit = state->primaryLimit;
        secondaryLimit = state->secondaryLimit;
        while (1) {
            stream = state->stream;
            value = *(u16*)stream + state->currentValue;
            if (value >= primaryLimit) {
                if (primaryLimit < secondaryLimit) {
                    event->value = primaryLimit + state->valueOffset;
                    event->type = 2;
                    return event;
                }
            } else if (value < secondaryLimit) {
                if (stream[2] == 0xFF && stream[3] == 0xFF) {
                    state->stream = 0;
                    goto handle_command;
                }

                event->eventData = stream;
                state->currentValue = value;
                stream = state->stream;
                if ((stream[2] & 0x80) != 0) {
                    state->stream = stream + 4;
                } else if ((stream[2] | stream[3]) != 0) {
                    state->stream = stream + 6;
                } else {
                    state->stream = stream + 4;
                    continue;
                }

                event->type = 0;
                event->value = value + state->valueOffset;
                return event;
            }

            event->value = secondaryLimit + state->valueOffset;
            event->type = 1;
            return event;
        }
    }

    return 0;
}

/*
 * Sorted-by-time insert into a channel event queue.
 *
 * EN v1.0 Address: 0x8026E070
 * EN v1.0 Size: 116b
 */
void synthInsertChannelEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event) {
    SynthSequenceEvent* current;
    SynthSequenceEvent* prev;

    prev = 0;
    current = queue->eventList;
    while (current != 0) {
        if (current->value > event->value) {
            event->next = current;
            event->prev = prev;
            if (prev != 0) {
                prev->next = event;
            } else {
                queue->eventList = event;
            }
            current->prev = event;
            return;
        }

        prev = current;
        current = current->next;
    }

    event->prev = prev;
    if (prev != 0) {
        prev->next = event;
    } else {
        queue->eventList = event;
    }
    event->next = 0;
}
