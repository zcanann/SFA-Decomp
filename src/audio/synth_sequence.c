#include "src/audio/synth_internal.h"
#include "src/audio/synth_voice_overlays.h"

#define SYNTH_TRACK_COMMAND_END 0xFFFF
#define SYNTH_TRACK_COMMAND_JUMP 0xFFFE

u8* synthReadVariablePair(u8* input, u16* value0, s16* value1) {
    s16 combined;
    s32 shift;
    u32 combinedValue;
    u8 high;
    u8 low;

    high = input[0];
    low = input[1];
    if (high == 0x80 && low == 0) {
        return 0;
    }

    if ((high & 0x80) != 0) {
        combinedValue = (u32)((high & 0x7F) << 8);
        combinedValue = combinedValue | low;
        *value0 = (u16)combinedValue;
        input += 2;
    } else {
        *value0 = high;
        input += 1;
    }

    high = input[0];
    low = input[1];
    if ((high & 0x80) != 0) {
        combinedValue = (u32)((high & 0x7F) << 8);
        combinedValue = combinedValue | low;
        combined = (s16)combinedValue;
        shift = 1;
        combined = (s16)(combined << shift);
        *value1 = (s16)(combined >> shift);
        input += 2;
    } else {
        combined = high;
        shift = 9;
        combined = (s16)(combined << shift);
        *value1 = (s16)(combined >> shift);
        input += 1;
    }

    return input;
}

SynthSequenceEvent* synthGetNextChannelEvent(u8 channel) {
    SynthSequenceEvent* event;
    SynthKeyGroupState* keyGroupState;
    SynthSequenceState* state;
    SynthTrackCommand* command;
    SynthTrackCursor* cursor;
    SynthVoice* voice;
    u8* keyGroupMap;
    u8* stream;
    u32 value;

    voice = gSynthCurrentVoice;
    cursor = SYNTH_TRACK_CURSOR(voice, channel);
    state = SYNTH_SEQUENCE_STATE(voice, channel);
    if (cursor->current != 0) {
        event = SYNTH_CHANNEL_EVENT(voice, channel);
        event->channel = channel;
        event->state = state;

        if (state->stream == 0) {
            goto handle_command;
        } else {
            while (1) {
                stream = state->stream;
                value = *(u16*)stream + state->currentValue;
                if (value < state->primaryLimit) {
                    if (value < state->secondaryLimit) {
                        if (stream[2] == 0xFF && stream[3] == 0xFF) {
                            state->stream = 0;
                            goto handle_command;
                        }

                        event->eventData = stream;
                        state->currentValue = value;
                        if ((stream[2] & 0x80) != 0) {
                            state->stream = stream + 4;
                        } else if ((stream[2] | stream[3]) == 0) {
                            state->stream = stream + 4;
                            continue;
                        } else {
                            state->stream = stream + 6;
                        }

                        event->type = 0;
                        event->value = value + state->valueOffset;
                        return event;
                    }
                } else if (state->primaryLimit < state->secondaryLimit) {
                    event->value = state->primaryLimit + state->valueOffset;
                    event->type = 2;
                    return event;
                }

                event->value = state->secondaryLimit + state->valueOffset;
                event->type = 1;
                return event;
            }
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
                keyGroupState = SYNTH_KEYGROUP_STATE(voice, keyGroupMap[channel]);
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
    }

    return 0;
}

void synthInsertChannelEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event) {
    SynthSequenceEvent* current;
    SynthSequenceEvent* prev;

    prev = 0;
    for (current = queue->eventList; current != 0; current = current->next) {
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
    }

    event->prev = prev;
    if (prev != 0) {
        prev->next = event;
    } else {
        queue->eventList = event;
    }
    event->next = 0;
}
