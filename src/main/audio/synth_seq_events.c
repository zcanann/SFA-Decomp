#include "main/audio/synth_seq_events.h"

#define SYNTH_TRACK_COMMAND_END 0xFFFF
#define SYNTH_TRACK_COMMAND_JUMP 0xFFFE

#define TRACK_CMD(cursor) ((SynthTrackCommand*)(cursor)->current)

typedef struct SynthVoiceKeyGroups
{
    u8 pad[0x14E8];
    SynthKeyGroupState keyGroupStates[SYNTH_VOICE_NOTE_COUNT];
} SynthVoiceKeyGroups;

#define KEYGROUP_STATE(voice, index) \
    (((SynthKeyGroupState*)((u8*)(voice) + 0x14E8))[index])

SynthSequenceEvent* synthGetNextChannelEvent(u8 channel)
{
    u32 trackId;
    SynthTrackCursor* track;
    SynthSequenceEvent* ev;
    SynthSequenceState* pattern;
    u32 patternTime;
    u32 pitchTime;
    u32 modTime;

    trackId = channel;
    track = SYNTH_TRACK_CURSOR(gSynthCurrentVoice, trackId);
    pattern = SYNTH_SEQUENCE_STATE(gSynthCurrentVoice, trackId);

    if (track->current != 0)
    {
        ev = SYNTH_CHANNEL_EVENT(gSynthCurrentVoice, trackId);
        ev->channel = channel;
        ev->state = pattern;

        if (pattern->stream == 0)
        {
        null_pattern_addr:
            if (TRACK_CMD(track)->command == SYNTH_TRACK_COMMAND_END)
            {
                track->current = 0;
                return 0;
            }

            if (TRACK_CMD(track)->command == SYNTH_TRACK_COMMAND_JUMP)
            {
                if (SYNTH_KEYGROUP_MAP(gSynthCurrentVoice) == 0)
                {
                    if (KEYGROUP_STATE(gSynthCurrentVoice, 0).active)
                    {
                        track->current = 0;
                        return 0;
                    }
                }
                else if (KEYGROUP_STATE(gSynthCurrentVoice,
                                        SYNTH_KEYGROUP_MAP(gSynthCurrentVoice)[trackId]).active)
                {
                    track->current = 0;
                    return 0;
                }

                ev->type = 3;
                ev->value = TRACK_CMD(track)->value0;
                track->current = track->base + TRACK_CMD(track)->arg * sizeof(SynthTrackCommand);
                return ev;
            }

            ev->type = 4;
            ev->value = TRACK_CMD(track)->value0;
            ev->eventData = track->current;
            track->current = TRACK_CMD(track) + 1;
            return ev;
        }

        pitchTime = pattern->primaryLimit;
        modTime = pattern->secondaryLimit;

    loop:
        patternTime = *(u16*)pattern->stream + pattern->currentValue;
        if (patternTime >= pitchTime)
        {
            goto use_pitch_time;
        }
        if (patternTime >= modTime)
        {
            goto use_mod_time;
        }
        if (pattern->stream[2] == 0xFF && pattern->stream[3] == 0xFF)
        {
            pattern->stream = 0;
            goto null_pattern_addr;
        }

        ev->eventData = pattern->stream;
        pattern->currentValue = patternTime;

        if ((pattern->stream[2] & 0x80) != 0)
        {
            pattern->stream += 4;
            goto use_pattern_time;
        }
        if ((pattern->stream[2] | pattern->stream[3]) == 0)
        {
            pattern->stream += 4;
            goto loop;
        }
        pattern->stream += 6;

    use_pattern_time:
        ev->type = 0;
        ev->value = patternTime + pattern->valueOffset;
        goto end;

    use_pitch_time:
        if (pitchTime < modTime)
        {
            ev->value = pitchTime + pattern->valueOffset;
            ev->type = 2;
            goto end;
        }

    use_mod_time:
        ev->value = modTime + pattern->valueOffset;
        ev->type = 1;

    end:
        return ev;
    }

    return 0;
}

/*
 * Sorted-by-time insert into a channel event queue.
 *
 * EN v1.0 Address: 0x8026E070
 * EN v1.0 Size: 116b
 */
void synthInsertChannelEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event)
{
    SynthSequenceEvent* current;
    SynthSequenceEvent* prev;

    prev = 0;
    current = queue->eventList;
    while (current != 0)
    {
        if (current->value > event->value)
        {
            event->next = current;
            event->prev = prev;
            if (prev != 0)
            {
                prev->next = event;
            }
            else
            {
                queue->eventList = event;
            }
            current->prev = event;
            return;
        }

        prev = current;
        current = current->next;
    }

    event->prev = prev;
    if (prev != 0)
    {
        prev->next = event;
    }
    else
    {
        queue->eventList = event;
    }
    event->next = 0;
}
