#include "main/audio/synth_seq_events.h"

typedef struct SynthVoiceKeyGroups
{
    u8 pad[0x14E8];
    SynthKeyGroupState keyGroupStates[SYNTH_VOICE_NOTE_COUNT];
} SynthVoiceKeyGroups;

#define SYNTH_TRACK_COMMAND_END  0xFFFF
#define SYNTH_TRACK_COMMAND_JUMP 0xFFFE

#define TRACK_CMD(cursor) ((SynthTrackCommand*)(cursor)->current)

#define KEYGROUP_STATE(voice, index) (((SynthKeyGroupState*)((u8*)(voice) + 0x14E8))[index])

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
    track = SYNTH_TRACK_CURSOR(gSynthCurrentVoice, channel);
    pattern = SYNTH_SEQUENCE_STATE(gSynthCurrentVoice, trackId);

    if (track->current != 0)
    {
        ev = SYNTH_CHANNEL_EVENT(gSynthCurrentVoice, trackId);
        ev->trackId = channel;
        ev->state = pattern;

        for (;;)
        {
            if (pattern->noteData == 0)
            {
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
                    else if (KEYGROUP_STATE(gSynthCurrentVoice, SYNTH_KEYGROUP_MAP(gSynthCurrentVoice)[trackId]).active)
                    {
                        track->current = 0;
                        return 0;
                    }

                    ev->type = 3;
                    ev->time = TRACK_CMD(track)->value0;
                    track->current = track->base + TRACK_CMD(track)->arg * sizeof(SynthTrackCommand);
                    return ev;
                }

                ev->type = 4;
                ev->time = TRACK_CMD(track)->value0;
                ev->data = track->current;
                track->current = TRACK_CMD(track) + 1;
                return ev;
            }

            pitchTime = pattern->pitchBend.nextTime;
            modTime = pattern->modulation.nextTime;

            for (;;)
            {
                patternTime = *(u16*)pattern->noteData + pattern->lastTime;
                if (patternTime < pitchTime && patternTime < modTime)
                {
                    if (pattern->noteData[2] == 0xFF && pattern->noteData[3] == 0xFF)
                    {
                        pattern->noteData = 0;
                        break;
                    }

                    ev->data = pattern->noteData;
                    pattern->lastTime = patternTime;

                    if ((pattern->noteData[2] & 0x80) != 0)
                    {
                        pattern->noteData += 4;
                    }
                    else if ((pattern->noteData[2] | pattern->noteData[3]) == 0)
                    {
                        pattern->noteData += 4;
                        continue;
                    }
                    else
                    {
                        pattern->noteData += 6;
                    }
                    ev->type = 0;
                    ev->time = patternTime + pattern->baseTime;
                }
                else if (pitchTime < modTime)
                {
                    ev->time = pitchTime + pattern->baseTime;
                    ev->type = 2;
                }
                else
                {
                    ev->time = modTime + pattern->baseTime;
                    ev->type = 1;
                }
                return ev;
            }
        }
    }

    return 0;
}

/*
 * Sorted-by-time insert into a channel event queue.
 */
void synthInsertChannelEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event)
{
    SynthSequenceEvent* current;
    SynthSequenceEvent* prev;

    prev = 0;
    current = queue->eventList;
    while (current != 0)
    {
        if (current->time > event->time)
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
