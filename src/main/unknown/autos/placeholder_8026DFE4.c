#include "main/unknown/autos/placeholder_8026DFE4.h"

/* Placeholder for the larger channel-event walker. */
SynthSequenceEvent* synthGetNextChannelEvent(u8 channel) {
    (void)channel;
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
