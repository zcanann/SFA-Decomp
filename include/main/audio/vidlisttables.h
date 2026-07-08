#ifndef MAIN_AUDIO_VIDLISTTABLES_H_
#define MAIN_AUDIO_VIDLISTTABLES_H_

#include "types.h"

typedef struct SynthRootListNode
{
    u16 next;
    u16 prev;
} SynthRootListNode;

typedef struct SynthVoiceListNode
{
    u8 prev;
    u8 next;
    u16 user;
} SynthVoiceListNode;

typedef struct VidListTables
{
    u8 vidLists[0x800];
    u8 midiKeySlots[0x80];
    u8 directSlots[0x40];
    SynthVoiceListNode priorityLinks[0x40];
    u8 priorityGroupHeads[0x100];
    SynthRootListNode prioritySortLinks[0x100];
    SynthVoiceListNode freeList[0x40];
} VidListTables;

#endif /* MAIN_AUDIO_VIDLISTTABLES_H_ */
