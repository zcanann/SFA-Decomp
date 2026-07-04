#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"



extern u8 vidListNodes[];
extern u16 voicePrioSortRootListRoot;

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

#define VB_PRIO_HEAD(vb, p) \
    (*(u8*)((u8*)&(vb)->priorityGroupHeads[0] + (p)))
#define VB_PRIO_LINK(vb, i) \
    ((SynthVoiceListNode*)((u8*)&(vb)->priorityLinks[0] + (i) * 4))
typedef struct VoicePrioPrev
{
    u16 prev;
    u16 pad;
} VoicePrioPrev;

#define VB_PRIO_SORT_NEXT(vb, p) \
    (((SynthRootListNode*)((u8*)&(vb)->prioritySortLinks[0] + (p) * 4))->next)
#define VB_PRIO_SORT_PREV(vb, p) \
    (((VoicePrioPrev *)((u8 *)&(vb)->prioritySortLinks[0] + 2))[p].prev)

/*
 * Insert the voice into the new priority group's list and keep the global
 * group list sorted by priority.
 */
void voiceSetPriority(McmdVoiceState* svoice, u8 prio)
{
    u32 v;
    VidListTables* vb;
    u16 li;
    SynthVoiceListNode* vps;
    u16 root;
    u16 i;

    v = (u8)svoice->voiceHandle;
    vb = (VidListTables*)vidListNodes;
    vps = VB_PRIO_LINK(vb, v);
    if (vps->user == 1)
    {
        if (svoice->priorityGroup == prio)
        {
            return;
        }

        voiceRemovePriority((int)svoice);
    }

    vps->user = 1;
    vps->prev = 0xff;
    if ((vps->next = VB_PRIO_HEAD(vb, prio)) != 0xFF)
    {
        VB_PRIO_LINK(vb, VB_PRIO_HEAD(vb, prio))->prev = v;
    }
    else if ((root = voicePrioSortRootListRoot) != 0xFFFF)
    {
        if (prio >= root)
        {
            for (i = root; i != 0xFFFF; i = VB_PRIO_SORT_NEXT(vb, i))
            {
                if (i > prio)
                {
                    break;
                }
                li = i;
            }

            VB_PRIO_SORT_NEXT(vb, li) = prio;
            VB_PRIO_SORT_PREV(vb, prio) = li;
            VB_PRIO_SORT_NEXT(vb, prio) = i;
            if (i != 0xFFFF)
            {
                VB_PRIO_SORT_PREV(vb, i) = prio;
            }
        }
        else
        {
            VB_PRIO_SORT_NEXT(vb, prio) = root;
            VB_PRIO_SORT_PREV(vb, prio) = 0xFFFF;
            VB_PRIO_SORT_PREV(vb, root) = prio;
            voicePrioSortRootListRoot = prio;
        }
    }
    else
    {
        VB_PRIO_SORT_NEXT(vb, prio) = 0xFFFF;
        VB_PRIO_SORT_PREV(vb, prio) = 0xFFFF;
        voicePrioSortRootListRoot = prio;
    }

    VB_PRIO_HEAD(vb, prio) = v;
    svoice->priorityGroup = prio;
    hwSetPriority(svoice->voiceHandle & 0xFF, ((u32)prio << 24) | (svoice->priorityValue >> 15));
}

SynthRootListNode voicePrioritySortLinks[0x100];
