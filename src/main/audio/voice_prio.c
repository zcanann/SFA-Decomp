#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"



extern u8 vidListNodes[];
extern u16 voicePrioSortRootListRoot;

typedef struct VoicePrioVoice
{
    u8 prev;
    u8 next;
    u16 user;
} VoicePrioVoice;

typedef struct VoicePrioRoot
{
    u16 next;
    u16 prev;
} VoicePrioRoot;

/* Voice priority bookkeeping lives directly behind the vid node pool. */
typedef struct VoicePrioBlock
{
    u8 vidNodes[0x8C0];
    VoicePrioVoice prioVoices[64]; /* 0x8C0 */
    u8 prioVoicesRoot[256]; /* 0x9C0 */
    VoicePrioRoot prioRootList[256]; /* 0xAC0 */
} VoicePrioBlock;

/*
 * Insert the voice into the new priority group's list and keep the global
 * group list sorted by priority.
 */
typedef struct VoicePrioPrev
{
    u16 prev;
    u16 pad;
} VoicePrioPrev;

/* prev links viewed as their own table at +0xAC2 (matches target addressing) */
#define ROOT_PREV(idx) (((VoicePrioPrev *)((u8 *)vb + 0xAC2))[idx].prev)

void voiceSetPriority(McmdVoiceState* svoice, u8 prio)
{
    u32 v;
    VoicePrioBlock* vb;
    u16 li;
    VoicePrioVoice* vps;
    u16 root;
    u16 i;

    v = (u8)svoice->voiceHandle;
    vb = (VoicePrioBlock*)vidListNodes;
    vps = (VoicePrioVoice*)&((u8*)vb)[(v << 2) + 2240];
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
    if ((vps->next = vb->prioVoicesRoot[prio]) != 0xFF)
    {
        vb->prioVoices[vb->prioVoicesRoot[prio]].prev = v;
    }
    else if ((root = voicePrioSortRootListRoot) != 0xFFFF)
    {
        if (prio >= root)
        {
            for (i = root; i != 0xFFFF; i = vb->prioRootList[i].next)
            {
                if (i > prio)
                {
                    break;
                }
                li = i;
            }

            vb->prioRootList[li].next = prio;
            ROOT_PREV(prio) = li;
            vb->prioRootList[prio].next = i;
            if (i != 0xFFFF)
            {
                ROOT_PREV(i) = prio;
            }
        }
        else
        {
            vb->prioRootList[prio].next = root;
            ROOT_PREV(prio) = 0xFFFF;
            ROOT_PREV(root) = prio;
            voicePrioSortRootListRoot = prio;
        }
    }
    else
    {
        vb->prioRootList[prio].next = 0xFFFF;
        ROOT_PREV(prio) = 0xFFFF;
        voicePrioSortRootListRoot = prio;
    }

    vb->prioVoicesRoot[prio] = v;
    svoice->priorityGroup = prio;
    hwSetPriority(svoice->voiceHandle & 0xFF, ((u32)prio << 24) | (svoice->priorityValue >> 15));
}
