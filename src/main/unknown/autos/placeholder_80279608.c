#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80279608.h"

extern void voiceRemovePriority(int state);
extern void hwSetPriority(u8 voiceId, u32 priority);

extern u8 vidListNodes[];
extern u16 voicePrioSortRootListRoot;    /* sorted-list head (u16) */

#define voicePriorityLinks (vidListNodes + 0x8c0)
#define voicePriorityGroupHeads (vidListNodes + 0x9c0)
#define voicePrioritySortLinks (vidListNodes + 0xac0)

/*
 * Inserts the voice into the new group's linked list (prepend) and
 * into the global priority-sorted list (sorted insert). Removes the
 * voice from any prior group first.
 *
 * EN v1.0 Address: 0x802795CC
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80279608
 * EN v1.1 Size: 400b
 */
void voiceSetPriority(int state, u8 newGroup)
{
    u8 *nodes = vidListNodes;
    u32 voiceHandle = *(u32 *)(state + 0xf4);
    u32 voiceId = voiceHandle & 0xff;
    u8 *slot = nodes + 0x8c0 + ((voiceHandle << 2) & 0x3fc);
    u8 oldFirst;
    u16 prev;
    u16 cur;

    /* if already assigned to a group: short-circuit if same group, else remove */
    if (*(u16 *)(slot + 2) == 1) {
        if (*(u8 *)(state + 0x10c) == newGroup) {
            return;
        }
        voiceRemovePriority(state);
    }

    *(u16 *)(slot + 2) = 1;
    *(u8 *)(slot + 0) = 0xff;

    /* prepend to new group's linked list */
    {
        u32 group = newGroup;
        u8 *groupHead = nodes + group + 0x9c0;
        oldFirst = *groupHead;
        *(u8 *)(slot + 1) = oldFirst;
        if (oldFirst != 0xff) {
            /* group had voices: link old first to new voice */
            *(u8 *)(nodes + 0x8c0 + oldFirst * 4) = (u8)voiceId;
        } else {
            /* group was empty: insert into the global priority list */
            cur = voicePrioSortRootListRoot;
            if (cur != 0xffff) {
                if (group < cur) {
                    /* prepend: group's next = old head, old head's prev = group */
                    *(u16 *)(nodes + 0xac0 + group * 4) = cur;
                    *(u16 *)(nodes + 0xac2 + group * 4) = 0xffff;
                    *(u16 *)(nodes + 0xac2 + cur * 4) = (u16)group;
                    voicePrioSortRootListRoot = (u16)group;
                } else {
                    /* walk list: find first node with id > group */
                    prev = cur;
                    cur = *(u16 *)(nodes + 0xac0 + cur * 4);
                    while (cur != 0xffff) {
                        if (cur > group) {
                            break;
                        }
                        prev = cur;
                        cur = *(u16 *)(nodes + 0xac0 + cur * 4);
                    }
                    /* insert after prev */
                    *(u16 *)(nodes + 0xac0 + prev * 4) = (u16)group;
                    *(u16 *)(nodes + 0xac2 + group * 4) = prev;
                    *(u16 *)(nodes + 0xac0 + group * 4) = cur;
                    if (cur != 0xffff) {
                        *(u16 *)(nodes + 0xac2 + cur * 4) = (u16)group;
                    }
                }
            } else {
                /* list empty: group becomes head and tail */
                *(u16 *)(nodes + 0xac0 + group * 4) = 0xffff;
                *(u16 *)(nodes + 0xac2 + group * 4) = 0xffff;
                voicePrioSortRootListRoot = (u16)group;
            }
        }
        *groupHead = (u8)voiceId;
    }

    *(u8 *)(state + 0x10c) = newGroup;
    {
        u32 prio = *(u32 *)(state + 0x110) >> 15;
        prio |= ((u32)newGroup & 0xff) << 24;
        hwSetPriority((u8)voiceId, prio);
    }
}
