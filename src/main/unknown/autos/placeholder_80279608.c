#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80279608.h"

extern void fn_802794EC(void *state);
extern void hwSetPriority(u8 voiceId, u32 priority);

extern u8 lbl_803CA2D0[];   /* voice tables */
extern u16 lbl_803DE2FC;    /* sorted-list head (u16) */

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
void fn_802795CC(int state, u8 newGroup)
{
    u32 voiceId = *(u8 *)(state + 0xf4);
    u8 *base = lbl_803CA2D0;
    u8 *slot = base + voiceId * 4 + 0x8c0;
    u16 oldFirst;
    u16 prev;
    u16 cur;

    /* if already assigned to a group: short-circuit if same group, else remove */
    if (*(u16 *)(slot + 2) == 1) {
        if (*(u8 *)(state + 0x10c) == newGroup) {
            return;
        }
        fn_802794EC((void *)state);
    }

    *(u16 *)(slot + 2) = 1;
    *(u8 *)(slot + 0) = 0xff;

    /* prepend to new group's linked list */
    {
        u8 *groupHead = base + newGroup * 4 + 0x9c0;
        oldFirst = *groupHead;
        *(u8 *)(slot + 1) = (u8)oldFirst;
        if ((u8)oldFirst == 0xff) {
            /* group was empty: insert into the global priority list */
            cur = lbl_803DE2FC;
            if (cur == 0xffff) {
                /* list empty: voice becomes head and tail */
                *(u16 *)(base + voiceId * 4 + 0xac0) = 0xffff;
                *(u16 *)(base + voiceId * 4 + 0xac2) = 0xffff;
                lbl_803DE2FC = (u16)voiceId;
            } else if ((u32)cur > voiceId) {
                /* prepend: voice's next = old head, old head's prev = voice */
                *(u16 *)(base + voiceId * 4 + 0xac0) = cur;
                *(u16 *)(base + voiceId * 4 + 0xac2) = 0xffff;
                *(u16 *)(base + cur * 4 + 0xac2) = (u16)voiceId;
                lbl_803DE2FC = (u16)voiceId;
            } else {
                /* walk list: find first node with id > voiceId */
                prev = cur;
                cur = *(u16 *)(base + cur * 4 + 0xac0);
                while (cur != 0xffff) {
                    if (cur > voiceId) {
                        break;
                    }
                    prev = cur;
                    cur = *(u16 *)(base + cur * 4 + 0xac0);
                }
                /* insert after prev */
                *(u16 *)(base + prev * 4 + 0xac0) = (u16)voiceId;
                *(u16 *)(base + voiceId * 4 + 0xac2) = prev;
                *(u16 *)(base + voiceId * 4 + 0xac0) = cur;
                if (cur != 0xffff) {
                    *(u16 *)(base + cur * 4 + 0xac2) = (u16)voiceId;
                }
            }
        } else {
            /* group had voices: link old first to new voice */
            *(u8 *)(base + oldFirst * 4 + 0x8c0) = (u8)voiceId;
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
