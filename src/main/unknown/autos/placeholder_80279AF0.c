#include "ghidra_import.h"

extern void fn_80278A98(int state, int x);
extern void voiceRemovePriority(int state);

typedef struct VoiceIdSlot {
    u8 prev;
    u8 next;
    u16 active;
} VoiceIdSlot;

extern VoiceIdSlot voiceFreeListSlots[];
extern u8 *synthVoice;
extern u8 lbl_803BD150[];
extern u8 vidListNodes[];
extern u8 synthIdleWaitActive;
extern u16 voicePrioSortRootListRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceListInsert;
extern u8 voiceListRoot;

#define voicePriorityLinks (vidListNodes + 0x8c0)
#define voicePriorityGroupHeads (vidListNodes + 0x9c0)
#define voicePrioritySortLinks (vidListNodes + 0xac0)

/*
 * Allocate a voice id, preferring a free slot but stealing the lowest-priority
 * compatible active voice when limits are exceeded.
 */
u32 voiceAllocate(u8 priority, u8 maxInstances, u16 key, u8 streamKind)
{
    u8 voiceLink;
    u16 priorityNode;
    int enforceKind;
    u32 selectedVoice;
    u32 candidate;
    int state;
    u32 current;
    u32 limit;
    int matchingCount;

    if (synthIdleWaitActive != 0) {
        return 0xffffffff;
    }

    if (streamKind != 0) {
        enforceKind = 0;
        if ((lbl_803BD150[0x212] <= voiceFxRunning) &&
            (lbl_803BD150[0x212] < lbl_803BD150[0x210])) {
            enforceKind = 1;
        }
        if (maxInstances < lbl_803BD150[0x212]) {
            goto count_matching_key;
        }
    } else {
        enforceKind = 0;
        if ((lbl_803BD150[0x211] <= voiceMusicRunning) &&
            (lbl_803BD150[0x211] < lbl_803BD150[0x210])) {
            enforceKind = 1;
        }
        if (maxInstances < lbl_803BD150[0x211]) {
count_matching_key:
            matchingCount = 0;
            selectedVoice = 0xffffffff;
            priorityNode = voicePrioSortRootListRoot;
            while (((priorityNode != 0xffff) && (priorityNode <= priority)) &&
                   (selectedVoice == 0xffffffff)) {
                voiceLink = *(u8 *)(voicePriorityGroupHeads + priorityNode);
                while ((current = voiceLink) != 0xff) {
                    state = (int)(synthVoice + current * 0x404);
                    candidate = selectedVoice;
                    if (key == *(u16 *)(state + 0x100)) {
                        matchingCount++;
                        if ((*(u8 *)(state + 0x11c) == 0) &&
                            (!enforceKind || (streamKind == *(u8 *)(state + 0x11d))) &&
                            ((*(u32 *)(state + 0x118) & 2) == 0)) {
                            candidate = current;
                            if (selectedVoice != 0xffffffff) {
                                candidate = selectedVoice;
                                if (*(u32 *)(state + 0x110) <
                                    *(u32 *)(synthVoice + selectedVoice * 0x404 + 0x110)) {
                                    candidate = current;
                                }
                            }
                        }
                    }
                    selectedVoice = candidate;
                    voiceLink = *(u8 *)(voicePriorityLinks + 1 + current * 4);
                }
                priorityNode = *(u16 *)(voicePrioritySortLinks + (u32)priorityNode * 4);
            }
            limit = maxInstances;
            if ((int)limit <= matchingCount) {
                goto found_voice;
            }
            while (((current = priorityNode) != 0xffff) && (matchingCount < (int)limit)) {
                voiceLink = *(u8 *)(voicePriorityGroupHeads + current);
                while ((candidate = voiceLink) != 0xff) {
                    if (key == *(u16 *)(synthVoice + candidate * 0x404 + 0x100)) {
                        matchingCount++;
                    }
                    voiceLink = *(u8 *)(voicePriorityLinks + 1 + candidate * 4);
                }
                priorityNode = *(u16 *)(voicePrioritySortLinks + current * 4);
            }
            if ((int)limit <= matchingCount) {
                goto found_voice;
            }
        }
    }

    selectedVoice = voiceListRoot;
    candidate = 0xffffffff;
    if ((selectedVoice == 0xff) || (enforceKind)) {
        selectedVoice = voicePrioSortRootListRoot;
        if (priority < selectedVoice) {
            return 0xffffffff;
        }
        while (((selectedVoice != 0xffff) && (selectedVoice <= priority)) &&
               (candidate == 0xffffffff)) {
            voiceLink = *(u8 *)(voicePriorityGroupHeads + selectedVoice);
            while ((current = voiceLink) != 0xff) {
                state = (int)(synthVoice + current * 0x404);
                limit = candidate;
                if ((*(u8 *)(state + 0x11c) == 0) &&
                    (!enforceKind || (streamKind == *(u8 *)(state + 0x11d))) &&
                    ((*(u32 *)(state + 0x118) & 2) == 0)) {
                    limit = current;
                    if (candidate != 0xffffffff) {
                        limit = candidate;
                        if (*(u32 *)(state + 0x110) <
                            *(u32 *)(synthVoice + candidate * 0x404 + 0x110)) {
                            limit = current;
                        }
                    }
                }
                candidate = limit;
                voiceLink = *(u8 *)(voicePriorityLinks + 1 + current * 4);
            }
            selectedVoice = *(u16 *)(voicePrioritySortLinks + selectedVoice * 4);
        }
        selectedVoice = candidate;
        if (candidate == 0xffffffff) {
            return 0xffffffff;
        }
    }

    if (priority < *(u8 *)(synthVoice + selectedVoice * 0x404 + 0x10c)) {
        return 0xffffffff;
    }

found_voice:
    if (selectedVoice == 0xffffffff) {
        return 0xffffffff;
    }
    state = selectedVoice * 4;
    if (voiceFreeListSlots[selectedVoice].active == 1) {
        if (voiceFreeListSlots[selectedVoice].prev == 0xff) {
            voiceListRoot = voiceFreeListSlots[selectedVoice].next;
        } else {
            voiceFreeListSlots[voiceFreeListSlots[selectedVoice].prev].next =
                voiceFreeListSlots[selectedVoice].next;
        }
        if (voiceFreeListSlots[selectedVoice].next != 0xff) {
            voiceFreeListSlots[voiceFreeListSlots[selectedVoice].next].prev =
                voiceFreeListSlots[selectedVoice].prev;
        }
        if (selectedVoice == voiceListInsert) {
            voiceListInsert = voiceFreeListSlots[selectedVoice].prev;
        }
        voiceFreeListSlots[selectedVoice].active = 0;
    } else if (*(s8 *)(synthVoice + selectedVoice * 0x404 + 0x11d) == 0) {
        voiceMusicRunning--;
    } else {
        voiceFxRunning--;
    }

    if (streamKind == 0) {
        voiceMusicRunning++;
        return selectedVoice;
    }
    voiceFxRunning++;
    return selectedVoice;
}

/*
 * Release a voice slot: clear voice flags, unlink from id table,
 * decrement counter, and mark id slot as free (-1).
 *
 * EN v1.1 Address: 0x80279B98, size 228b
 */
void voiceFree(int state)
{
    fn_80278A98(state, 2);
    voiceRemovePriority(state);
    *(u32 *)(state + 0x34) = 0;
    *(u8 *)(state + 0x10c) = 0;
    {
        u32 voice = *(u32 *)(state + 0xf4);
        u8 v = (u8)voice;
        VoiceIdSlot *slot = &voiceFreeListSlots[v];
        if (slot->active == 0) {
            slot->active = 1;
            if (voiceListRoot != 0xff) {
                slot->next = 0xff;
                slot->prev = voiceListInsert;
                voiceFreeListSlots[voiceListInsert].next = v;
            } else {
                slot->next = 0xff;
                slot->prev = 0xff;
                voiceListRoot = v;
            }
            voiceListInsert = v;
            if (*(u8 *)(state + 0x11d) != 0) {
                voiceFxRunning--;
            } else {
                voiceMusicRunning--;
            }
        }
    }
    *(int *)(state + 0xf4) = -1;
}
