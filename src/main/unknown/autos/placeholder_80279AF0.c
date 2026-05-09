#include "ghidra_import.h"

extern void fn_80278A98(int state, int x);
extern void voiceRemovePriority(int state);

typedef struct VoiceIdSlot {
    u8 prev;
    u8 next;
    u16 active;
} VoiceIdSlot;

extern VoiceIdSlot lbl_803CB190[];
extern u8 *lbl_803DE268;
extern u8 lbl_803BD150[];
extern u8 lbl_803CA2D0[];
extern u8 lbl_803DE270;
extern u16 lbl_803DE2FC;
extern u8 lbl_803DE2FE;
extern u8 lbl_803DE2FF;
extern u8 lbl_803DE300;
extern u8 lbl_803DE301;

/*
 * Allocate a voice id, preferring a free slot but stealing the lowest-priority
 * compatible active voice when limits are exceeded.
 */
u32 voiceAllocate(u8 priority, u8 maxInstances, s16 key, s8 streamKind)
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

    if (lbl_803DE270 != 0) {
        return 0xffffffff;
    }

    if (streamKind == 0) {
        enforceKind = 0;
        if ((lbl_803BD150[0x211] <= lbl_803DE2FE) &&
            (lbl_803BD150[0x211] < lbl_803BD150[0x210])) {
            enforceKind = 1;
        }
        if (maxInstances < lbl_803BD150[0x211]) {
            goto count_matching_key;
        }
    } else {
        enforceKind = 0;
        if ((lbl_803BD150[0x212] <= lbl_803DE2FF) &&
            (lbl_803BD150[0x212] < lbl_803BD150[0x210])) {
            enforceKind = 1;
        }
        if (maxInstances < lbl_803BD150[0x212]) {
count_matching_key:
            matchingCount = 0;
            selectedVoice = 0xffffffff;
            priorityNode = lbl_803DE2FC;
            while (((priorityNode != 0xffff) && (priorityNode <= priority)) &&
                   (selectedVoice == 0xffffffff)) {
                voiceLink = *(u8 *)(lbl_803CA2D0 + 0x9c0 + priorityNode);
                while ((current = voiceLink) != 0xff) {
                    state = (int)(lbl_803DE268 + current * 0x404);
                    candidate = selectedVoice;
                    if (key == *(s16 *)(state + 0x100)) {
                        matchingCount++;
                        if ((*(s8 *)(state + 0x11c) == 0) &&
                            (!enforceKind || (streamKind == *(s8 *)(state + 0x11d))) &&
                            ((*(u32 *)(state + 0x118) & 2) == 0)) {
                            candidate = current;
                            if (selectedVoice != 0xffffffff) {
                                candidate = selectedVoice;
                                if (*(u32 *)(state + 0x110) <
                                    *(u32 *)(lbl_803DE268 + selectedVoice * 0x404 + 0x110)) {
                                    candidate = current;
                                }
                            }
                        }
                    }
                    selectedVoice = candidate;
                    voiceLink = *(u8 *)(lbl_803CA2D0 + 0x8c1 + current * 4);
                }
                priorityNode = *(u16 *)(lbl_803CA2D0 + 0xac0 + (u32)priorityNode * 4);
            }
            limit = maxInstances;
            if ((int)limit <= matchingCount) {
                goto found_voice;
            }
            while (((current = priorityNode) != 0xffff) && (matchingCount < (int)limit)) {
                voiceLink = *(u8 *)(lbl_803CA2D0 + 0x9c0 + current);
                while ((candidate = voiceLink) != 0xff) {
                    if (key == *(s16 *)(lbl_803DE268 + candidate * 0x404 + 0x100)) {
                        matchingCount++;
                    }
                    voiceLink = *(u8 *)(lbl_803CA2D0 + 0x8c1 + candidate * 4);
                }
                priorityNode = *(u16 *)(lbl_803CA2D0 + 0xac0 + current * 4);
            }
            if ((int)limit <= matchingCount) {
                goto found_voice;
            }
        }
    }

    selectedVoice = lbl_803DE301;
    candidate = 0xffffffff;
    if ((selectedVoice == 0xff) || (enforceKind)) {
        selectedVoice = lbl_803DE2FC;
        if (priority < selectedVoice) {
            return 0xffffffff;
        }
        while (((selectedVoice != 0xffff) && (selectedVoice <= priority)) &&
               (candidate == 0xffffffff)) {
            voiceLink = *(u8 *)(lbl_803CA2D0 + 0x9c0 + selectedVoice);
            while ((current = voiceLink) != 0xff) {
                state = (int)(lbl_803DE268 + current * 0x404);
                limit = candidate;
                if ((*(s8 *)(state + 0x11c) == 0) &&
                    (!enforceKind || (streamKind == *(s8 *)(state + 0x11d))) &&
                    ((*(u32 *)(state + 0x118) & 2) == 0)) {
                    limit = current;
                    if (candidate != 0xffffffff) {
                        limit = candidate;
                        if (*(u32 *)(state + 0x110) <
                            *(u32 *)(lbl_803DE268 + candidate * 0x404 + 0x110)) {
                            limit = current;
                        }
                    }
                }
                candidate = limit;
                voiceLink = *(u8 *)(lbl_803CA2D0 + 0x8c1 + current * 4);
            }
            selectedVoice = *(u16 *)(lbl_803CA2D0 + 0xac0 + selectedVoice * 4);
        }
        selectedVoice = candidate;
        if (candidate == 0xffffffff) {
            return 0xffffffff;
        }
    }

    if (priority < *(u8 *)(lbl_803DE268 + selectedVoice * 0x404 + 0x10c)) {
        return 0xffffffff;
    }

found_voice:
    if (selectedVoice == 0xffffffff) {
        return 0xffffffff;
    }
    state = selectedVoice * 4;
    if (lbl_803CB190[selectedVoice].active == 1) {
        if (lbl_803CB190[selectedVoice].prev == 0xff) {
            lbl_803DE301 = lbl_803CB190[selectedVoice].next;
        } else {
            lbl_803CB190[lbl_803CB190[selectedVoice].prev].next =
                lbl_803CB190[selectedVoice].next;
        }
        if (lbl_803CB190[selectedVoice].next != 0xff) {
            lbl_803CB190[lbl_803CB190[selectedVoice].next].prev =
                lbl_803CB190[selectedVoice].prev;
        }
        if (selectedVoice == lbl_803DE300) {
            lbl_803DE300 = lbl_803CB190[selectedVoice].prev;
        }
        lbl_803CB190[selectedVoice].active = 0;
    } else if (*(s8 *)(lbl_803DE268 + selectedVoice * 0x404 + 0x11d) == 0) {
        lbl_803DE2FE--;
    } else {
        lbl_803DE2FF--;
    }

    if (streamKind == 0) {
        lbl_803DE2FE++;
        return selectedVoice;
    }
    lbl_803DE2FF++;
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
        VoiceIdSlot *slot = &lbl_803CB190[v];
        if (slot->active == 0) {
            slot->active = 1;
            if (lbl_803DE301 != 0xff) {
                slot->next = 0xff;
                slot->prev = lbl_803DE300;
                lbl_803CB190[lbl_803DE300].next = v;
            } else {
                slot->next = 0xff;
                slot->prev = 0xff;
                lbl_803DE301 = v;
            }
            lbl_803DE300 = v;
            if (*(u8 *)(state + 0x11d) != 0) {
                lbl_803DE2FF--;
            } else {
                lbl_803DE2FE--;
            }
        }
    }
    *(int *)(state + 0xf4) = -1;
}
