#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802792F8.h"

extern u8 vidListNodes[];

#define voicePriorityLinks (vidListNodes + 0x8c0)
#define voicePriorityGroupHeads (vidListNodes + 0x9c0)
#define voicePrioritySortLinks (vidListNodes + 0xac0)
typedef struct SynthVoiceRec {
    u8 pad[0xec];
    u32 prevId;
    u32 nextId;
    u32 vid;
    u32 vidList;
    u32 vidMasterList;
    u8 pad2[0x404 - 0x100];
} SynthVoiceRec;

extern u32 vidCurrentId;
extern void *vidRoot;
extern void *vidFree;
extern u16 voicePrioSortRootListRoot;
extern SynthVoiceRec *synthVoice;
extern void voiceUnregister(int state);

typedef struct VoicePriorityLink {
    u8 prev;
    u8 next;
    u16 active;
} VoicePriorityLink;

typedef struct VoicePrioritySortLink {
    u16 next;
    u16 prev;
} VoicePrioritySortLink;

/*
 * Remove a voice from the vid id list, recycling any allocated id-list nodes.
 */
#define VID_UNLINK(off) \
    if ((u32 *)(*(u32 **)(state + (off)))[1] != 0) { \
        *(u32 *)(*(u32 **)(state + (off)))[1] = (*(u32 **)(state + (off)))[0]; \
    } else { \
        vidRoot = (void *)(*(u32 **)(state + (off)))[0]; \
    } \
    if ((u32 *)(*(u32 **)(state + (off)))[0] != 0) { \
        *(u32 *)((*(u32 **)(state + (off)))[0] + 4) = (*(u32 **)(state + (off)))[1]; \
    } \
    (*(u32 **)(state + (off)))[0] = (u32)vidFree; \
    if (vidFree != 0) { \
        *(u32 *)((u8 *)vidFree + 4) = *(u32 *)(state + (off)); \
    } \
    (*(u32 **)(state + (off)))[1] = 0; \
    vidFree = *(void **)(state + (off))

void vidRemoveVoice(int state)
{
    if (*(u32 *)(state + 0xf4) != 0xffffffff) {
        voiceUnregister(state);
        if (*(u32 *)(state + 0xf0) != 0xffffffff) {
            synthVoice[*(u32 *)(state + 0xf0) & 0xff].prevId =
                *(u32 *)(state + 0xec);
            if (*(u32 *)(state + 0xec) != 0xffffffff) {
                synthVoice[*(u32 *)(state + 0xec) & 0xff].nextId =
                    *(u32 *)(state + 0xf0);
            }
            VID_UNLINK(0xf8);
            *(u32 *)(state + 0xf8) = 0;
        } else if (*(u32 *)(state + 0xec) != 0xffffffff) {
            *(u32 *)(*(u32 *)(state + 0xf8) + 0xc) = *(u32 *)(state + 0xec);
            synthVoice[*(u32 *)(state + 0xec) & 0xff].nextId = 0xffffffff;
            synthVoice[*(u32 *)(state + 0xec) & 0xff].vidMasterList =
                *(u32 *)(state + 0xfc);
            if (*(u32 *)(state + 0xf8) != *(u32 *)(state + 0xfc)) {
                VID_UNLINK(0xf8);
                *(u32 *)(state + 0xf8) = 0;
            }
            *(u32 *)(state + 0xf8) = 0;
            *(u32 *)(state + 0xfc) = 0;
        } else if (*(u32 *)(state + 0xf8) != *(u32 *)(state + 0xfc)) {
            VID_UNLINK(0xf8);
            *(u32 *)(state + 0xf8) = 0;
            VID_UNLINK(0xfc);
            *(u32 *)(state + 0xfc) = 0;
        } else {
            VID_UNLINK(0xf8);
            *(u32 *)(state + 0xf8) = 0;
            *(u32 *)(state + 0xfc) = 0;
        }
    }
}

/*
 * Snapshot the current entry's `next` pointer (state->[0xf8]) into the
 * cached field (state->[0xfc]) and return that next entry's id field.
 *
 * EN v1.0 Address: 0x802791E8
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027938C
 * EN v1.1 Size: 20b
 */
int vidMakeRoot(int state)
{
    *(int *)(state + 0xfc) = *(int *)(state + 0xf8);
    return *(int *)(*(int *)(state + 0xf8) + 0x8);
}

/*
 * Allocate the next unique id from the global counter, walking the
 * sorted-by-id list to skip any already-in-use ids. Used to assign
 * fresh handles to dynamically-allocated voices.
 *
 * EN v1.0 Address: 0x802791EC
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802793A0
 * EN v1.1 Size: 332b
 */
u32 vidMakeNew(int state, int returnNewId)
{
    u32 nextId;
    int **cursor;
    int **node;
    int **prev;
    int **freeNode;

    do {
        nextId = vidCurrentId;
        vidCurrentId = nextId + 1;
    } while (nextId == 0xffffffffU);

    cursor = vidRoot;
    prev = 0;
    while ((node = cursor) != 0) {
        if ((u32)node[2] > nextId) {
            break;
        }
        if ((u32)node[2] == nextId) {
            do {
                nextId = vidCurrentId;
                vidCurrentId = nextId + 1;
            } while (nextId == 0xffffffffU);
        }
        prev = node;
        cursor = (int **)*node;
    }

    freeNode = (int **)vidFree;
    if (freeNode == 0) {
        return 0xffffffffU;
    }
    if ((vidFree = *(void **)vidFree) != 0) {
        *(u32 *)((u8 *)vidFree + 4) = 0;
    }
    if (prev == 0) {
        vidRoot = freeNode;
    } else {
        *prev = (int *)freeNode;
    }
    freeNode[1] = (int *)prev;
    *freeNode = (int *)node;
    if (node != 0) {
        node[1] = (int *)freeNode;
    }
    freeNode[2] = (int *)nextId;
    freeNode[3] = *(int **)(state + 0xf4);
    *(u32 *)(state + 0xfc) = ((u32)returnNewId != 0) ? (u32)freeNode : 0;
    *(u32 *)(state + 0xf8) = (u32)freeNode;
    if ((u32)returnNewId != 0) {
        return nextId;
    }
    return *(u32 *)(state + 0xf4);
}

/*
 * Look up a voice handle's slot via the sorted linked list.
 * Returns -1 for the sentinel id 0xFFFFFFFF or if not found.
 *
 * EN v1.0 Address: 0x802791F0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027949C
 * EN v1.1 Size: 80b
 */
int vidGetInternalId(u32 id)
{
    int *node;

    if (id != 0xffffffffU) {
        node = vidRoot;
        while (node != NULL) {
            if (*(u32 *)(node + 2) == id) goto found;
            if (*(u32 *)(node + 2) > id) break;
            node = *(int **)node;
        }
        node = NULL;
found:
        if (node != NULL) {
            return *(int *)(node + 3);
        }
    }
    return -1;
}

/*
 * voiceRemovePriority - voice priority-queue removal (sister to placeholder_
 * 80279608's insert). Removes the active voice from its group's
 * linked list and from the sorted priority list.
 *
 * EN v1.0 Address: 0x802791F4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802794EC
 * EN v1.1 Size: 224b
 */
typedef struct VoicePrioVoiceRec {
    u8 prev;
    u8 next;
    u16 user;
} VoicePrioVoiceRec;

typedef struct VoicePrioRootRec {
    u16 next;
    u16 prev;
} VoicePrioRootRec;

typedef struct VoicePrioBlockRec {
    u8 vidNodes[0x8C0];
    VoicePrioVoiceRec prioVoices[64];   /* 0x8C0 */
    u8 prioVoicesRoot[256];             /* 0x9C0 */
    VoicePrioRootRec prioRootList[256]; /* 0xAC0 */
} VoicePrioBlockRec;

void voiceRemovePriority(int state)
{
    VoicePrioBlockRec *vb;
    VoicePrioVoiceRec *vps;
    VoicePrioRootRec *pr;

    vb = (VoicePrioBlockRec *)vidListNodes;
    vps = &vb->prioVoices[*(u32 *)(state + 0xf4) & 0xff];
    if (vps->user != 1) {
        return;
    }
    if (vps->prev != 0xff) {
        vb->prioVoices[vps->prev].next = vps->next;
    } else {
        vb->prioVoicesRoot[*(u8 *)(state + 0x10c)] = vps->next;
    }
    if (vps->next != 0xff) {
        vb->prioVoices[vps->next].prev = vps->prev;
    } else if (vps->prev == 0xff) {
        pr = &vb->prioRootList[*(u8 *)(state + 0x10c)];
        if (pr->prev != 0xffff) {
            vb->prioRootList[pr->prev].next = pr->next;
        } else {
            voicePrioSortRootListRoot = pr->next;
        }
        if (pr->next != 0xffff) {
            vb->prioRootList[pr->next].prev = pr->prev;
        }
    }
    vps->user = 0;
}
