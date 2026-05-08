#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802792F8.h"

extern u8 lbl_803CA2D0[];
extern u32 lbl_803DE2F0;
extern void *lbl_803DE2F4;
extern void *lbl_803DE2F8;
extern u16 lbl_803DE2FC;
extern u8 *lbl_803DE268;
extern void fn_8027A2B4(int state);

/*
 * Remove a voice from the vid id list, recycling any allocated id-list nodes.
 */
void fn_80279038(int state)
{
    u32 *node;
    int next;

    if (*(int *)(state + 0xf4) != -1) {
        fn_8027A2B4(state);
        if (*(u32 *)(state + 0xf0) == 0xffffffff) {
            if (*(int *)(state + 0xec) == -1) {
                node = *(u32 **)(state + 0xf8);
                if (node == *(u32 **)(state + 0xfc)) {
                    if ((u32 *)node[1] == 0) {
                        lbl_803DE2F4 = (void *)node[0];
                    } else {
                        *(u32 *)node[1] = node[0];
                    }
                    next = *(int *)*(u32 **)(state + 0xf8);
                    if (next != 0) {
                        *(u32 *)(next + 4) = (*(u32 **)(state + 0xf8))[1];
                    }
                    **(u32 **)(state + 0xf8) = (u32)lbl_803DE2F8;
                    if (lbl_803DE2F8 != 0) {
                        *(u32 *)((u8 *)lbl_803DE2F8 + 4) = *(u32 *)(state + 0xf8);
                    }
                    *(u32 *)(*(int *)(state + 0xf8) + 4) = 0;
                    lbl_803DE2F8 = *(void **)(state + 0xf8);
                    *(u32 *)(state + 0xf8) = 0;
                    *(u32 *)(state + 0xfc) = 0;
                } else {
                    if ((u32 *)node[1] == 0) {
                        lbl_803DE2F4 = (void *)node[0];
                    } else {
                        *(u32 *)node[1] = node[0];
                    }
                    next = *(int *)*(u32 **)(state + 0xf8);
                    if (next != 0) {
                        *(u32 *)(next + 4) = (*(u32 **)(state + 0xf8))[1];
                    }
                    **(u32 **)(state + 0xf8) = (u32)lbl_803DE2F8;
                    if (lbl_803DE2F8 != 0) {
                        *(u32 *)((u8 *)lbl_803DE2F8 + 4) = *(u32 *)(state + 0xf8);
                    }
                    *(u32 *)(*(int *)(state + 0xf8) + 4) = 0;
                    lbl_803DE2F8 = *(void **)(state + 0xf8);
                    *(u32 *)(state + 0xf8) = 0;
                    node = *(u32 **)(state + 0xfc);
                    if ((u32 *)node[1] == 0) {
                        lbl_803DE2F4 = (void *)node[0];
                    } else {
                        *(u32 *)node[1] = node[0];
                    }
                    next = *(int *)*(u32 **)(state + 0xfc);
                    if (next != 0) {
                        *(u32 *)(next + 4) = (*(u32 **)(state + 0xfc))[1];
                    }
                    **(u32 **)(state + 0xfc) = (u32)lbl_803DE2F8;
                    if (lbl_803DE2F8 != 0) {
                        *(u32 *)((u8 *)lbl_803DE2F8 + 4) = *(u32 *)(state + 0xfc);
                    }
                    *(u32 *)(*(int *)(state + 0xfc) + 4) = 0;
                    lbl_803DE2F8 = *(void **)(state + 0xfc);
                    *(u32 *)(state + 0xfc) = 0;
                }
            } else {
                *(u32 *)(*(int *)(state + 0xf8) + 0xc) = *(u32 *)(state + 0xec);
                *(u32 *)(lbl_803DE268 + (*(u32 *)(state + 0xec) & 0xff) * 0x404 + 0xf0) =
                    0xffffffff;
                *(u32 *)(lbl_803DE268 + (*(u32 *)(state + 0xec) & 0xff) * 0x404 + 0xfc) =
                    *(u32 *)(state + 0xfc);
                node = *(u32 **)(state + 0xf8);
                if (node != *(u32 **)(state + 0xfc)) {
                    if ((u32 *)node[1] == 0) {
                        lbl_803DE2F4 = (void *)node[0];
                    } else {
                        *(u32 *)node[1] = node[0];
                    }
                    next = *(int *)*(u32 **)(state + 0xf8);
                    if (next != 0) {
                        *(u32 *)(next + 4) = (*(u32 **)(state + 0xf8))[1];
                    }
                    **(u32 **)(state + 0xf8) = (u32)lbl_803DE2F8;
                    if (lbl_803DE2F8 != 0) {
                        *(u32 *)((u8 *)lbl_803DE2F8 + 4) = *(u32 *)(state + 0xf8);
                    }
                    *(u32 *)(*(int *)(state + 0xf8) + 4) = 0;
                    lbl_803DE2F8 = *(void **)(state + 0xf8);
                    *(u32 *)(state + 0xf8) = 0;
                }
                *(u32 *)(state + 0xf8) = 0;
                *(u32 *)(state + 0xfc) = 0;
            }
        } else {
            *(u32 *)(lbl_803DE268 + (*(u32 *)(state + 0xf0) & 0xff) * 0x404 + 0xec) =
                *(u32 *)(state + 0xec);
            if (*(u32 *)(state + 0xec) != 0xffffffff) {
                *(u32 *)(lbl_803DE268 + (*(u32 *)(state + 0xec) & 0xff) * 0x404 + 0xf0) =
                    *(u32 *)(state + 0xf0);
            }
            node = *(u32 **)(state + 0xf8);
            if ((u32 *)node[1] == 0) {
                lbl_803DE2F4 = (void *)node[0];
            } else {
                *(u32 *)node[1] = node[0];
            }
            next = *(int *)*(u32 **)(state + 0xf8);
            if (next != 0) {
                *(u32 *)(next + 4) = (*(u32 **)(state + 0xf8))[1];
            }
            **(u32 **)(state + 0xf8) = (u32)lbl_803DE2F8;
            if (lbl_803DE2F8 != 0) {
                *(u32 *)((u8 *)lbl_803DE2F8 + 4) = *(u32 *)(state + 0xf8);
            }
            *(u32 *)(*(int *)(state + 0xf8) + 4) = 0;
            lbl_803DE2F8 = *(void **)(state + 0xf8);
            *(u32 *)(state + 0xf8) = 0;
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
    int wrapped;
    u32 nextId;
    int **freeNode;
    int **cursor;
    int **node;
    int **prev;

    freeNode = lbl_803DE2F8;
    nextId = lbl_803DE2F0;
    do {
        lbl_803DE2F0 = nextId;
        nextId = lbl_803DE2F0 + 1;
    } while (lbl_803DE2F0 == 0xffffffffU);

    nextId = lbl_803DE2F0;
    cursor = lbl_803DE2F4;
    prev = 0;
    lbl_803DE2F0++;
    while ((node = cursor) != 0 && ((u32)node[2] <= nextId)) {
        if ((u32)node[2] == nextId) {
            do {
                wrapped = lbl_803DE2F0 == 0xffffffffU;
                nextId = lbl_803DE2F0;
                lbl_803DE2F0++;
            } while (wrapped);
        }
        prev = node;
        cursor = (int **)*node;
    }

    if (lbl_803DE2F8 != 0) {
        lbl_803DE2F8 = *(void **)lbl_803DE2F8;
        if (lbl_803DE2F8 != 0) {
            *(u32 *)((u8 *)lbl_803DE2F8 + 4) = 0;
        }
        if (prev == 0) {
            lbl_803DE2F4 = freeNode;
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
        cursor = freeNode;
        if (returnNewId == 0) {
            cursor = 0;
        }
        *(int ***)(state + 0xfc) = cursor;
        *(int ***)(state + 0xf8) = freeNode;
        if (returnNewId == 0) {
            return *(u32 *)(state + 0xf4);
        }
        return nextId;
    }
    return 0xffffffffU;
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

    if (id == 0xffffffffU) {
        return -1;
    }
    node = lbl_803DE2F4;
    while (node != NULL) {
        if (*(u32 *)(node + 2) == id) {
            break;
        }
        if (*(u32 *)(node + 2) > id) {
            node = NULL;
            break;
        }
        node = *(int **)node;
    }
    if (node == NULL) {
        return -1;
    }
    return *(int *)(node + 3);
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
#pragma dont_inline on
void voiceRemovePriority(int state)
{
    u32 voiceId;
    int offset;
    u16 *priorityNode;
    u8 *slot;

    voiceId = *(u32 *)(state + 0xf4) & 0xff;
    offset = voiceId * 4;
    slot = lbl_803CA2D0 + 0x8c0 + offset;
    if (*(u16 *)(slot + 2) != 1) {
        return;
    }
    if (*slot == 0xff) {
        *(u8 *)(lbl_803CA2D0 + 0x9c0 + *(u8 *)(state + 0x10c)) = slot[1];
    } else {
        *(u8 *)(lbl_803CA2D0 + 0x8c1 + (u32)*slot * 4) = slot[1];
    }
    if (slot[1] == 0xff) {
        if (*slot == 0xff) {
            offset = (u32)*(u8 *)(state + 0x10c) * 4;
            priorityNode = (u16 *)(lbl_803CA2D0 + 0xac0 + offset);
            if (*(u16 *)(lbl_803CA2D0 + 0xac2 + offset) == 0xffff) {
                lbl_803DE2FC = *priorityNode;
            } else {
                *(u16 *)(lbl_803CA2D0 +
                         0xac0 + (u32)*(u16 *)(lbl_803CA2D0 + 0xac2 + offset) * 4) =
                    *priorityNode;
            }
            if (*priorityNode != 0xffff) {
                *(u16 *)(lbl_803CA2D0 + 0xac2 + (u32)*priorityNode * 4) =
                    *(u16 *)(lbl_803CA2D0 + 0xac2 + offset);
            }
        }
    } else {
        *(u8 *)(lbl_803CA2D0 + 0x8c0 + (u32)slot[1] * 4) = *slot;
    }
    *(u16 *)(lbl_803CA2D0 + 0x8c2 + voiceId * 4) = 0;
}
#pragma dont_inline reset
