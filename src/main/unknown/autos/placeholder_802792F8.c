#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802792F8.h"

extern u8 lbl_803CA2D0[];
extern u32 lbl_803DE2F0;
extern void *lbl_803DE2F4;

/*
 * fn_80279038 - large voice-queue init (~144 instructions). Stubbed
 * pending full decode.
 */
#pragma dont_inline on
void fn_80279038(void)
{
}
#pragma dont_inline reset

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
#pragma dont_inline on
u32 vidMakeNew(void)
{
    return 0;
}
#pragma dont_inline reset

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
    (void)state;
}
#pragma dont_inline reset
