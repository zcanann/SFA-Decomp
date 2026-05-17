#include "ghidra_import.h"

typedef struct Snd3DEmitterLite {
    u8 pad00[0x40];
    u32 groupKey;
} Snd3DEmitterLite;

typedef struct S3DActiveNode {
    struct S3DActiveNode *next;
    f32 distance;
    f32 arg1;
    f32 arg2;
    f32 arg3;
    f32 arg4;
    Snd3DEmitterLite *emitter;
} S3DActiveNode;

typedef struct S3DSortedNode {
    struct S3DSortedNode *next;
    f32 distance;
    Snd3DEmitterLite *emitter;
} S3DSortedNode;

typedef struct S3DMixGroup {
    u32 key;
    S3DActiveNode *activeHead;
    S3DSortedNode *sortedHead;
    u16 sortedCount;
    u8 pad0e[2];
} S3DMixGroup;

extern u8 lbl_803CC8C0[];
extern u8 lbl_803DE36B;
extern u8 lbl_803DE36C;
extern u8 lbl_803DE36D;

#define S3D_MAX_GROUPS 0x40
#define S3D_MAX_ACTIVE_NODES 0x40
#define S3D_MIX_GROUPS ((S3DMixGroup *)(lbl_803CC8C0 + 0x50))
#define S3D_ACTIVE_NODES ((S3DActiveNode *)(lbl_803CC8C0 + 0x450))
#define S3D_SORTED_NODES ((S3DSortedNode *)(lbl_803CC8C0 + 0xb50))

/*
 * fn_802800C0 - large reverb/effect chain init (~840 instructions).
 * Stubbed.
 */
#pragma dont_inline on
void fn_802800C0(void) {}
#pragma dont_inline reset

/*
 * fn_802805A4 - 540-instr per-voice update. Stubbed.
 */
#pragma dont_inline on
void fn_802805A4(void) {}
#pragma dont_inline reset

/*
 * fn_802807C4 - distance-sorted voice node insert.
 */
#pragma dont_inline on
void fn_802807C4(Snd3DEmitterLite *emitter, f32 distance)
{
    S3DMixGroup *groups;
    S3DMixGroup *group;
    S3DSortedNode *node;
    S3DSortedNode *prev;
    S3DSortedNode *newNode;
    u32 groupIndex;
    u32 remaining;

    groups = S3D_MIX_GROUPS;
    group = groups;
    remaining = lbl_803DE36B;
    groupIndex = 0;
    while ((remaining != 0) && (emitter->groupKey != group->key)) {
        group++;
        groupIndex++;
        remaining--;
    }

    if (groupIndex == lbl_803DE36B) {
        group->activeHead = (S3DActiveNode *)0x0;
        group->sortedHead = (S3DSortedNode *)0x0;
        group->sortedCount = 0;
        group->key = emitter->groupKey;
        lbl_803DE36B++;
    }

    group->sortedCount++;
    node = group->sortedHead;
    prev = (S3DSortedNode *)0x0;
    while ((node != (S3DSortedNode *)0x0) && (node->distance <= distance)) {
        prev = node;
        node = node->next;
    }

    newNode = &S3D_SORTED_NODES[lbl_803DE36D];
    if (prev == (S3DSortedNode *)0x0) {
        group->sortedHead = newNode;
    } else {
        prev->next = newNode;
    }
    newNode->next = node;
    newNode->emitter = emitter;
    newNode->distance = distance;
    lbl_803DE36D++;
}
#pragma dont_inline reset

/*
 * fn_802808D8 - active spatial voice node insert.
 */
#pragma dont_inline on
int fn_802808D8(Snd3DEmitterLite *emitter, f32 distance, f32 arg1, f32 arg2, f32 arg3, f32 arg4)
{
    S3DMixGroup *groups;
    S3DMixGroup *group;
    S3DActiveNode *scan;
    S3DActiveNode *next;
    S3DActiveNode *newNode;
    u32 groupIndex;
    u32 groupCount;
    u32 activeIndex;

    groups = S3D_MIX_GROUPS;
    group = groups;
    groupCount = lbl_803DE36B;
    groupIndex = 0;
    while ((groupCount != 0) && (emitter->groupKey != group->key)) {
        group++;
        groupIndex++;
        groupCount--;
    }

    if (groupIndex == lbl_803DE36B) {
        if (groupCount == S3D_MAX_GROUPS) {
            return 0;
        }
        group->activeHead = (S3DActiveNode *)0x0;
        group->sortedHead = (S3DSortedNode *)0x0;
        group->sortedCount = 0;
        group->key = emitter->groupKey;
        lbl_803DE36B++;
    }

    activeIndex = lbl_803DE36C;
    if (activeIndex == S3D_MAX_ACTIVE_NODES) {
        return 0;
    }

    scan = group->activeHead;
    if (scan == (S3DActiveNode *)0x0) {
        newNode = &S3D_ACTIVE_NODES[activeIndex];
        newNode->next = (S3DActiveNode *)0x0;
        group->activeHead = newNode;
    } else {
        do {
            next = scan->next;
            if (next == (S3DActiveNode *)0x0) {
                break;
            }
            if (next->distance < distance) {
                break;
            }
            scan = next;
        } while (true);
        newNode = &S3D_ACTIVE_NODES[activeIndex];
        newNode->next = next;
        scan->next = newNode;
    }

    newNode->emitter = emitter;
    newNode->arg4 = arg4;
    newNode->arg1 = arg1;
    newNode->arg2 = arg2;
    newNode->arg3 = arg3;
    lbl_803DE36C++;
    newNode->distance = distance;
    return 1;
}
#pragma dont_inline reset

/*
 * audioFn_80280a08 - 552-instr voice list walker with FP math. Stubbed.
 */
#pragma dont_inline on
void audioFn_80280a08(void) {}
#pragma dont_inline reset
