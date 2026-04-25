#include "dolphin/os.h"

static int __initialized = 0;

asm void __sys_free(register void* p) {
    nofralloc
    stwu r1, -0x20(r1)
    mflr r0
    stw r0, 0x24(r1)
    stw r31, 0x1c(r1)
    stw r30, 0x18(r1)
    stw r29, 0x14(r1)
    mr r29, r3
    lwz r0, __initialized(r0)
    cmpwi r0, 0
    bne _sf_skip
    bl OSGetArenaLo
    mr r31, r3
    bl OSGetArenaHi
    mr r30, r3
    mr r3, r31
    li r5, 1
    mr r4, r30
    bl OSInitAlloc
    mr r31, r3
    bl OSSetArenaLo
    addi r0, r31, 0x1f
    clrrwi r30, r30, 5
    clrrwi r3, r0, 5
    mr r4, r30
    bl OSCreateHeap
    bl OSSetCurrentHeap
    mr r3, r30
    bl OSSetArenaLo
    li r0, 1
    stw r0, __initialized(r0)
_sf_skip:
    mr r4, r29
    li r3, 0
    bl OSFreeToHeap
    lwz r0, 0x24(r1)
    lwz r31, 0x1c(r1)
    lwz r30, 0x18(r1)
    lwz r29, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x20
    blr
}
