#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/MWCriticalSection_gc.h"

/*
 * The target bytes at this split are not the TRK critical-section stubs
 * the symbol names suggest: MWEnterCriticalSection calls a float helper
 * (fn_8003B9EC), MWExitCriticalSection peeks into an object at r3+0xB8
 * and clears a field. Both look like game-side shims that happen to
 * live here. Asm-only to preserve the exact byte image.
 */

void fn_8003B9EC(float x);
__declspec(section ".sdata2") extern const float lbl_803E54E0;

asm void MWInitializeCriticalSection(u32* section) {
    nofralloc
    blr
}

asm void MWEnterCriticalSection(u32* section) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    extsb r0, r8
    cmpwi r0, 0x0
    beq _mwe_0
    lfs f1, lbl_803E54E0(r0)
    bl fn_8003B9EC
_mwe_0:
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void MWExitCriticalSection(u32* section) {
    nofralloc
    lwz r4, 0xb8(r3)
    lwz r3, 0x0(r4)
    lhz r0, 0xb0(r3)
    rlwinm r0, r0, 0, 25, 25
    cmpwi r0, 0x0
    beqlr
    li r0, 0x0
    stw r0, 0x0(r4)
    blr
}
