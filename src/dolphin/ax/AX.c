/*
 * Target bytes at this split are not Dolphin SDK AX init/quit. AXInit and
 * AXQuit here look like thread control helpers: a sbss flag (lbl_803DE2D8)
 * is checked, and a bss thread object (lbl_803A6100) is either Cancelled
 * or Resumed. Asm-only to preserve the exact byte image.
 */

extern void OSCancelThread(void* thread);
extern void OSResumeThread(void* thread);

extern int lbl_803DE2D8;
extern char lbl_803A6100[];

asm void AXInit(void) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    lwz r0, lbl_803DE2D8(r0)
    cmpwi r0, 0x0
    beq _ai_0
    lis r3, lbl_803A6100@ha
    addi r3, r3, lbl_803A6100@l
    bl OSCancelThread
    li r0, 0x0
    stw r0, lbl_803DE2D8(r0)
_ai_0:
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void AXQuit(void) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    lwz r0, lbl_803DE2D8(r0)
    cmpwi r0, 0x0
    beq _aq_0
    lis r3, lbl_803A6100@ha
    addi r3, r3, lbl_803A6100@l
    bl OSResumeThread
_aq_0:
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}
