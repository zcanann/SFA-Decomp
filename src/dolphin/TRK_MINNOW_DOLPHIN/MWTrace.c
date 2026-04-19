#include "dolphin/types.h"

extern u32 lbl_803DD648;
extern char* lbl_803DD64C;
extern u32 lbl_8033B1A0[];
extern char lbl_802C7B80[];

asm void MWTRACE(register int level, register char* format) {
    nofralloc
    lwz r4, lbl_803DD648(r13)
    addi r0, r4, 1
    stw r0, lbl_803DD648(r13)
    mulli r5, r4, 0x14
    lis r4, lbl_8033B1A0@ha
    addi r0, r4, lbl_8033B1A0@l
    add r6, r0, r5
    cmpwi r3, 0xFF
    bne lbl_not_ff
    li r0, 0
    b lbl_store_current
lbl_not_ff:
    slwi r5, r3, 5
    lis r4, lbl_802C7B80@ha
    addi r0, r4, lbl_802C7B80@l
    add r0, r0, r5
lbl_store_current:
    stw r0, lbl_803DD64C(r13)
    li r0, 8
    stw r0, 0(r6)
    stw r3, 4(r6)
    blr
}
