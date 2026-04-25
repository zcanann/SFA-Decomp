#include "dolphin/types.h"

extern u32 lbl_803DC9C8;
extern char* lbl_803DC9CC;
extern u32 lbl_8033A540[];
extern char lbl_802C7400[];

asm void MWTRACE(register int level, register char* format) {
    nofralloc
    lwz r4, lbl_803DC9C8(r0)
    addi r0, r4, 1
    stw r0, lbl_803DC9C8(r0)
    mulli r5, r4, 0x14
    lis r4, lbl_8033A540@ha
    addi r0, r4, lbl_8033A540@l
    add r6, r0, r5
    cmpwi r3, 0xFF
    bne lbl_not_ff
    li r0, 0
    b lbl_store_current
lbl_not_ff:
    slwi r5, r3, 5
    lis r4, lbl_802C7400@ha
    addi r0, r4, lbl_802C7400@l
    add r0, r0, r5
lbl_store_current:
    stw r0, lbl_803DC9CC(r0)
    li r0, 8
    stw r0, 0(r6)
    stw r3, 4(r6)
    blr
}
