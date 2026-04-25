/*
 * MSL ansi_files: only __close_all lives here in v1.0. The __files[4]
 * table lives at 0x80332380 (auto_07 data). Asm to lock byte image.
 */
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"

extern FILE __files[4];
int fclose(FILE*);
asm void fn_8028D574(void* p);

asm void __close_all(void) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    lis r3, __files@ha
    stw r0, 0x14(r1)
    addi r0, r3, __files@l
    stw r31, 0xc(r1)
    mr r31, r0
    b _ca_check
_ca_loop:
    lhz r0, 0x4(r31)
    extrwi. r0, r0, 3, 23
    beq _ca_skip_close
    mr r3, r31
    bl fclose
_ca_skip_close:
    mr r3, r31
    lwz r31, 0x4c(r31)
    lbz r0, 0xc(r3)
    cmplwi r0, 0x0
    beq _ca_path2
    bl fn_8028D574
    b _ca_check
_ca_path2:
    lhz r0, 0x4(r3)
    li r4, 0x3
    rlwimi r0, r4, 6, 23, 25
    cmplwi r31, 0x0
    sth r0, 0x4(r3)
    beq _ca_check
    lbz r0, 0xc(r31)
    cmplwi r0, 0x0
    beq _ca_check
    li r0, 0x0
    stw r0, 0x4c(r3)
_ca_check:
    cmplwi r31, 0x0
    bne _ca_loop
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}
