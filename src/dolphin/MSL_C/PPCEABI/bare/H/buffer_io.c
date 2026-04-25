/*
 * MSL buffer_io: __flush_buffer + __prep_buffer (target order is reverse of
 * standard MSL source). Asm-only to lock byte image.
 */
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"

asm int __flush_buffer(FILE* file, size_t* bytes_flushed) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    mr r31, r3
    stw r30, 0x8(r1)
    mr r30, r4
    lwz r3, 0x1c(r3)
    lwz r0, 0x24(r31)
    subf. r0, r3, r0
    beq _fb_end_prep
    stw r0, 0x28(r31)
    addi r5, r31, 0x28
    lwz r12, 0x40(r31)
    lwz r3, 0x0(r31)
    lwz r4, 0x1c(r31)
    lwz r6, 0x48(r31)
    mtctr r12
    bctrl
    cmplwi r30, 0x0
    beq _fb_skip_store
    lwz r0, 0x28(r31)
    stw r0, 0x0(r30)
_fb_skip_store:
    cmpwi r3, 0x0
    beq _fb_pos
    b _fb_end
_fb_pos:
    lwz r3, 0x18(r31)
    lwz r0, 0x28(r31)
    add r0, r3, r0
    stw r0, 0x18(r31)
_fb_end_prep:
    lwz r0, 0x1c(r31)
    li r3, 0x0
    stw r0, 0x24(r31)
    lwz r0, 0x20(r31)
    stw r0, 0x28(r31)
    lwz r5, 0x18(r31)
    lwz r4, 0x2c(r31)
    lwz r0, 0x28(r31)
    and r4, r5, r4
    subf r0, r4, r0
    stw r0, 0x28(r31)
    lwz r0, 0x18(r31)
    stw r0, 0x34(r31)
_fb_end:
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    lwz r30, 0x8(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void __prep_buffer(FILE* file) {
    nofralloc
    lwz r0, 0x1c(r3)
    stw r0, 0x24(r3)
    lwz r0, 0x20(r3)
    stw r0, 0x28(r3)
    lwz r5, 0x18(r3)
    lwz r4, 0x2c(r3)
    lwz r0, 0x28(r3)
    and r4, r5, r4
    subf r0, r4, r0
    stw r0, 0x28(r3)
    lwz r0, 0x18(r3)
    stw r0, 0x34(r3)
    blr
}
