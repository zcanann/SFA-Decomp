/*
 * Target bytes at 0x80294640..0x802947CC absorbed into this TU.
 * Contents: PPCMtdec/PPCHalt weak helpers, an EXIDeviceEnable-ish helper,
 * an InitializeUART/WriteUARTN write_byte wrapper, fabs wrapper, and a
 * float-to-int magic-constant helper.
 * Asm-only to preserve the exact byte image.
 */

#include "dolphin.h"

extern int InitializeUART(u32);
extern int WriteUARTN(void* buf, u32 n);

extern u32 lbl_803326E8;
extern u32 lbl_803DE418;
extern const double lbl_803E7E30;

asm void PPCMtdec(register u32 newDec) {
#ifdef __MWERKS__
    nofralloc
    mtdec r3
    blr
#endif
}

asm void PPCHalt(void) {
#ifdef __MWERKS__
    nofralloc
    sync
_halt_loop:
    nop
    li r3, 0
    nop
    b _halt_loop
#endif
}

asm u8 fn_8029465C(int x) {
    nofralloc
    cmpwi r3, -0x1
    bne _f465c_0
    li r3, -0x1
    blr
_f465c_0:
    lis r4, lbl_803326E8@ha
    clrlwi r3, r3, 24
    addi r0, r4, lbl_803326E8@l
    add r3, r0, r3
    lbz r3, 0(r3)
    blr
}

asm int fn_80294684(int handle, void* buf, u32* count) {
    nofralloc
    mflr r0
    li r3, 0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    stw r31, 0x24(r1)
    addi r31, r5, 0
    stw r30, 0x20(r1)
    addi r30, r4, 0
    lwz r0, lbl_803DE418(r0)
    cmpwi r0, 0
    bne _f4684_init_done
    lis r3, 0x1
    subi r3, r3, 0x1f00
    bl InitializeUART
    cmpwi r3, 0
    bne _f4684_init_done
    li r0, 1
    stw r0, lbl_803DE418(r0)
_f4684_init_done:
    cmpwi r3, 0
    beq _f4684_write
    li r3, 1
    b _f4684_end
_f4684_write:
    mr r3, r30
    lwz r4, 0(r31)
    bl WriteUARTN
    cmpwi r3, 0
    beq _f4684_ok
    li r0, 0
    stw r0, 0(r31)
    li r3, 1
    b _f4684_end
_f4684_ok:
    li r3, 0
_f4684_end:
    lwz r0, 0x2c(r1)
    lwz r31, 0x24(r1)
    lwz r30, 0x20(r1)
    mtlr r0
    addi r1, r1, 0x28
    blr
}

asm float fn_8029471C(float x) {
    nofralloc
    fabs f1, f1
    blr
}

asm float fn_80294724(float x, int n) {
    nofralloc
    stwu r1, -0x28(r1)
    lis r4, 0x4330
    stfs f1, 0x8(r1)
    lfd f2, lbl_803E7E30(r0)
    lfs f1, 0x8(r1)
    fctiwz f0, f1
    stfd f0, 0x18(r1)
    lwz r0, 0x1c(r1)
    stfd f0, 0x20(r1)
    xoris r0, r0, 0x8000
    stw r0, 0x14(r1)
    lwz r6, 0x24(r1)
    stw r4, 0x10(r1)
    lfd f0, 0x10(r1)
    fsubs f0, f0, f2
    fsubs f0, f0, f1
    stfs f0, 0xc(r1)
    lwz r0, 0xc(r1)
    cmpwi r0, 0
    beq _f4724_skip
    lwz r5, 0x8(r1)
    lis r0, 0x4b80
    rlwinm r3, r5, 0, 1, 8
    cmpw r3, r0
    blt _f4724_lt
    b _f4724_skip
_f4724_lt:
    clrrwi. r0, r5, 31
    beq _f4724_pos
    subi r6, r6, 0x1
    xoris r0, r6, 0x8000
    stw r0, 0x14(r1)
    stw r4, 0x10(r1)
    lfd f0, 0x10(r1)
    fsubs f1, f0, f2
    b _f4724_skip
_f4724_pos:
    xoris r0, r6, 0x8000
    stw r0, 0x14(r1)
    stw r4, 0x10(r1)
    lfd f0, 0x10(r1)
    fsubs f1, f0, f2
_f4724_skip:
    addi r1, r1, 0x28
    blr
}
