/*
 * EXIUart: target only exposes InitializeUART + WriteUARTN. Asm-only.
 */
#include <dolphin/os.h>
#include <dolphin/exi.h>

extern u32 lbl_803DE0A4;
extern u32 lbl_803DE0A0;
extern s32 lbl_803DE098;
extern u32 lbl_803DE09C;

asm int InitializeUART(u32 baudrate) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x8(r1)
    lwz r3, lbl_803DE0A4(r0)
    addis r0, r3, 0x5a01
    cmplwi r0, 0x5a
    bne _iu_not_eq
    li r3, 0x0
    b _iu_end
_iu_not_eq:
    bl OSGetConsoleType
    rlwinm. r0, r3, 0, 3, 3
    bne _iu_set
    li r0, 0x0
    stw r0, lbl_803DE0A0(r0)
    li r3, 0x2
    b _iu_end
_iu_set:
    lis r3, 0xa5ff
    addi r0, r3, 0x5a
    li r3, 0x0
    stw r0, lbl_803DE0A0(r0)
    li r0, 0x1
    stw r3, lbl_803DE098(r0)
    li r3, 0x0
    stw r0, lbl_803DE09C(r0)
_iu_end:
    lwz r0, 0xc(r1)
    addi r1, r1, 0x8
    mtlr r0
    blr
}

asm int WriteUARTN(void* buf, u32 n) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    stmw r26, 0x18(r1)
    addi r30, r3, 0x0
    addi r31, r4, 0x0
    lwz r5, lbl_803DE0A0(r0)
    addis r0, r5, 0x5a01
    cmplwi r0, 0x5a
    beq _wu_eq
    li r3, 0x2
    b _wu_end
_wu_eq:
    lwz r3, lbl_803DE098(r0)
    li r5, 0x0
    lwz r4, lbl_803DE09C(r0)
    bl EXILock
    cmpwi r3, 0x0
    bne _wu_locked
    li r3, 0x0
    b _wu_end
_wu_locked:
    addi r4, r30, 0x0
    li r3, 0xd
    b _wu_check_lf
_wu_lf_loop:
    lbz r0, 0x0(r4)
    cmpwi r0, 0xa
    bne _wu_skip
    stb r3, 0x0(r4)
_wu_skip:
    addi r4, r4, 0x1
_wu_check_lf:
    subf r0, r30, r4
    cmplw r0, r31
    blt _wu_lf_loop
    lis r0, 0xa001
    stw r0, 0x14(r1)
    li r26, 0x0
    lis r29, 0x2001
    b _wu_outer_check
_wu_outer:
    lwz r3, lbl_803DE098(r0)
    li r5, 0x3
    lwz r4, lbl_803DE09C(r0)
    bl EXISelect
    cmpwi r3, 0x0
    bne _wu_sel_ok1
    li r0, -0x1
    b _wu_after_sel1
_wu_sel_ok1:
    stw r29, 0x10(r1)
    addi r4, r1, 0x10
    lwz r3, lbl_803DE098(r0)
    li r5, 0x4
    li r6, 0x1
    li r7, 0x0
    bl EXIImm
    lwz r3, lbl_803DE098(r0)
    bl EXISync
    lwz r3, lbl_803DE098(r0)
    addi r4, r1, 0x10
    li r5, 0x1
    li r6, 0x0
    li r7, 0x0
    bl EXIImm
    lwz r3, lbl_803DE098(r0)
    bl EXISync
    lwz r3, lbl_803DE098(r0)
    bl EXIDeselect
    lwz r0, 0x10(r1)
    srwi r0, r0, 24
    subfic r0, r0, 0x10
_wu_after_sel1:
    cmpwi r0, 0x0
    mr r27, r0
    bge _wu_pos
    li r26, 0x3
    b _wu_unlock
_wu_pos:
    cmpwi r0, 0xc
    bge _wu_select2
    cmplw r0, r31
    blt _wu_outer_check
_wu_select2:
    lwz r3, lbl_803DE098(r0)
    li r5, 0x3
    lwz r4, lbl_803DE09C(r0)
    bl EXISelect
    cmpwi r3, 0x0
    bne _wu_sel_ok2
    li r26, 0x3
    b _wu_unlock
_wu_sel_ok2:
    lwz r3, lbl_803DE098(r0)
    addi r4, r1, 0x14
    li r5, 0x4
    li r6, 0x1
    li r7, 0x0
    bl EXIImm
    lwz r3, lbl_803DE098(r0)
    bl EXISync
    b _wu_inner_check
_wu_inner:
    cmpwi r27, 0x4
    bge _wu_size_4
    cmplw r27, r31
    blt _wu_done_inner
_wu_size_4:
    cmplwi r31, 0x4
    bge _wu_clamp_4
    mr r28, r31
    b _wu_send
_wu_clamp_4:
    li r28, 0x4
_wu_send:
    lwz r3, lbl_803DE098(r0)
    mr r5, r28
    addi r4, r30, 0x0
    li r6, 0x1
    li r7, 0x0
    bl EXIImm
    lwz r3, lbl_803DE098(r0)
    add r30, r30, r28
    subf r31, r28, r31
    subf r27, r28, r27
    bl EXISync
_wu_inner_check:
    cmpwi r27, 0x0
    beq _wu_done_inner
    cmplwi r31, 0x0
    bne _wu_inner
_wu_done_inner:
    lwz r3, lbl_803DE098(r0)
    bl EXIDeselect
_wu_outer_check:
    cmplwi r31, 0x0
    bne _wu_outer
_wu_unlock:
    lwz r3, lbl_803DE098(r0)
    bl EXIUnlock
    mr r3, r26
_wu_end:
    lmw r26, 0x18(r1)
    lwz r0, 0x34(r1)
    addi r1, r1, 0x30
    mtlr r0
    blr
}
