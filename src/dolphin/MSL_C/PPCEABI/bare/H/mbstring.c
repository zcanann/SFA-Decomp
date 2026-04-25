#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "string.h"

extern const int lbl_803E7938;

asm int unicode_to_UTF8(char* s, wchar_t wchar);

asm size_t wcstombs(char* s, const wchar_t* pwcs, size_t n) {
    nofralloc
    stwu r1, -0x30(r1)
    mflr r0
    stw r0, 0x34(r1)
    stmw r27, 0x1c(r1)
    mr. r27, r3
    mr r28, r5
    li r30, 0x0
    beq _wcs_0
    cmplwi r4, 0x0
    bne _wcs_1
_wcs_0:
    li r3, 0x0
    b _wcs_end
_wcs_1:
    mr r29, r4
    b _wcs_loop_head
_wcs_loop:
    lhz r4, 0x0(r29)
    cmplwi r4, 0x0
    bne _wcs_enc
    li r0, 0x0
    stbx r0, r27, r30
    b _wcs_done
_wcs_enc:
    addi r3, r1, 0x8
    addi r29, r29, 0x2
    bl unicode_to_UTF8
    mr r31, r3
    add r0, r30, r31
    cmplw r0, r28
    bgt _wcs_done
    mr r5, r31
    add r3, r27, r30
    addi r4, r1, 0x8
    bl strncpy
    add r30, r30, r31
_wcs_loop_head:
    cmplw r30, r28
    ble _wcs_loop
_wcs_done:
    mr r3, r30
_wcs_end:
    lmw r27, 0x1c(r1)
    lwz r0, 0x34(r1)
    mtlr r0
    addi r1, r1, 0x30
    blr
}

asm int unicode_to_UTF8(char* s, wchar_t wchar) {
    nofralloc
    stwu r1, -0x10(r1)
    cmplwi r3, 0x0
    lwz r0, lbl_803E7938(r0)
    stw r0, 0x8(r1)
    bne _u8_0
    li r3, 0x0
    b _u8_end
_u8_0:
    clrlwi r0, r4, 16
    cmplwi r0, 0x80
    bge _u8_1
    li r5, 0x1
    b _u8_2
_u8_1:
    cmplwi r0, 0x800
    bge _u8_3
    li r5, 0x2
    b _u8_2
_u8_3:
    li r5, 0x3
_u8_2:
    cmpwi r5, 0x2
    add r6, r3, r5
    beq _u8_4
    bge _u8_5
    cmpwi r5, 0x1
    bge _u8_6
    b _u8_7
_u8_5:
    cmpwi r5, 0x4
    bge _u8_7
    clrlwi r0, r4, 26
    extrwi r4, r4, 10, 16
    ori r0, r0, 0x80
    stbu r0, -0x1(r6)
_u8_4:
    clrlwi r0, r4, 26
    extrwi r4, r4, 10, 16
    ori r0, r0, 0x80
    stbu r0, -0x1(r6)
_u8_6:
    addi r3, r1, 0x8
    lbzx r0, r3, r5
    or r0, r4, r0
    stb r0, -0x1(r6)
_u8_7:
    mr r3, r5
_u8_end:
    addi r1, r1, 0x10
    blr
}
