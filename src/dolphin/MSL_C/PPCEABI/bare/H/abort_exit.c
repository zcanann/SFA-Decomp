#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/signal.h"
#include "Runtime.PPCEABI.H/NMWException.h"
#include "stddef.h"

void _ExitProcess();

extern void (*_dtors[])(void);

void (*__atexit_funcs[64])(void);

extern void (*__console_exit)(void);

extern void (*__stdio_exit)(void);

extern int __atexit_curr_func_803DE3F4;
#define __atexit_curr_func __atexit_curr_func_803DE3F4

extern int __aborting;

asm void exit(int status) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    lwz r0, __aborting(r0)
    cmpwi r0, 0x0
    bne _exit_3
    bl __destroy_global_chain
    lis r3, _dtors@ha
    addi r0, r3, _dtors@l
    mr r31, r0
    b _exit_1
_exit_0:
    mtctr r12
    bctrl
    addi r31, r31, 0x4
_exit_1:
    lwz r12, 0x0(r31)
    cmplwi r12, 0x0
    bne _exit_0
    lwz r12, __stdio_exit(r0)
    cmplwi r12, 0x0
    beq _exit_3
    mtctr r12
    bctrl
    li r0, 0x0
    stw r0, __stdio_exit(r0)
_exit_3:
    lis r3, __atexit_funcs@ha
    addi r31, r3, __atexit_funcs@l
    b _exit_5
_exit_4:
    lwz r3, __atexit_curr_func(r0)
    subi r3, r3, 0x1
    slwi r0, r3, 2
    stw r3, __atexit_curr_func(r0)
    lwzx r12, r31, r0
    mtctr r12
    bctrl
_exit_5:
    lwz r0, __atexit_curr_func(r0)
    cmpwi r0, 0x0
    bgt _exit_4
    lwz r12, __console_exit(r0)
    cmplwi r12, 0x0
    beq _exit_6
    mtctr r12
    bctrl
    li r0, 0x0
    stw r0, __console_exit(r0)
_exit_6:
    bl _ExitProcess
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

/* heap deallocation helpers absorbed in this TU range */

extern unsigned char lbl_803DE400;     /* init flag */
extern unsigned int lbl_803DABB8[13];/* free-list buckets, 0x34 bytes */
extern unsigned int lbl_802C2A00;
extern void* memset(void*, int, unsigned int);
extern void __sys_free(void*);

asm void fn_8028D8A4(void* a, void** out_b);
asm void fn_8028D960(void* p);
asm void fn_8028D6A8(void* table, void* p);

asm void fn_8028D574(void* p) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    stw r30, 0x8(r1)
    mr r30, r3
    lbz r0, lbl_803DE400(r0)
    cmplwi r0, 0
    bne _f574_init_done
    lis r3, lbl_803DABB8@ha
    li r4, 0
    addi r3, r3, lbl_803DABB8@l
    li r5, 0x34
    bl memset
    li r0, 1
    stb r0, lbl_803DE400(r0)
_f574_init_done:
    cmplwi r30, 0
    lis r3, lbl_803DABB8@ha
    addi r31, r3, lbl_803DABB8@l
    beq _f574_end
    lwz r3, -0x4(r30)
    clrlwi. r0, r3, 31
    bne _f574_else
    lwz r5, 0x8(r3)
    b _f574_chk
_f574_else:
    lwz r0, -0x8(r30)
    clrrwi r3, r0, 3
    subi r5, r3, 0x8
_f574_chk:
    cmplwi r5, 0x44
    bgt _f574_big
    mr r3, r31
    mr r4, r30
    bl fn_8028D6A8
    b _f574_end
_f574_big:
    lwz r0, -0x4(r30)
    subi r4, r30, 0x8
    clrrwi r30, r0, 1
    mr r3, r30
    bl fn_8028D960
    lwz r3, 0x10(r30)
    li r5, 0
    rlwinm. r0, r3, 0, 30, 30
    bne _f574_done_check
    lwz r0, 0xc(r30)
    clrrwi r4, r3, 3
    clrrwi r3, r0, 3
    subi r0, r3, 0x18
    cmplw r4, r0
    bne _f574_done_check
    li r5, 1
_f574_done_check:
    cmpwi r5, 0
    beq _f574_end
    lwz r4, 0x4(r30)
    cmplw r4, r30
    bne _f574_l1
    li r4, 0
_f574_l1:
    lwz r0, 0(r31)
    cmplw r0, r30
    bne _f574_l2
    stw r4, 0(r31)
_f574_l2:
    cmplwi r4, 0
    beq _f574_l3
    lwz r0, 0(r30)
    stw r0, 0(r4)
    lwz r3, 0(r4)
    stw r4, 0x4(r3)
_f574_l3:
    li r0, 0
    mr r3, r30
    stw r0, 0x4(r30)
    stw r0, 0(r30)
    bl __sys_free
_f574_end:
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    lwz r30, 0x8(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void fn_8028D6A8(void* table, void* p) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    lis r6, lbl_802C2A00@ha
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    mr r31, r3
    addi r3, r6, lbl_802C2A00@l
    li r6, 0
    stw r30, 0x8(r1)
    b _f6a8_loop_chk
_f6a8_loop:
    addi r3, r3, 0x4
    addi r6, r6, 1
_f6a8_loop_chk:
    lwz r0, 0(r3)
    cmplw r5, r0
    bgt _f6a8_loop
    subi r7, r4, 0x4
    slwi r4, r6, 3
    lwz r3, 0(r7)
    addi r4, r4, 0x4
    add r4, r31, r4
    lwz r0, 0xc(r3)
    cmplwi r0, 0
    bne _f6a8_skip_relink
    lwz r5, 0x4(r4)
    cmplw r5, r3
    beq _f6a8_skip_relink
    lwz r0, 0(r4)
    cmplw r0, r3
    bne _f6a8_relink_else
    lwz r0, 0(r5)
    stw r0, 0x4(r4)
    lwz r5, 0(r4)
    lwz r0, 0(r5)
    stw r0, 0(r4)
    b _f6a8_skip_relink
_f6a8_relink_else:
    lwz r0, 0x4(r3)
    lwz r5, 0(r3)
    stw r0, 0x4(r5)
    lwz r0, 0(r3)
    lwz r5, 0x4(r3)
    stw r0, 0(r5)
    lwz r0, 0x4(r4)
    stw r0, 0x4(r3)
    lwz r5, 0x4(r3)
    lwz r0, 0(r5)
    stw r0, 0(r3)
    lwz r5, 0(r3)
    stw r3, 0x4(r5)
    lwz r5, 0x4(r3)
    stw r3, 0(r5)
    stw r3, 0x4(r4)
_f6a8_skip_relink:
    lwz r0, 0xc(r3)
    stw r0, 0x4(r7)
    stw r7, 0xc(r3)
    lwz r5, 0x10(r3)
    subic. r0, r5, 1
    stw r0, 0x10(r3)
    bne _f6a8_done
    lwz r0, 0x4(r4)
    cmplw r0, r3
    bne _f6a8_l1
    lwz r0, 0x4(r3)
    stw r0, 0x4(r4)
_f6a8_l1:
    lwz r0, 0(r4)
    cmplw r0, r3
    bne _f6a8_l2
    lwz r0, 0(r3)
    stw r0, 0(r4)
_f6a8_l2:
    lwz r0, 0x4(r3)
    lwz r5, 0(r3)
    stw r0, 0x4(r5)
    lwz r0, 0(r3)
    lwz r5, 0x4(r3)
    stw r0, 0(r5)
    lwz r0, 0x4(r4)
    cmplw r0, r3
    bne _f6a8_l3
    li r0, 0
    stw r0, 0x4(r4)
_f6a8_l3:
    lwz r0, 0(r4)
    cmplw r0, r3
    bne _f6a8_l4
    li r0, 0
    stw r0, 0(r4)
_f6a8_l4:
    lwz r0, -0x4(r3)
    subi r4, r3, 0x8
    clrrwi r30, r0, 1
    mr r3, r30
    bl fn_8028D960
    lwz r3, 0x10(r30)
    li r5, 0
    rlwinm. r0, r3, 0, 30, 30
    bne _f6a8_chk2
    lwz r0, 0xc(r30)
    clrrwi r4, r3, 3
    clrrwi r3, r0, 3
    subi r0, r3, 0x18
    cmplw r4, r0
    bne _f6a8_chk2
    li r5, 1
_f6a8_chk2:
    cmpwi r5, 0
    beq _f6a8_done
    lwz r4, 0x4(r30)
    cmplw r4, r30
    bne _f6a8_m1
    li r4, 0
_f6a8_m1:
    lwz r0, 0(r31)
    cmplw r0, r30
    bne _f6a8_m2
    stw r4, 0(r31)
_f6a8_m2:
    cmplwi r4, 0
    beq _f6a8_m3
    lwz r0, 0(r30)
    stw r0, 0(r4)
    lwz r3, 0(r4)
    stw r4, 0x4(r3)
_f6a8_m3:
    li r0, 0
    mr r3, r30
    stw r0, 0x4(r30)
    stw r0, 0(r30)
    bl __sys_free
_f6a8_done:
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    lwz r30, 0x8(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void fn_8028D8A4(void* a, void** out_b) {
    nofralloc
    lwz r6, 0(r3)
    clrrwi r8, r6, 3
    add r5, r3, r8
    lwz r7, 0(r5)
    rlwinm. r0, r7, 0, 30, 30
    bnelr
    clrlwi r0, r6, 29
    clrrwi r6, r7, 3
    stw r0, 0(r3)
    add r7, r8, r6
    clrrwi r0, r7, 3
    lwz r6, 0(r3)
    or r0, r6, r0
    stw r0, 0(r3)
    lwz r0, 0(r3)
    rlwinm. r0, r0, 0, 30, 30
    bne _f8a4_skip1
    subi r0, r7, 0x4
    stwx r7, r3, r0
_f8a4_skip1:
    lwz r0, 0(r3)
    rlwinm. r0, r0, 0, 30, 30
    bne _f8a4_else
    lwzx r6, r3, r7
    li r0, -0x5
    and r0, r6, r0
    stwx r0, r3, r7
    b _f8a4_done
_f8a4_else:
    lwzx r0, r3, r7
    ori r0, r0, 0x4
    stwx r0, r3, r7
_f8a4_done:
    lwz r3, 0(r4)
    cmplw r3, r5
    bne _f8a4_l1
    lwz r0, 0xc(r3)
    stw r0, 0(r4)
_f8a4_l1:
    lwz r0, 0(r4)
    cmplw r0, r5
    bne _f8a4_l2
    li r0, 0
    stw r0, 0(r4)
_f8a4_l2:
    lwz r0, 0x8(r5)
    lwz r3, 0xc(r5)
    stw r0, 0x8(r3)
    lwz r0, 0xc(r5)
    lwz r3, 0x8(r5)
    stw r0, 0xc(r3)
    blr
}
