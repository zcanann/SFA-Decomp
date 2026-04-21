#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/signal.h"
#include "Runtime.PPCEABI.H/NMWException.h"
#include "stddef.h"

void _ExitProcess();

extern void (*_dtors[])(void);

static void (*__atexit_funcs[64])(void);

static void (*__console_exit)(void);

void (*__stdio_exit)(void);

static int __atexit_curr_func;

static int __aborting;

asm void exit(int status) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    stw r31, 0xc(r1)
    lwz r0, __aborting(r13)
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
    lwz r12, __stdio_exit(r13)
    cmplwi r12, 0x0
    beq _exit_3
    mtctr r12
    bctrl
    li r0, 0x0
    stw r0, __stdio_exit(r13)
_exit_3:
    lis r3, __atexit_funcs@ha
    addi r31, r3, __atexit_funcs@l
    b _exit_5
_exit_4:
    lwz r3, __atexit_curr_func(r13)
    subi r3, r3, 0x1
    slwi r0, r3, 2
    stw r3, __atexit_curr_func(r13)
    lwzx r12, r31, r0
    mtctr r12
    bctrl
_exit_5:
    lwz r0, __atexit_curr_func(r13)
    cmpwi r0, 0x0
    bgt _exit_4
    lwz r12, __console_exit(r13)
    cmplwi r12, 0x0
    beq _exit_6
    mtctr r12
    bctrl
    li r0, 0x0
    stw r0, __console_exit(r13)
_exit_6:
    bl _ExitProcess
    lwz r0, 0x14(r1)
    lwz r31, 0xc(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}
