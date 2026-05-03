#include "dolphin/os.h"
#include "__ppc_eabi_linker.h"

typedef unsigned int size_t;

extern void DBInit(void);
extern void OSInit(void);
extern void OSResetSystem(int reset, unsigned long resetCode, int forceMenu);
extern void InitMetroTRK(void);
extern void __OSPSInit(void);
extern void __OSCacheInit(void);
extern void __init_user(void);
extern int main(int argc, char** argv);
extern void exit(int status);
extern void* memcpy(void* dst, const void* src, size_t n);
extern void* memset(void* dst, int val, size_t n);

__declspec(section ".init") static void __init_registers(void);
__declspec(section ".init") void __init_data(void);
__declspec(section ".init") void __init_hardware(void);
__declspec(section ".init") void __flush_cache(void* address, unsigned int size);

#define EXCEPTIONMASK_ADDR 0x80000044
#define BOOTINFO2_ADDR 0x800000F4
#define ARENAHI_ADDR 0x80000034
#define DEBUGFLAG_ADDR 0x800030E8
#define DVD_DEVICECODE_ADDR 0x800030E6
#define PAD3_STATUS_ADDR 0x800030E4
#define OS_BI2_DEBUGFLAG_OFFSET 0xC

__declspec(section ".init") void __check_pad3(void)
{
    if ((*(volatile unsigned short*)PAD3_STATUS_ADDR & 0x0eef) == 0x0eef) {
        OSResetSystem(0, 0, 0);
    }
}

__declspec(section ".init") __declspec(weak) asm void __start(void)
{
    nofralloc
    bl __init_registers
    bl __init_hardware
    li r0, -1
    stwu r1, -8(r1)
    stw r0, 4(r1)
    stw r0, 0(r1)
    bl __init_data
    li r0, 0
    lis r6, EXCEPTIONMASK_ADDR@ha
    addi r6, r6, EXCEPTIONMASK_ADDR@l
    stw r0, 0(r6)
    lis r6, BOOTINFO2_ADDR@ha
    addi r6, r6, BOOTINFO2_ADDR@l
    lwz r6, 0(r6)

_check_TRK:
    cmplwi r6, 0
    beq _load_lomem_debug_flag
    lwz r7, OS_BI2_DEBUGFLAG_OFFSET(r6)
    b _check_debug_flag

_load_lomem_debug_flag:
    lis r5, ARENAHI_ADDR@ha
    addi r5, r5, ARENAHI_ADDR@l
    lwz r5, 0(r5)
    cmplwi r5, 0
    beq _goto_main
    lis r7, DEBUGFLAG_ADDR@ha
    addi r7, r7, DEBUGFLAG_ADDR@l
    lwz r7, 0(r7)

_check_debug_flag:
    li r5, 0
    cmplwi r7, 2
    beq _goto_inittrk
    cmplwi r7, 3
    bne _goto_main
    li r5, 1

_goto_inittrk:
    lis r6, InitMetroTRK@ha
    addi r6, r6, InitMetroTRK@l
    mtlr r6
    blrl

_goto_main:
    lis r6, BOOTINFO2_ADDR@ha
    addi r6, r6, BOOTINFO2_ADDR@l
    lwz r5, 0(r6)
    cmplwi r5, 0
    beq+ _no_args
    lwz r6, 8(r5)
    cmplwi r6, 0
    beq+ _no_args
    add r6, r5, r6
    lwz r14, 0(r6)
    cmplwi r14, 0
    beq _no_args
    addi r15, r6, 4
    mtctr r14

_loop:
    addi r6, r6, 4
    lwz r7, 0(r6)
    add r7, r7, r5
    stw r7, 0(r6)
    bdnz _loop
    lis r5, ARENAHI_ADDR@ha
    addi r5, r5, ARENAHI_ADDR@l
    rlwinm r7, r15, 0, 0, 0x1a
    stw r7, 0(r5)
    b _end_of_parseargs

_no_args:
    li r14, 0
    li r15, 0

_end_of_parseargs:
    bl DBInit
    bl OSInit
    lis r4, DVD_DEVICECODE_ADDR@ha
    addi r4, r4, DVD_DEVICECODE_ADDR@l
    lhz r3, 0(r4)
    andi. r5, r3, 0x8000
    beq _check_pad3
    andi. r3, r3, 0x7fff
    cmplwi r3, 1
    bne _goto_skip_init_bba

_check_pad3:
    bl __check_pad3

_goto_skip_init_bba:
    bl __init_user
    mr r3, r14
    mr r4, r15
    bl main
    b exit
}

__declspec(section ".init") asm static void __init_registers(void)
{
    nofralloc
    lis r1, _stack_addr@h
    ori r1, r1, _stack_addr@l
    lis r2, _SDA2_BASE_@h
    ori r2, r2, _SDA2_BASE_@l
    lis r13, _SDA_BASE_@h
    ori r13, r13, _SDA_BASE_@l
    blr
}

static inline void __copy_rom_section(void* dst, const void* src, unsigned long size)
{
    if (size && (dst != src)) {
        memcpy(dst, src, size);
        __flush_cache(dst, size);
    }
}

static inline void __init_bss_section(void* dst, unsigned long size)
{
    if (size) {
        memset(dst, 0, size);
    }
}

#pragma scheduling off
__declspec(section ".init") void __init_data(void)
{
    __rom_copy_info* dci;
    __bss_init_info* bii;

    dci = _rom_copy_info;
    while (1) {
        if (dci->size == 0) {
            break;
        }
        __copy_rom_section(dci->addr, dci->rom, dci->size);
        dci++;
    }

    bii = _bss_init_info;
    while (1) {
        if (bii->size == 0) {
            break;
        }
        __init_bss_section(bii->addr, bii->size);
        bii++;
    }
}

__declspec(section ".init") asm void __init_hardware(void)
{
    nofralloc
    mfmsr r0
    ori r0, r0, 0x2000
    mtmsr r0
    mflr r31
    bl __OSPSInit
    bl __OSCacheInit
    mtlr r31
    blr
}

__declspec(section ".init") asm void __flush_cache(void* address, unsigned int size)
{
    nofralloc
    lis r5, ~0
    ori r5, r5, ~14
    and r5, r5, r3
    subf r3, r5, r3
    add r4, r4, r3

loop:
    dcbst r0, r5
    sync
    icbi r0, r5
    addic r5, r5, 8
    subic. r4, r4, 8
    bge loop
    isync
    blr
}
