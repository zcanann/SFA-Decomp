#include "global.h"

extern "C" {
extern void __OSPSInit(void);
extern void __OSFPRInit(void);
extern void __OSCacheInit(void);

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
SECTION_INIT asm void __init_hardware(void)
{
    // clang-format off
    nofralloc

    mfmsr r0
    ori r0, r0, 0x2000
    mtmsr r0
    mflr r31
    bl __OSPSInit
    bl __OSFPRInit
    bl __OSCacheInit
    mtlr r31
    blr
    // clang-format on
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
SECTION_INIT asm void __flush_cache(void* addr, unsigned int size)
{
    // clang-format off
    nofralloc

    lis r5, 0xFFFF
    ori r5, r5, 0xFFF1
    and r5, r5, r3
    subf r3, r5, r3
    add r4, r4, r3

lbl_80003438:
    dcbst 0, r5
    sync
    icbi 0, r5
    addic r5, r5, 8
    addic. r4, r4, -8
    bge lbl_80003438

    isync
    blr
    // clang-format on
}

}
