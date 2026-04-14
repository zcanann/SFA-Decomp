#include "dolphin.h"

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
u32 PPCMfmsr(void)
{
    asm { mfmsr r3 }
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
void PPCMtmsr(register u32 newMSR)
{
    asm { mtmsr newMSR }
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
u32 PPCMfhid0(void)
{
    asm { mfspr r3, HID0 }
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
void PPCMthid0(register u32 newHID0)
{
    asm { mtspr HID0, newHID0 }
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
u32 PPCMfl2cr(void)
{
    asm { mfspr r3, L2CR }
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
void PPCMtl2cr(register u32 newL2cr)
{
    asm { mtspr L2CR, newL2cr }
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
void PPCMtdec(register u32 newDec)
{
    asm { mtdec newDec }
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
void PPCSync(void)
{
    asm { sc }
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
void PPCHalt(void)
{
    asm {
        sync
    loop:
        nop
        li r3, 0
        nop
        b loop
    }
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
void PPCMtmmcr0(register u32 newMMCR0)
{
    asm { mtspr MMCR0, newMMCR0 }
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
void PPCMtmmcr1(register u32 newMMCR1)
{
    asm { mtspr MMCR1, newMMCR1 }
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
void PPCMtpmc1(register u32 newPMC1)
{
    asm { mtspr PMC1, newPMC1 }
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
void PPCMtpmc2(register u32 newPMC2)
{
    asm { mtspr PMC2, newPMC2 }
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
void PPCMtpmc3(register u32 newPMC3)
{
    asm { mtspr PMC3, newPMC3 }
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
void PPCMtpmc4(register u32 newPMC4)
{
    asm { mtspr PMC4, newPMC4 }
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
asm u32 PPCMffpscr(void)
{
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    mffs f31
    stfd f31, 0x8(r1)
    lwz r3, 0xc(r1)
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
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
asm void PPCMtfpscr(register u32 newFPSCR)
{
    nofralloc
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    li r4, 0
    stw r4, 0x10(r1)
    stw newFPSCR, 0x14(r1)
    lfd f31, 0x10(r1)
    mtfsf 255, f31
    lfd f31, 0x18(r1)
    addi r1, r1, 0x20
    blr
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
u32 PPCMfhid2(void)
{
    asm { mfspr r3, HID2 }
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
void PPCMthid2(register u32 newHID2)
{
    asm { mtspr HID2, newHID2 }
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
void PPCMtwpar(register u32 newWPAR)
{
    asm { mtspr WPAR, newWPAR }
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
asm void PPCDisableSpeculation(void)
{
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x8(r1)
    bl PPCMfhid0
    ori r3, r3, HID0_SPD
    bl PPCMthid0
    lwz r0, 0xc(r1)
    addi r1, r1, 0x8
    mtlr r0
    blr
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
void PPCSetFpNonIEEEMode(void)
{
    asm { mtfsb1 29 }
}
