#include "dolphin.h"

asm u32 PPCMfmsr(void) {
    nofralloc
    mfmsr r3
    blr
}

asm void PPCMtmsr(register u32 value) {
    nofralloc
    mtmsr value
    blr
}

asm u32 PPCMfhid0(void) {
    nofralloc
    mfspr r3, HID0
    blr
}

asm void PPCMthid0(register u32 value) {
    nofralloc
    mtspr HID0, value
    blr
}

asm u32 PPCMfl2cr(void) {
    nofralloc
    mfspr r3, L2CR
    blr
}

asm void PPCMtl2cr(register u32 value) {
    nofralloc
    mtspr L2CR, value
    blr
}

asm void PPCMtdec(register u32 value) {
    nofralloc
    mtdec value
    blr
}

asm u32 PPCMfhid2(void) {
    nofralloc
    mfspr r3, HID2
    blr
}

asm void PPCMthid2(register u32 value) {
    nofralloc
    mtspr HID2, value
    blr
}

asm u32 PPCMfwpar(void) {
    nofralloc
    sync
    mfspr r3, WPAR
    blr
}

asm void PPCMtwpar(register u32 value) {
    nofralloc
    mtspr WPAR, value
    blr
}

void PPCDisableSpeculation(void) {
    PPCMthid0(PPCMfhid0() | HID0_SPD);
}

asm void PPCSetFpNonIEEEMode(void) {
    nofralloc
    mtfsb1 29
    blr
}
