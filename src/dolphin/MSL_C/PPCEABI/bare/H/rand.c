#include "dolphin.h"

extern u32 lbl_803DE410;
extern float lbl_803E7C18;

u32 rand(void) {
    lbl_803DE410 = lbl_803DE410 * 0x19660D + 0x3C6EF35F;
    return lbl_803DE410;
}

void srand(u32 seed) {
    lbl_803DE410 = seed;
}

asm float fn_80292DEC(register float x) {
    nofralloc
    stwu r1, -24(r1)
    stfd f31, 16(r1)
    fres f31, f1
    lfs f0, lbl_803E7C18(r2)
    fnmsubs f0, f1, f31, f0
    fmuls f31, f31, f0
    lfs f0, lbl_803E7C18(r2)
    fnmsubs f0, f1, f31, f0
    fmuls f31, f31, f0
    fmr f1, f31
    lfd f31, 16(r1)
    addi r1, r1, 24
    blr
}

void fn_80292E20(int q, float* sin_out, float* cos_out) {
    (void)q;
    *sin_out = 0.0f;
    *cos_out = 1.0f;
}

void fn_80292F14(int q, float* sin_out, float* cos_out) {
    (void)q;
    *sin_out = 0.0f;
    *cos_out = 1.0f;
}

void fn_80293018(int q, float* sin_out, float* cos_out) {
    (void)q;
    *sin_out = 0.0f;
    *cos_out = 1.0f;
}
