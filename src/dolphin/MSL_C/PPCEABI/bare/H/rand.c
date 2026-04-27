#include "dolphin.h"

extern u32 lbl_803DE410;

u32 rand(void) {
    lbl_803DE410 = lbl_803DE410 * 0x41C64E6D + 0x3039;
    return lbl_803DE410;
}

void srand(u32 seed) {
    lbl_803DE410 = seed;
}

float fn_80292DEC(float x) {
    return 1.0f / x;
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
