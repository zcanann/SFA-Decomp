#include "dolphin.h"

extern u32 lbl_803DE410;
extern float lbl_803E7C18;
extern float lbl_803E7C20;
extern float lbl_803E7C24;
extern float lbl_803E7C28;
extern float lbl_803E7C2C;
extern float lbl_803E7C30;
extern float lbl_803E7C34;
extern float lbl_803E7C38;
extern float lbl_803E7C3C;
extern float lbl_803E7C40;
extern float lbl_803E7C44;
extern float lbl_803E7C48;
extern float lbl_803E7C4C;
extern float lbl_803E7C50;
extern float lbl_803E7C54;
extern float lbl_803E7C58;
extern float lbl_803E7C5C;
extern float lbl_803E7C60;
extern float lbl_803E7C64;
extern float lbl_803E7C68;
extern float lbl_803E7C6C;

float fn_80291E08(s16* p);

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

#define STORE_SINCOS(q, sin_value, cos_value, sin_out, cos_out) \
    switch ((((u16)(q)) + 0x2000) & 0xC000) {                  \
        case 0x0000:                                           \
            *(sin_out) = (sin_value);                          \
            *(cos_out) = (cos_value);                          \
            break;                                             \
        case 0x4000:                                           \
            *(sin_out) = (cos_value);                          \
            *(cos_out) = -(sin_value);                         \
            break;                                             \
        case 0x8000:                                           \
            *(sin_out) = -(sin_value);                         \
            *(cos_out) = -(cos_value);                         \
            break;                                             \
        default:                                               \
            *(sin_out) = -(cos_value);                         \
            *(cos_out) = (sin_value);                          \
            break;                                             \
    }

void fn_80292E20(int q, float* sin_out, float* cos_out) {
    s16 angle = q << 2;
    float x = fn_80291E08(&angle);
    float x2 = x * x;
    float sin_value = x * (lbl_803E7C24 * x2 + lbl_803E7C20);
    float cos_value = x2 * (lbl_803E7C30 * x2 + lbl_803E7C2C) + lbl_803E7C28;

    STORE_SINCOS(q, sin_value, cos_value, sin_out, cos_out);
}

void angleToVec2(int q, float* sin_out, float* cos_out) {
    s16 angle = q << 2;
    float x = fn_80291E08(&angle);
    float x2 = x * x;
    float sin_value = x * ((lbl_803E7C3C * x2 + lbl_803E7C38) * x2 + lbl_803E7C34);
    float cos_value = ((lbl_803E7C4C * x2 + lbl_803E7C48) * x2 + lbl_803E7C44) * x2 + lbl_803E7C40;

    STORE_SINCOS(q, sin_value, cos_value, sin_out, cos_out);
}

void fn_80293018(int q, float* sin_out, float* cos_out) {
    s16 angle = q << 2;
    float x = fn_80291E08(&angle);
    float x2 = x * x;
    float sin_value = x * (((lbl_803E7C5C * x2 + lbl_803E7C58) * x2 + lbl_803E7C54) * x2 + lbl_803E7C50);
    float cos_value = (((lbl_803E7C6C * x2 + lbl_803E7C68) * x2 + lbl_803E7C64) * x2 + lbl_803E7C60) * x2 + lbl_803E7C40;

    STORE_SINCOS(q, sin_value, cos_value, sin_out, cos_out);
}
