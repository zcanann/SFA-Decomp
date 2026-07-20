#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"

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

float fn_80292DEC(float value) {
    float reciprocal;

    reciprocal = __fres(value);
    reciprocal *= lbl_803E7C18 - value * reciprocal;
    reciprocal *= lbl_803E7C18 - value * reciprocal;

    return reciprocal;
}

#define STORE_SINCOS(angle, sine, cosine, sinOut, cosOut) \
    switch ((((u16)(angle)) + 0x2000) & 0xC000) {         \
        case 0x0000:                                      \
            *(sinOut) = (sine);                           \
            *(cosOut) = (cosine);                         \
            break;                                        \
        case 0x4000:                                      \
            *(sinOut) = (cosine);                         \
            *(cosOut) = -(sine);                          \
            break;                                        \
        case 0x8000:                                      \
            *(sinOut) = -(sine);                          \
            *(cosOut) = -(cosine);                        \
            break;                                        \
        default:                                          \
            *(sinOut) = -(cosine);                        \
            *(cosOut) = (sine);                           \
            break;                                        \
    }

void fn_80292E20(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine = scaledAngle * (lbl_803E7C24 * angleSquared + lbl_803E7C20);
    float cosine = angleSquared * (lbl_803E7C30 * angleSquared + lbl_803E7C2C) + lbl_803E7C28;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void angleToVec2(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine = scaledAngle * ((lbl_803E7C3C * angleSquared + lbl_803E7C38) * angleSquared + lbl_803E7C34);
    float cosine = ((lbl_803E7C4C * angleSquared + lbl_803E7C48) * angleSquared + lbl_803E7C44) * angleSquared + lbl_803E7C40;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}

void fn_80293018(int angle, float* sinOut, float* cosOut) {
    s16 scaledAngleBits = (u16)angle << 1 << 1;
    float scaledAngle = fastCastS16ToFloat(&scaledAngleBits);
    float angleSquared = scaledAngle * scaledAngle;
    float sine = scaledAngle *
                 (((lbl_803E7C5C * angleSquared + lbl_803E7C58) * angleSquared + lbl_803E7C54) * angleSquared +
                  lbl_803E7C50);
    float cosine =
        (lbl_803E7C60 + ((lbl_803E7C6C * angleSquared + lbl_803E7C68) * angleSquared + lbl_803E7C64) * angleSquared) *
            angleSquared +
        lbl_803E7C40;

    STORE_SINCOS(angle, sine, cosine, sinOut, cosOut);
}
