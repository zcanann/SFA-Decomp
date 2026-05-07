#include "dolphin.h"

extern float lbl_803E7AB8;
extern double lbl_803E7AC0;
extern double lbl_803E7AC8;
extern double lbl_803E7AD0;
extern double lbl_803E7AD8;
extern double lbl_803E7AE0;
extern double lbl_803E7AE8;
extern double lbl_803E7AF0;
extern double lbl_803E7AF8;
extern double lbl_803E7B00;
extern double lbl_803E7B08;
extern double lbl_803E7B10;
extern double lbl_803E7B18;
extern double lbl_803E7B20;
extern double lbl_803E7B28;
extern double lbl_803E7B30;
extern double lbl_803E7B38;
extern double lbl_803E7B40;
extern double lbl_803E7B48;
extern double lbl_803E7B50;
extern double lbl_803E7B58;
extern double lbl_803E7B60;
extern double lbl_803E7B68;
extern double lbl_803E7B70;
extern double lbl_803E7B78;
extern double lbl_803E7B80;
extern double lbl_803E7B88;
extern double lbl_803E7B90;
extern double lbl_803E7B98;
extern double lbl_803E7BA0;
extern double lbl_803E7BA8;
extern double lbl_803E7BB0;
extern double lbl_803E7BB8;
extern double lbl_803E7BC0;
extern float lbl_803E7BC8;
extern double lbl_803E7BD0;
extern float lbl_803E7BD8;
extern float lbl_803E7BDC;
extern float lbl_803E7BE0;
extern float lbl_803E7BE4;
extern float lbl_803E7BE8;
extern float lbl_803E7BEC;
extern float lbl_803E7BF0;

float fastCastS16ToFloat(s16* p);
void fastCastFloatToS16(s16* p, float x);

typedef union FloatBits {
    float f;
    u32 u;
} FloatBits;

float __ieee754_sqrt(float x, float y) {
    FloatBits bits;
    FloatBits result;
    s16 exponent;
    int scale;
    double mantissa;
    double poly;
    double scaled;
    double frac;
    float value;

    if (x == lbl_803E7AB8) {
        if (y != lbl_803E7AB8) {
            return lbl_803E7AB8;
        }
        return lbl_803E7BC8;
    }

    bits.f = x;
    exponent = (s16)(((bits.u >> 23) & 0xFF) - 127);
    result.u = (bits.u & 0x7FFFFF) | 0x3F800000;
    mantissa = result.f - lbl_803E7AC0;

    poly = lbl_803E7B60 * mantissa + lbl_803E7B58;
    poly = mantissa * poly + lbl_803E7B50;
    poly = mantissa * poly + lbl_803E7B48;
    poly = mantissa * poly + lbl_803E7B40;
    poly = mantissa * poly + lbl_803E7B38;
    poly = mantissa * poly + lbl_803E7B30;
    poly = mantissa * poly + lbl_803E7B28;
    poly = mantissa * poly + lbl_803E7B20;
    poly = mantissa * poly + lbl_803E7B18;
    poly = mantissa * poly + lbl_803E7B10;
    poly = mantissa * poly + lbl_803E7B08;
    poly = mantissa * poly + lbl_803E7B00;
    poly = mantissa * poly + lbl_803E7AF8;
    poly = mantissa * poly + lbl_803E7AF0;
    poly = mantissa * poly + lbl_803E7AE8;
    poly = mantissa * poly + lbl_803E7AE0;
    poly = mantissa * poly + lbl_803E7AD8;
    poly = mantissa * poly + lbl_803E7AD0;
    poly = mantissa * poly + lbl_803E7AC8;
    scaled = y * (mantissa * poly + (double)exponent);
    scale = (int)scaled;
    frac = scaled - (double)scale;

    if (frac != lbl_803E7B68) {
        poly = lbl_803E7BC0 * frac + lbl_803E7BB8;
        poly = frac * poly + lbl_803E7BB0;
        poly = frac * poly + lbl_803E7BA8;
        poly = frac * poly + lbl_803E7BA0;
        poly = frac * poly + lbl_803E7B98;
        poly = frac * poly + lbl_803E7B90;
        poly = frac * poly + lbl_803E7B88;
        poly = frac * poly + lbl_803E7B80;
        poly = frac * poly + lbl_803E7B78;
        value = (float)(frac * poly + lbl_803E7B70);
    } else {
        value = lbl_803E7BC8;
    }

    if ((bits.u & 0x80000000) && (((int)y) & 1)) {
        value = -value;
    }

    result.f = value;
    result.u += (u32)scale << 23;
    return result.f;
}

float __ieee754_log(float x, float y) {
    FloatBits bits;
    FloatBits result;
    s16 exponent;
    s16 scale;
    float value;
    float frac;

    if (x == lbl_803E7AB8) {
        if (y != lbl_803E7AB8) {
            return lbl_803E7AB8;
        }
        return lbl_803E7BC8;
    }

    bits.f = x;
    exponent = (s16)(((bits.u >> 23) & 0xFF) - 127);
    result.u = (bits.u & 0x7FFFFF) | 0x3F800000;

    value = result.f - lbl_803E7BC8;
    value = ((lbl_803E7BE4 * value + lbl_803E7BE0) * value + lbl_803E7BDC) * value + lbl_803E7BD8;
    value = y * (value + fastCastS16ToFloat(&exponent));

    fastCastFloatToS16(&scale, value);
    frac = fastCastS16ToFloat(&scale);
    value -= frac;

    if (value != lbl_803E7AB8) {
        value = (lbl_803E7BF0 * value + lbl_803E7BEC) * value + lbl_803E7BE8;
    } else {
        value = lbl_803E7BC8;
    }

    if ((bits.u & 0x80000000) && (((int)y) & 1)) {
        value = -value;
    }

    result.f = value;
    result.u += (u32)scale << 23;
    return result.f;
}
