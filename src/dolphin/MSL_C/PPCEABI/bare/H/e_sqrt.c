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
extern float lbl_803E7BD8;
extern float lbl_803E7BDC;
extern float lbl_803E7BE0;
extern float lbl_803E7BE4;
extern float lbl_803E7BE8;
extern float lbl_803E7BEC;
extern float lbl_803E7BF0;

float fastCastS16ToFloat(s16* p);
void fastCastFloatToS16(float x, s16* p);


float powfCoreHighPrecision(float x, float y) {
    register double mantissa;
    register double frac;
    register double mantissa2;
    register double scaleconv;
    register u32 ix;
    register int exponent;
    register int scale;
    register int ysign;
    float value;
    float m;

    if (x != lbl_803E7AB8) {
        ix = *(u32 *)&x;
        exponent = (s16)(((ix >> 23) & 0xFF) - 127);
        *(u32 *)&m = (ix & 0x7FFFFF) | 0x3F800000;
        mantissa = m - lbl_803E7AC0;
        mantissa2 = mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (mantissa * (lbl_803E7B60 * mantissa + lbl_803E7B58) + lbl_803E7B50) + lbl_803E7B48) + lbl_803E7B40) + lbl_803E7B38) + lbl_803E7B30) + lbl_803E7B28) + lbl_803E7B20) + lbl_803E7B18) + lbl_803E7B10) + lbl_803E7B08) + lbl_803E7B00) + lbl_803E7AF8) + lbl_803E7AF0) + lbl_803E7AE8) + lbl_803E7AE0) + lbl_803E7AD8) + lbl_803E7AD0) + lbl_803E7AC8);
        mantissa = y * (mantissa2 + (double)exponent);
        scale = mantissa;
        scaleconv = (double)scale;
        frac = mantissa - scaleconv;

        value = (frac != lbl_803E7B68) ? (float)(frac * (frac * (frac * (frac * (frac * (frac * (frac * (frac * (frac * (lbl_803E7BC0 * frac + lbl_803E7BB8) + lbl_803E7BB0) + lbl_803E7BA8) + lbl_803E7BA0) + lbl_803E7B98) + lbl_803E7B90) + lbl_803E7B88) + lbl_803E7B80) + lbl_803E7B78) + lbl_803E7B70) : lbl_803E7BC8;

        if ((int)(ix & 0x80000000)) {
            ysign = y;
            if (ysign & 1) {
                value = -value;
            }
        }
        *(u32 *)&value += scale << 23;
        return value;
    }
    if (y != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }
    return lbl_803E7BC8;
}

float powfCoreFast(float x, register float y) {
    register float expf;
    register float scalef;
    register u32 ix;
    register int ysign;
    float result;
    float value;
    s16 exponent;
    s16 scale;

    if (x != lbl_803E7AB8) {
        ix = *(u32 *)&x;
        exponent = ((ix >> 23) & 0xFF) - 127;
        *(u32 *)&value = (ix & 0x7FFFFF) | 0x3F800000;
        value = value - lbl_803E7BC8;
        value = value * (value * (lbl_803E7BE4 * value + lbl_803E7BE0) + lbl_803E7BDC) + lbl_803E7BD8;
        expf = fastCastS16ToFloat(&exponent);
        value = y * (value + expf);
        fastCastFloatToS16(value, &scale);
        scalef = fastCastS16ToFloat(&scale);
        value = value - scalef;
        result = (value != lbl_803E7AB8) ? (value * (lbl_803E7BF0 * value + lbl_803E7BEC) + lbl_803E7BE8) : lbl_803E7BC8;
        if ((int)(ix & 0x80000000)) {
            ysign = y;
            if (ysign & 1) {
                result = -result;
            }
        }
        *(u32 *)&result += scale << 23;
        return result;
    }
    if (y != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }
    return lbl_803E7BC8;
}
