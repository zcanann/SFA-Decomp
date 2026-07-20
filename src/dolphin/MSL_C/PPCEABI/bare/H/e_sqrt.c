#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

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

float powfCoreHighPrecision(float base, float power) {
    register double logValue;
    register double fractionalExponent;
    register double log2Mantissa;
    register double resultExponentAsDouble;
    register u32 baseBits;
    register int baseExponent;
    register int resultExponent;
    register int integerPower;
    float result;
    float normalizedBase;

    if (base != lbl_803E7AB8) {
        baseBits = *(u32 *)&base;
        baseExponent = (s16)(((baseBits >> 23) & 0xFF) - 127);
        *(u32 *)&normalizedBase = (baseBits & 0x7FFFFF) | 0x3F800000;
        logValue = normalizedBase - lbl_803E7AC0;
        log2Mantissa = logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (logValue * (lbl_803E7B60 * logValue + lbl_803E7B58) + lbl_803E7B50) + lbl_803E7B48) + lbl_803E7B40) + lbl_803E7B38) + lbl_803E7B30) + lbl_803E7B28) + lbl_803E7B20) + lbl_803E7B18) + lbl_803E7B10) + lbl_803E7B08) + lbl_803E7B00) + lbl_803E7AF8) + lbl_803E7AF0) + lbl_803E7AE8) + lbl_803E7AE0) + lbl_803E7AD8) + lbl_803E7AD0) + lbl_803E7AC8);
        logValue = power * (log2Mantissa + (double)baseExponent);
        resultExponent = logValue;
        resultExponentAsDouble = (double)resultExponent;
        fractionalExponent = logValue - resultExponentAsDouble;

        result = (fractionalExponent != lbl_803E7B68) ? (float)(fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (fractionalExponent * (lbl_803E7BC0 * fractionalExponent + lbl_803E7BB8) + lbl_803E7BB0) + lbl_803E7BA8) + lbl_803E7BA0) + lbl_803E7B98) + lbl_803E7B90) + lbl_803E7B88) + lbl_803E7B80) + lbl_803E7B78) + lbl_803E7B70) : lbl_803E7BC8;

        if ((int)(baseBits & 0x80000000)) {
            integerPower = power;
            if (integerPower & 1) {
                result = -result;
            }
        }
        *(u32 *)&result += resultExponent << 23;
        return result;
    }
    if (power != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }
    return lbl_803E7BC8;
}

float powfCoreFast(float base, register float power) {
    float resultExponentAsFloat;
    float baseExponentAsFloat;
    register u32 baseBits;
    register int integerPower;
    float result;
    float logValue;
    s16 baseExponent;
    s16 resultExponent;

    if (base != lbl_803E7AB8) {
        baseBits = *(u32 *)&base;
        baseExponent = ((baseBits >> 23) & 0xFF) - 127;
        *(u32 *)&logValue = (baseBits & 0x7FFFFF) | 0x3F800000;
        logValue = logValue - lbl_803E7BC8;
        logValue = logValue * (logValue * (lbl_803E7BE4 * logValue + lbl_803E7BE0) + lbl_803E7BDC) + lbl_803E7BD8;
        baseExponentAsFloat = fastCastS16ToFloat(&baseExponent);
        logValue = power * (logValue + baseExponentAsFloat);
        fastCastFloatToS16(logValue, &resultExponent);
        resultExponentAsFloat = fastCastS16ToFloat(&resultExponent);
        logValue = logValue - resultExponentAsFloat;
        result = (logValue != lbl_803E7AB8) ? (logValue * (lbl_803E7BF0 * logValue + lbl_803E7BEC) + lbl_803E7BE8) : lbl_803E7BC8;
        if ((int)(baseBits & 0x80000000)) {
            integerPower = power;
            if (integerPower & 1) {
                result = -result;
            }
        }
        *(u32 *)&result += resultExponent << 23;
        return result;
    }
    if (power != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }
    return lbl_803E7BC8;
}
