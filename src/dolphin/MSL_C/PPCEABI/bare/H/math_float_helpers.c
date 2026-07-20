#include "dolphin/os/OSFastCast.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"




extern const float lbl_803E7978;
extern const float lbl_803E797C;
extern const float lbl_803E7980;
extern const float lbl_803E7984;
extern const float lbl_803E7988;
extern const float lbl_803E798C;
extern const float lbl_803E7990;
extern const float lbl_803E7994;
extern const float lbl_803E7998[2];
extern const float lbl_803E79A0;
extern const float lbl_803E79A4;
extern const float lbl_803E79A8;
extern const float lbl_803E79AC;
extern const float lbl_803E79B0;

float fabsf(float value)
{
    double magnitude = __fabs(value);
    return magnitude;
}

float fastCastU16ToFloat(const u16* input)
{
    register const u16* ptr = input;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_U16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToU16(float value, u16* output)
{
    register u16* ptr = output;
    register float input = value;

    asm {
        fmr f31, input
        psq_st f31, 0(ptr), 1, OS_FASTCAST_U16
    }
}

#pragma optimization_level 0
#pragma optimize_for_size on
float exp2f(float value)
{
    s16 exponent;
    float integerPart;
    float fraction;
    float result;

    if (value < lbl_803E7978) {
        return lbl_803E797C;
    }

    fastCastFloatToS16(value, &exponent);
    integerPart = fastCastS16ToFloat(&exponent);
    fraction = value - integerPart;

    if (fraction != lbl_803E797C) {
        if (value < lbl_803E797C) {
            exponent--;
            fraction += lbl_803E7980;
        }

        result = (((lbl_803E7994 * fraction + lbl_803E7990) * fraction + lbl_803E798C) * fraction + lbl_803E7988)
               * fraction + lbl_803E7984;
    } else {
        result = lbl_803E7980;
    }

    *(u32*)&result = *(u32*)&result + ((u32)exponent << 23);
    return result;
}
#pragma optimize_for_size reset
#pragma optimization_level reset

float expf(float value)
{
    return exp2f(lbl_803E7998[0] * *(float*)&value);
}

const float lbl_803E7978 = -127.0f;
const float lbl_803E797C = 0.0f;
const float lbl_803E7980 = 1.0f;
const float lbl_803E7984 = 1.0000035762786865f;
const float lbl_803E7988 = 0.692969560623169f;
const float lbl_803E798C = 0.24162131547927856f;
const float lbl_803E7990 = 0.05171773582696915f;
const float lbl_803E7994 = 0.013683983124792576f;
const float lbl_803E7998[2] = {1.4426950216293335f, 0.0f};

float fastCastS16ToFloat(const s16* input)
{
    register const s16* ptr = input;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_S16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToS16(float value, s16* output)
{
    register s16* ptr = output;
    register float input = value;

    asm {
        fmr f31, input
        psq_st f31, 0(ptr), 1, OS_FASTCAST_S16
    }
}

const float lbl_803E79A0 = 65536.0f;
const float lbl_803E79A4 = 0.0f;
const float lbl_803E79A8 = -1.0f;
const float lbl_803E79AC = 8388608.0f;
const float lbl_803E79B0 = 1.0f;
const float lbl_803E79B4 = 0.0f;

#pragma optimization_level 0
#pragma optimize_for_size on
float fastFloorf(float value)
{
    float absoluteValue;
    float roundedValue;
    u16 shortValue;
    int integerValue;

    absoluteValue = __fabsf(value);
    if (absoluteValue < *(float*)&lbl_803E79A0) {
        fastCastFloatToU16(absoluteValue, &shortValue);
        roundedValue = fastCastU16ToFloat(&shortValue);

        if (value >= *(float*)&lbl_803E79A4) {
            return roundedValue;
        }

        if (value != -roundedValue) {
            return *(float*)&lbl_803E79A8 - roundedValue;
        }

        return -roundedValue;
    }

    if (absoluteValue < *(float*)&lbl_803E79AC) {
        integerValue = value;
        roundedValue = (float)integerValue;

        if (value >= *(float*)&lbl_803E79A4) {
            return roundedValue;
        }

        if (value != roundedValue) {
            return roundedValue - *(float*)&lbl_803E79B0;
        }

        return roundedValue;
    }

    return value;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
