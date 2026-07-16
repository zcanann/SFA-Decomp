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

float fabsf(float x)
{
    double y = __fabs(x);
    return y;
}

float fastCastU16ToFloat(s16* p)
{
    register s16* ptr = p;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_U16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToU16(float x, s16* p)
{
    register s16* ptr = p;
    register float value = x;

    asm {
        fmr f31, value
        psq_st f31, 0(ptr), 1, OS_FASTCAST_U16
    }
}

float fastCastS16ToFloat(s16* p);
void fastCastFloatToS16(float x, s16* p);

#pragma optimization_level 0
#pragma optimize_for_size on
float exp2f(float x)
{
    s16 exponent;
    float integer_part;
    float fraction;
    float result;

    if (x < lbl_803E7978) {
        return lbl_803E797C;
    }

    fastCastFloatToS16(x, &exponent);
    integer_part = fastCastS16ToFloat(&exponent);
    fraction = x - integer_part;

    if (fraction != lbl_803E797C) {
        if (x < lbl_803E797C) {
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

float expf(float x)
{
    return exp2f(lbl_803E7998[0] * *(float*)&x);
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

float fastCastS16ToFloat(s16* p)
{
    register s16* ptr = p;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_S16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToS16(float x, s16* p)
{
    register s16* ptr = p;
    register float value = x;

    asm {
        fmr f31, value
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
float fastFloorf(float x)
{
    float abs_x;
    float rounded;
    s16 short_value;
    int int_value;

    abs_x = __fabsf(x);
    if (abs_x < *(float*)&lbl_803E79A0) {
        fastCastFloatToU16(abs_x, &short_value);
        rounded = fastCastU16ToFloat(&short_value);

        if (x >= *(float*)&lbl_803E79A4) {
            return rounded;
        }

        if (x != -rounded) {
            return *(float*)&lbl_803E79A8 - rounded;
        }

        return -rounded;
    }

    if (abs_x < *(float*)&lbl_803E79AC) {
        int_value = x;
        rounded = (float)int_value;

        if (x >= *(float*)&lbl_803E79A4) {
            return rounded;
        }

        if (x != rounded) {
            return rounded - *(float*)&lbl_803E79B0;
        }

        return rounded;
    }

    return x;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
