#include "dolphin/os/OSFastCast.h"
#include "sfa_light_decls.h"




// exp2f constants
extern float lbl_803E7978;  // -127.0f
extern float lbl_803E797C;  // 0.0f
extern float lbl_803E7980;  // 1.0f
extern float lbl_803E7984;  // exp2_p0
extern float lbl_803E7988;  // exp2_p1
extern float lbl_803E798C;  // exp2_p2
extern float lbl_803E7990;  // exp2_p3
extern float lbl_803E7994;  // exp2_p4
// expf constants
extern float lbl_803E7998;  // log2e (1.4426950216293335f)
// internal floorf-like helper constants
extern float lbl_803E79A0;  // 65536.0f (small_int_limit)
extern float lbl_803E79A4;  // 0.0f
extern float lbl_803E79A8;  // -1.0f
extern float lbl_803E79AC;  // 8388608.0f (large_int_limit)
extern float lbl_803E79B0;  // 1.0f

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
    return exp2f(lbl_803E7998 * *(float*)&x);
}

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

#pragma optimization_level 0
#pragma optimize_for_size on
float fastFloorf(float x)
{
    float abs_x;
    float rounded;
    s16 short_value;
    int int_value;

    abs_x = __fabsf(x);
    if (abs_x < lbl_803E79A0) {
        fastCastFloatToU16(abs_x, &short_value);
        rounded = fastCastU16ToFloat(&short_value);

        if (x >= lbl_803E79A4) {
            return rounded;
        }

        if (x != -rounded) {
            return lbl_803E79A8 - rounded;
        }

        return -rounded;
    }

    if (abs_x < lbl_803E79AC) {
        int_value = x;
        rounded = (float)int_value;

        if (x >= lbl_803E79A4) {
            return rounded;
        }

        if (x != rounded) {
            return rounded - lbl_803E79B0;
        }

        return rounded;
    }

    return x;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
