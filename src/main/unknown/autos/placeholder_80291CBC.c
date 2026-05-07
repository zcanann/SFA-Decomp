#include "dolphin/types.h"
#include "dolphin/os/OSFastCast.h"

extern double __fabs(double);
extern float __fabsf(float);

// fn_80291D00 constants
extern float lbl_803E7978;  // -127.0f
extern float lbl_803E797C;  // 0.0f
extern float lbl_803E7980;  // 1.0f
extern float lbl_803E7984;  // exp2_p0
extern float lbl_803E7988;  // exp2_p1
extern float lbl_803E798C;  // exp2_p2
extern float lbl_803E7990;  // exp2_p3
extern float lbl_803E7994;  // exp2_p4
// fn_80291DD8 constants
extern float lbl_803E7998;  // log2e (1.4426950216293335f)
// fn_80291E40 constants
extern float lbl_803E79A0;  // 65536.0f (small_int_limit)
extern float lbl_803E79A4;  // 0.0f
extern float lbl_803E79A8;  // -1.0f
extern float lbl_803E79AC;  // 8388608.0f (large_int_limit)
extern float lbl_803E79B0;  // 1.0f

float fn_80291CBC(float x)
{
    double y = __fabs(x);
    return y;
}

float fn_80291CC8(s16* p)
{
    register s16* ptr = p;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_U16
        fmr result, f31
    }

    return result;
}

void fn_80291CE4(s16* p, float x)
{
    register s16* ptr = p;
    register float value = x;

    asm {
        fmr f31, value
        psq_st f31, 0(ptr), 1, OS_FASTCAST_U16
    }
}

float fn_80291E08(s16* p);
void fn_80291E24(s16* p, float x);

float fn_80291D00(float x)
{
    s16 exponent;
    register float input = x;
    register float integer_part;
    register float fraction;
    float result;
    u32 bits;

    if (input < lbl_803E7978) {
        return lbl_803E797C;
    }

    fn_80291E24(&exponent, input);
    integer_part = fn_80291E08(&exponent);
    fraction = input - integer_part;

    if (fraction != lbl_803E797C) {
        if (input < lbl_803E797C) {
            exponent--;
            fraction += lbl_803E7980;
        }

        result = (((lbl_803E7994 * fraction + lbl_803E7990) * fraction + lbl_803E798C) * fraction + lbl_803E7988)
               * fraction + lbl_803E7984;
    } else {
        result = lbl_803E7980;
    }

    bits = *(u32*)&result + ((u32)exponent << 23);
    *(u32*)&result = bits;
    return result;
}

float fn_80291DD8(float x)
{
    volatile float y = x;
    return fn_80291D00(lbl_803E7998 * y);
}

float fn_80291E08(s16* p)
{
    register s16* ptr = p;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_S16
        fmr result, f31
    }

    return result;
}

void fn_80291E24(s16* p, float x)
{
    register s16* ptr = p;
    register float value = x;

    asm {
        fmr f31, value
        psq_st f31, 0(ptr), 1, OS_FASTCAST_S16
    }
}

float fn_80291E40(float x)
{
    register float input = x;
    register float abs_x;
    register float rounded;
    s16 short_value;
    int int_value;

    abs_x = __fabsf(input);
    if (abs_x < lbl_803E79A0) {
        fn_80291CE4(&short_value, abs_x);
        rounded = fn_80291CC8(&short_value);

        if (input >= lbl_803E79A4) {
            return rounded;
        }

        if (input != -rounded) {
            return lbl_803E79A8 - rounded;
        }

        return -rounded;
    }

    if (abs_x < lbl_803E79AC) {
        int_value = (int)input;
        rounded = (float)int_value;

        if (input >= lbl_803E79A4) {
            return rounded;
        }

        if (input != rounded) {
            return rounded - lbl_803E79B0;
        }

        return rounded;
    }

    return input;
}
