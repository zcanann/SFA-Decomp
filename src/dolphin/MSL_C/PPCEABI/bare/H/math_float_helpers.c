typedef signed short s16;
typedef unsigned int u32;

extern double __fabs(double);
extern float __fabsf(float);

static const float min_exp2_arg = -127.0f;
static const float zero = 0.0f;
static const float one = 1.0f;
static const float exp2_p0 = 1.0000035762786865f;
static const float exp2_p1 = 0.692969560623169f;
static const float exp2_p2 = 0.24162131547927856f;
static const float exp2_p3 = 0.05171773582696915f;
static const float exp2_p4 = 0.013683983124792576f;
static const float log2e = 1.4426950216293335f;
static const float small_int_limit = 65536.0f;
static const float large_int_limit = 8388608.0f;

float fn_80291CBC(float x)
{
    double y = __fabs(x);
    return y;
}

asm float fn_80291CC8(register s16* p)
{
    nofralloc
    stwu r1, -24(r1)
    stfd f31, 16(r1)
    psq_l f31, 0(r3), 1, 3
    fmr f1, f31
    lfd f31, 16(r1)
    addi r1, r1, 24
    blr
}

asm void fn_80291CE4(register s16* p, register float x)
{
    nofralloc
    stwu r1, -24(r1)
    stfd f31, 16(r1)
    fmr f31, f1
    psq_st f31, 0(r3), 1, 3
    lfd f31, 16(r1)
    addi r1, r1, 24
    blr
}

float fn_80291E08(s16* p);
void fn_80291E24(s16* p, float x);

float fn_80291D00(float x)
{
    s16 exponent;
    float integer_part;
    float fraction;
    float result;
    u32 bits;

    if (x < min_exp2_arg) {
        return zero;
    }

    fn_80291E24(&exponent, x);
    integer_part = fn_80291E08(&exponent);
    fraction = x - integer_part;

    if (fraction != zero) {
        if (x < zero) {
            exponent--;
            fraction += one;
        }

        result = (((exp2_p4 * fraction + exp2_p3) * fraction + exp2_p2) * fraction + exp2_p1)
               * fraction + exp2_p0;
    } else {
        result = one;
    }

    bits = *(u32*)&result + ((u32)exponent << 23);
    *(u32*)&result = bits;
    return result;
}

float fn_80291DD8(float x)
{
    volatile float y = x;
    return fn_80291D00(log2e * y);
}

asm float fn_80291E08(register s16* p)
{
    nofralloc
    stwu r1, -24(r1)
    stfd f31, 16(r1)
    psq_l f31, 0(r3), 1, 5
    fmr f1, f31
    lfd f31, 16(r1)
    addi r1, r1, 24
    blr
}

asm void fn_80291E24(register s16* p, register float x)
{
    nofralloc
    stwu r1, -24(r1)
    stfd f31, 16(r1)
    fmr f31, f1
    psq_st f31, 0(r3), 1, 5
    lfd f31, 16(r1)
    addi r1, r1, 24
    blr
}

float fn_80291E40(float x)
{
    float abs_x;
    float rounded;
    s16 short_value;
    int int_value;

    abs_x = __fabsf(x);
    if (abs_x < small_int_limit) {
        fn_80291CE4(&short_value, abs_x);
        rounded = fn_80291CC8(&short_value);

        if (x >= zero) {
            return rounded;
        }

        if (x != -rounded) {
            return -one - rounded;
        }

        return -rounded;
    }

    if (abs_x < large_int_limit) {
        int_value = (int)x;
        rounded = (float)int_value;

        if (x >= zero) {
            return rounded;
        }

        if (x != rounded) {
            return rounded - one;
        }

        return rounded;
    }

    return x;
}
