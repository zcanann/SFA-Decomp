#include "dolphin/types.h"

extern const float __one_over_F[];

extern float lbl_803DC648;
extern float lbl_803DC64C;
__declspec(section ".sdata") extern float lbl_803DC650[];
__declspec(section ".sdata") extern u32 lbl_803DC658;
__declspec(section ".sdata") extern u32 lbl_803DC65C;
extern const float lbl_803E7E50;
extern const float lbl_803E7E54;
extern const float lbl_803E7E58;
extern const double lbl_803E7E60;

u32 lbl_80332C78[] = {
    0xBEC00000, 0xBEBA406C, 0xBEB48C35, 0xBEAEE32E, 0xBEA9452D, 0xBEA3B205, 0xBE9E298F, 0xBE98ABA0,
    0xBE933812, 0xBE8DCEBD, 0xBE886F7B, 0xBE831A28, 0xBE7B9D3C, 0xBE711973, 0xBE66A8B1, 0xBE5C4AB0,
    0xBE51FF2E, 0xBE47C5E9, 0xBE3D9EA1, 0xBE338918, 0xBE29850F, 0xBE1F924A, 0xBE15B08E, 0xBE0BDFA1,
    0xBE021F4A, 0xBDF0DEA4, 0xBDDD9F05, 0xBDCA7F4A, 0xBDB77F0B, 0xBDA49DE0, 0xBD91DB66, 0xBD7E6E71,
    0xBD5961ED, 0xBD349081, 0xBD0FF971, 0xBCD7380E, 0xBC8EEF19, 0xBC0E2D45, 0x38256316, 0x3C0E9C73,
    0x3C8DDD45, 0x3CD4011D, 0x3D0CDD83, 0x3D2F861E, 0x3D51FAFE, 0x3D743CBA, 0x3D8B25F6, 0x3D9C1492,
    0x3DACEA7C, 0x3DBDA7FB, 0x3DCE4D54, 0x3DDEDACE, 0x3DEF50AD, 0x3DFFAF33, 0x3E07FB51, 0x3E10139E,
    0x3E1820A0, 0x3E202276, 0x3E28193F, 0x3E30051A, 0x3E37E624, 0x3E3FBC7A, 0x3E47883A, 0x3E4F4981,
    0x3E570069, 0x3E5EAD0F, 0x3E664F8D, 0x3E6DE7FF, 0x3E75767F, 0x3E7CFB27, 0x3E823B08, 0x3E85F3AA,
    0x3E89A785, 0x3E8D56A6, 0x3E910118, 0x3E94A6E9, 0x3E984822, 0x3E9BE4D1, 0x3E9F7CFF, 0x3EA310B9,
    0x3EA6A009, 0x3EAA2AFA, 0x3EADB197, 0x3EB133EA, 0x3EB4B1FD, 0x3EB82BDC, 0x3EBBA190, 0x3EBF1322,
    0x3EC2809D, 0x3EC5EA0B, 0x3EC94F75, 0x3ECCB0E4, 0x3ED00E61, 0x3ED367F7, 0x3ED6BDAD, 0x3EDA0F8D,
    0x3EDD5DA0, 0x3EE0A7EE, 0x3EE3EE7F, 0x3EE7315D, 0x3EEA708F, 0x3EEDAC1E, 0x3EF0E412, 0x3EF41873,
    0x3EF74949, 0x3EFA769B, 0x3EFDA072, 0x3F00636A, 0x3F01F4E5, 0x3F0384AD, 0x3F0512C7, 0x3F069F35,
    0x3F0829FB, 0x3F09B31E, 0x3F0B3A9F, 0x3F0CC083, 0x3F0E44CD, 0x3F0FC781, 0x3F1148A1, 0x3F12C832,
    0x3F144636, 0x3F15C2B0, 0x3F173DA4, 0x3F18B714, 0x3F1A2F04, 0x3F1BA578, 0x3F1D1A71, 0x3F1E8DF2,
    0x3F200000, 0x3F317218, 0x3E75FDF0, 0x3D635854, 0x3C1D9561, 0x3AAEBE2F, 0x3921805E, 0x3781E214,
    0x35B3C15F, 0x33DD30D7, 0x3F7FFFFE, 0x3EFFFFFF, 0x3E2AAB03, 0x3D2AAAE6, 0x3C0874AA, 0x3AB5F6D0,
    0x3956A4B8, 0x37D5E715,
};

static inline float bit_float(u32 bits)
{
    return *(float*)&bits;
}

static inline u32 float_bits(float value)
{
    return *(u32*)&value;
}

#define bit_float(bits) (*(float*)&(bits))

static inline float int_float(s32 value)
{
    struct {
        u32 hi;
        u32 lo;
    } cvt;

    cvt.hi = 0x43300000;
    cvt.lo = value ^ 0x80000000;
    return (float)*(double*)&cvt - (float)lbl_803E7E60;
}

static inline int classify_float(float value)
{
    u32 bits;
    s32 exponent;
    u32 fraction;

    bits = float_bits(value);
    exponent = bits & 0x7F800000;

    if (exponent >= 0x7F800000) {
        if (exponent == 0x7F800000) {
            fraction = bits & 0x007FFFFF;
            if (fraction != 0) {
                return 1;
            }
            return 2;
        }
        return 4;
    }

    if (exponent == 0) {
        fraction = bits & 0x007FFFFF;
        if (fraction != 0) {
            return 5;
        }
        return 3;
    }

    return 4;
}

static inline float log2_kernel(float x, float* table)
{
    u32 bits;
    u32 fraction;
    u32 index;
    int exponent;
    float result;
    u32 log_c0_bits;
    u32 log_c1_bits;

    bits = float_bits(x);
    fraction = bits & 0x007FFFFF;
    exponent = (bits >> 23) - 0x80;
    index = fraction >> 16;
    log_c0_bits = lbl_803DC658;
    log_c1_bits = lbl_803DC65C;

    if ((bits & 0xFFFF) != 0) {
        u32 high_bits;
        u32 full_bits;
        float delta;
        float delta2;
        float log_c0;
        float log_c1;

        high_bits = (bits & 0x007F0000) | 0x3F800000;
        full_bits = fraction | 0x3F800000;

        if ((bits & 0x00008000) != 0) {
            ++index;
            high_bits += 0x10000;
        }

        log_c0 = bit_float(log_c0_bits);
        log_c1 = bit_float(log_c1_bits);
        delta = (bit_float(full_bits) - bit_float(high_bits)) * __one_over_F[index];
        delta2 = delta * delta;
        result = delta * log_c1 + log_c0;
        result = delta2 * result;
        result = lbl_803DC650[1] * delta + result;
        result = lbl_803DC650[0] * delta + result;
        result = delta + result;
        result = table[index] + result;
        result = (int_float(exponent) + lbl_803E7E54) + result;
        return result;
    }

    return (int_float(exponent) + lbl_803E7E54) + table[index];
}

#undef bit_float

static inline float exp2_kernel(float x, float* table)
{
    int exponent;
    u32 bits;
    float fraction;
    float scale;
    float poly;

    exponent = (int)x;
    fraction = x - int_float(exponent);

    if (exponent > 128) {
        return lbl_803DC64C;
    }

    if (exponent < -127) {
        return lbl_803E7E50;
    }

    bits = exponent + 127;
    bits <<= 23;
    scale = bit_float(bits);

    poly = fraction * table[137] + table[136];
    poly = fraction * poly + table[135];
    poly = fraction * poly + table[134];
    poly = fraction * poly + table[133];
    poly = fraction * poly + table[132];
    poly = fraction * poly + table[131];
    poly = fraction * poly + table[130];
    poly = fraction * poly + table[129];
    poly = fraction * poly;

    return scale * (lbl_803E7E58 + poly);
}

#define float_bits(value) (*(u32*)&(value))

float __ieee754_pow(float x, float y)
{
    float log_value;
    float* table;
    int int_y;

    table = (float*)lbl_80332C78;

    if (x > lbl_803E7E50) {
        log_value = log2_kernel(x, table);
        return exp2_kernel(y * log_value, table);
    }

    if (x < lbl_803E7E50) {
        int_y = (int)y;
        if (y - int_float(int_y) != lbl_803E7E50) {
            return lbl_803DC648;
        }

        if (int_y % 2 != 0) {
            log_value = log2_kernel(-x, table);
            return -exp2_kernel(y * log_value, table);
        }

        log_value = log2_kernel(-x, table);
        return exp2_kernel(y * log_value, table);
    }

    if (classify_float(x) == 1) {
        return x;
    }

    switch (classify_float(y)) {
    case 3:
        return lbl_803E7E58;
    case 1:
    case 2:
        return lbl_803DC648;
    case 4:
    case 5:
        if ((float_bits(x) & 0x80000000) != 0) {
            return lbl_803DC64C;
        }
        return lbl_803E7E50;
    }

    return lbl_803E7E50;
}
