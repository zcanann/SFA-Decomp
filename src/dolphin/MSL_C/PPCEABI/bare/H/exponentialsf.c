#include "dolphin/types.h"

extern const float __one_over_F[];

extern const float lbl_803E7E50;
extern const float lbl_803E7E54;
extern const float lbl_803E7E58;
extern const double lbl_803E7E60;
extern float lbl_803DC648;
extern float lbl_803DC64C;
__declspec(section ".sdata") extern float lbl_803DC650[];
__declspec(section ".sdata") extern u32 lbl_803DC658;
__declspec(section ".sdata") extern u32 lbl_803DC65C;

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

static inline u32 float_bits(float value)
{
    return *(u32*)&value;
}

typedef enum FloatClass {
    FLOAT_CLASS_NAN = 1,
    FLOAT_CLASS_INFINITY = 2,
    FLOAT_CLASS_ZERO = 3,
    FLOAT_CLASS_NORMAL = 4,
    FLOAT_CLASS_SUBNORMAL = 5,
} FloatClass;

static inline FloatClass classify_float(float value)
{
    u32 bits;
    s32 fraction;

    bits = float_bits(value);

    switch ((s32)(bits & 0x7F800000)) {
    case 0x7F800000:
        fraction = bits & 0x007FFFFF;
        if (fraction != 0) {
            return FLOAT_CLASS_NAN;
        }
        return FLOAT_CLASS_INFINITY;
    case 0:
        fraction = bits & 0x007FFFFF;
        if (fraction != 0) {
            return FLOAT_CLASS_SUBNORMAL;
        }
        return FLOAT_CLASS_ZERO;
    default:
        return FLOAT_CLASS_NORMAL;
    }
}

typedef union {
    float f;
    long i;
} float_word;

static inline float log2_kernel(float value, const float* table)
{
    u32 bits;
    int exponent;
    u32 tableIndex;
    u32 fractionBits;
    float_word roundedMantissa;
    float_word coef0;
    float_word coef1;
    float_word inputWord;
    float_word normalizedMantissa;

    bits = *(u32*)&value;
    coef0.i = lbl_803DC658;
    coef1.i = lbl_803DC65C;
    exponent = (bits >> 23) - 0x80;
    fractionBits = bits;
    fractionBits &= 0x007FFFFF;
    tableIndex = fractionBits >> 16;

    if ((bits & 0xFFFF) != 0) {
        float delta;

        inputWord.i = bits;
        roundedMantissa.i = (bits & 0x007F0000) | 0x3F800000;
        normalizedMantissa.i = fractionBits | 0x3F800000;

        if ((bits & 0x00008000) != 0) {
            ++tableIndex;
            roundedMantissa.i += 0x10000;
        }

        delta = normalizedMantissa.f - roundedMantissa.f;
        delta *= __one_over_F[tableIndex];
        return ((float)exponent + lbl_803E7E54)
             + (table[tableIndex]
                + (delta
                   + (lbl_803DC650[0] * delta
                      + (lbl_803DC650[1] * delta + (delta * delta) * (delta * coef1.f + coef0.f)))));
    }

    return ((float)exponent + lbl_803E7E54) + table[tableIndex];
}

static inline float exp2_kernel(float value, const float* table)
{
    float_word exponentScale;
    float_word scaleCopy;
    float fraction;
    float scaleFactor;
    float polynomial;

    exponentScale.i = value;
    scaleCopy.i = exponentScale.i;
    fraction = value - (float)exponentScale.i;

    if (exponentScale.i > 128) {
        return lbl_803DC64C;
    }

    if (exponentScale.i < -127) {
        return 0.0f;
    }

    exponentScale.i += 127;
    exponentScale.i <<= 23;
    scaleFactor = exponentScale.f;

    polynomial = fraction
         * (fraction
                * (fraction
                       * (fraction
                              * (fraction
                                     * (fraction * (fraction * (fraction * table[137] + table[136]) + table[135])
                                            + table[134])
                                     + table[133])
                              + table[132])
                       + table[131])
                + table[130])
         + table[129];
    polynomial = fraction * polynomial;

    return scaleFactor * (polynomial + lbl_803E7E58);
}

#define float_bits(value) (*(u32*)&(value))

#pragma optimization_level 2
#pragma opt_propagation off
float powf(float base, float power)
{
    const float* table;
    int integerPower;
    float fractionalPower;

    table = (const float*)lbl_80332C78;

    if (base > lbl_803E7E50) {
        power *= log2_kernel(base, table);
        return exp2_kernel(power, table);
    }

    if (base < lbl_803E7E50) {
        integerPower = power;
        fractionalPower = power - (float)integerPower;
        if (fractionalPower != lbl_803E7E50) {
            return lbl_803DC648;
        }

        if (integerPower % 2 != 0) {
            power *= log2_kernel(-base, table);
            return -exp2_kernel(power, table);
        }

        power *= log2_kernel(-base, table);
        return exp2_kernel(power, table);
    }

    if (classify_float(base) == FLOAT_CLASS_NAN) {
        return base;
    }

    switch (classify_float(power)) {
    case FLOAT_CLASS_ZERO:
        return 1.0f;
    case FLOAT_CLASS_NAN:
    case FLOAT_CLASS_INFINITY:
        return lbl_803DC648;
    case FLOAT_CLASS_NORMAL:
    case FLOAT_CLASS_SUBNORMAL:
        if ((float_bits(base) & 0x80000000) != 0) {
            return lbl_803DC64C;
        }
        return base;
    }

    return 0.0f;
}
#pragma opt_propagation reset

const float lbl_803E7E50 = 0.0f;
const float lbl_803E7E54 = 1.375f;
const float lbl_803E7E58 = 1.0f;
const double lbl_803E7E60 = 4503601774854144.0;
