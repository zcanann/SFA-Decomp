#include "dolphin/MSL_C/PPCEABI/bare/H/exponentialsf.h"
#include "dolphin/types.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/common_float_tables.h"

static float sLog2EMinusOne[2] = {0.41015625f, 0.0325387903f};

static float sLog2MantissaTable[129] = {
    -0.375f,        -0.36377275f,   -0.352632195f,   -0.341576993f,   -0.330605894f,  -0.319717556f,  -0.308910817f,
    -0.298184395f,  -0.287537158f,  -0.276967913f,   -0.266475528f,   -0.256058931f,  -0.245716989f,  -0.235448644f,
    -0.225252882f,  -0.21512866f,   -0.205074996f,   -0.195090905f,   -0.185175434f,  -0.175327659f,  -0.165546641f,
    -0.155831486f,  -0.146181315f,  -0.136595264f,   -0.127072483f,   -0.117612153f,  -0.108213462f,  -0.0988755971f,
    -0.089597784f,  -0.0803792477f, -0.0712192506f,  -0.0621170439f,  -0.0530719049f, -0.0440831222f, -0.0351499952f,
    -0.0262718461f, -0.017447995f,  -0.00867778528f, 3.94313465e-05f, 0.00870429259f, 0.0173174236f,  0.0258794371f,
    0.0343909375f,  0.0428525135f,  0.0512647554f,   0.0596282259f,   0.0679434985f,  0.0762111098f,  0.0844316185f,
    0.0926055536f,  0.100733429f,   0.108815774f,    0.116853096f,    0.124845885f,   0.132794634f,   0.140699834f,
    0.148561954f,   0.156381458f,   0.164158806f,    0.171894461f,    0.179588854f,   0.187242419f,   0.194855601f,
    0.202428833f,   0.209962502f,   0.217457041f,    0.224912837f,    0.232330307f,   0.239709839f,   0.24705182f,
    0.254356623f,   0.261624634f,   0.268856198f,    0.2760517f,      0.28321147f,    0.290335923f,   0.29742533f,
    0.304480106f,   0.31150052f,    0.318486959f,    0.325439721f,    0.332359135f,   0.339245528f,   0.346099198f,
    0.352920443f,   0.35970962f,    0.366466999f,    0.373192847f,    0.379887491f,   0.386551231f,   0.393184334f,
    0.399787068f,   0.406359702f,   0.412902564f,    0.419415861f,    0.425899893f,   0.432354927f,   0.438781202f,
    0.445178956f,   0.451548487f,   0.457890004f,    0.464203775f,    0.470490038f,   0.476749033f,   0.482980996f,
    0.489186138f,   0.495364726f,   0.501516938f,    0.507643044f,    0.513743222f,   0.51981777f,    0.525866807f,
    0.531890571f,   0.537889361f,   0.543863237f,    0.549812496f,    0.555737317f,   0.561637938f,   0.567514479f,
    0.573367238f,   0.579196334f,   0.585001945f,    0.590784311f,    0.59654355f,    0.602279902f,   0.607993603f,
    0.613684714f,   0.619353414f,   0.625f};
static float sExp2Polynomial[9] = {0.693147182f,   0.240226507f,    0.0555041581f,   0.00961813424f, 0.00133318256f,
                                   0.00015401977f, 1.54832742e-05f, 1.33928177e-06f, 1.02999984e-07f};
static u32 sUnusedMathData[8] = {0x3F7FFFFE, 0x3EFFFFFF, 0x3E2AAB03, 0x3D2AAAE6,
                                 0x3C0874AA, 0x3AB5F6D0, 0x3956A4B8, 0x37D5E715};

static inline u32 float_bits(float value) {
    return *(u32*)&value;
}

typedef enum FloatClass {
    FLOAT_CLASS_NAN = 1,
    FLOAT_CLASS_INFINITY = 2,
    FLOAT_CLASS_ZERO = 3,
    FLOAT_CLASS_NORMAL = 4,
    FLOAT_CLASS_SUBNORMAL = 5,
} FloatClass;

static inline FloatClass classify_float(float value) {
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

#pragma push
#pragma section sconst_type ".sdata"
static inline float log2_kernel(float value) {
    u32 bits;
    int exponent;
    u32 tableIndex;
    u32 fractionBits;
    float_word roundedMantissa;
    float coefficients[2] = {-0.72135162353515625f, 0.4808933f};
    float_word inputWord;
    float_word normalizedMantissa;
    float exponentValue;

    bits = *(u32*)&value;
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
        exponentValue = (float)exponent;
        return (exponentValue + 1.375f) + (sLog2MantissaTable[tableIndex] +
                                           (delta + (sLog2EMinusOne[0] * delta +
                                                     (sLog2EMinusOne[1] * delta +
                                                      (delta * delta) * (delta * coefficients[1] + coefficients[0])))));
    }

    exponentValue = (float)exponent;
    return (exponentValue + 1.375f) + sLog2MantissaTable[tableIndex];
}
#pragma pop

static inline float exp2_kernel(float value) {
    float_word exponentScale;
    float_word scaleCopy;
    float fraction;
    float scaleFactor;
    float polynomial;

    exponentScale.i = value;
    scaleCopy.i = exponentScale.i;
    fraction = value - (float)exponentScale.i;

    if (exponentScale.i > 128) {
        return HUGE_VALF;
    }

    if (exponentScale.i < -127) {
        return 0.0f;
    }

    exponentScale.i += 127;
    exponentScale.i <<= 23;
    scaleFactor = exponentScale.f;

    polynomial =
        fraction *
            (fraction * (fraction * (fraction * (fraction * (fraction * (fraction * (fraction * sExp2Polynomial[8] +
                                                                                     sExp2Polynomial[7]) +
                                                                         sExp2Polynomial[6]) +
                                                             sExp2Polynomial[5]) +
                                                 sExp2Polynomial[4]) +
                                     sExp2Polynomial[3]) +
                         sExp2Polynomial[2]) +
             sExp2Polynomial[1]) +
        sExp2Polynomial[0];
    polynomial = fraction * polynomial;

    return scaleFactor * (polynomial + 1.0f);
}

#define float_bits(value) (*(u32*)&(value))

#pragma optimization_level 2
#pragma opt_propagation off
float powf(float base, float power) {
    int integerPower;
    float fractionalPower;

    if (base > 0.0f) {
        power *= log2_kernel(base);
        return exp2_kernel(power);
    }

    if (base < 0.0f) {
        integerPower = power;
        fractionalPower = power - (int)power;
        if (fractionalPower) {
            return NAN;
        }

        if (integerPower % 2 != 0) {
            power *= log2_kernel(-base);
            return -exp2_kernel(power);
        }

        power *= log2_kernel(-base);
        return exp2_kernel(power);
    }

    if (classify_float(base) == FLOAT_CLASS_NAN) {
        return base;
    }

    switch (classify_float(power)) {
    case FLOAT_CLASS_ZERO:
        return 1.0f;
    case FLOAT_CLASS_NAN:
    case FLOAT_CLASS_INFINITY:
        return NAN;
    case FLOAT_CLASS_NORMAL:
    case FLOAT_CLASS_SUBNORMAL:
        if ((float_bits(base) & 0x80000000) != 0) {
            return HUGE_VALF;
        }
        return base;
    }

    return 0.0f;
}
#pragma opt_propagation reset
