#include "dolphin/os/OSFastCast.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

extern const float sExp2UnderflowThreshold;
extern const float sExp2Zero;
extern const float sExp2One;
extern const float sExp2FractionCoeff0;
extern const float sExp2FractionCoeff1;
extern const float sExp2FractionCoeff2;
extern const float sExp2FractionCoeff3;
extern const float sExp2FractionCoeff4;
extern const float sExpLog2EWithTail[2];
extern const float sFastFloorU16Limit;
extern const float sFastFloorZero;
extern const float sFastFloorNegativeOne;
extern const float sFastFloorIntegerLimit;
extern const float sFastFloorOne;

float fabsf(float value) {
    double magnitude = __fabs(value);
    return magnitude;
}

float fastCastU16ToFloat(const u16* input) {
    register const u16* ptr = input;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_U16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToU16(float value, u16* output) {
    register u16* ptr = output;
    register float input = value;

    asm {
        fmr f31, input
        psq_st f31, 0(ptr), 1, OS_FASTCAST_U16
    }
}

#pragma optimization_level 0
#pragma optimize_for_size on
float exp2f(float value) {
    s16 exponent;
    float integerPart;
    float fraction;
    union {
        float value;
        u32 bits;
    } result;

    if (value < sExp2UnderflowThreshold) {
        return sExp2Zero;
    }

    fastCastFloatToS16(value, &exponent);
    integerPart = fastCastS16ToFloat(&exponent);
    fraction = value - integerPart;

    if (fraction != sExp2Zero) {
        if (value < sExp2Zero) {
            exponent--;
            fraction += sExp2One;
        }

        result.value =
            (((sExp2FractionCoeff4 * fraction + sExp2FractionCoeff3) * fraction + sExp2FractionCoeff2) * fraction +
             sExp2FractionCoeff1) *
                fraction +
            sExp2FractionCoeff0;
    } else {
        result.value = sExp2One;
    }

    /* Scale the fractional approximation by adjusting its binary32 exponent. */
    result.bits += (u32)exponent << 23;
    return result.value;
}
#pragma optimize_for_size reset
#pragma optimization_level reset

float expf(float value) {
    return exp2f(sExpLog2EWithTail[0] * *(float*)&value);
}

const float sExp2UnderflowThreshold = -127.0f;
const float sExp2Zero = 0.0f;
const float sExp2One = 1.0f;
const float sExp2FractionCoeff0 = 1.0000035762786865f;
const float sExp2FractionCoeff1 = 0.692969560623169f;
const float sExp2FractionCoeff2 = 0.24162131547927856f;
const float sExp2FractionCoeff3 = 0.05171773582696915f;
const float sExp2FractionCoeff4 = 0.013683983124792576f;
/* Only the first word is consumed; retain the zero tail without assigning it a role. */
const float sExpLog2EWithTail[2] = {1.4426950216293335f, 0.0f};

float fastCastS16ToFloat(const s16* input) {
    register const s16* ptr = input;
    register float result;

    asm {
        psq_l f31, 0(ptr), 1, OS_FASTCAST_S16
        fmr result, f31
    }

    return result;
}

void fastCastFloatToS16(float value, s16* output) {
    register s16* ptr = output;
    register float input = value;

    asm {
        fmr f31, input
        psq_st f31, 0(ptr), 1, OS_FASTCAST_S16
    }
}

const float sFastFloorU16Limit = 65536.0f;
const float sFastFloorZero = 0.0f;
const float sFastFloorNegativeOne = -1.0f;
const float sFastFloorIntegerLimit = 8388608.0f;
const float sFastFloorOne = 1.0f;
const float lbl_803E79B4 = 0.0f;

#pragma optimization_level 0
#pragma optimize_for_size on
float fastFloorf(float value) {
    float absoluteValue;
    float roundedValue;
    u16 shortValue;
    int integerValue;

    absoluteValue = __fabsf(value);
    if (absoluteValue < *(float*)&sFastFloorU16Limit) {
        fastCastFloatToU16(absoluteValue, &shortValue);
        roundedValue = fastCastU16ToFloat(&shortValue);

        if (value >= *(float*)&sFastFloorZero) {
            return roundedValue;
        }

        if (value != -roundedValue) {
            return *(float*)&sFastFloorNegativeOne - roundedValue;
        }

        return -roundedValue;
    }

    if (absoluteValue < *(float*)&sFastFloorIntegerLimit) {
        integerValue = value;
        roundedValue = (float)integerValue;

        if (value >= *(float*)&sFastFloorZero) {
            return roundedValue;
        }

        if (value != roundedValue) {
            return roundedValue - *(float*)&sFastFloorOne;
        }

        return roundedValue;
    }

    return value;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
