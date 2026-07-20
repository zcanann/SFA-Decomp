#ifndef DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_FLOAT_HELPERS_H_
#define DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_FLOAT_HELPERS_H_

#include "dolphin/types.h"

float fastCastS16ToFloat(const s16* input);
void fastCastFloatToS16(float value, s16* output);
float fastCastU16ToFloat(const u16* input);
void fastCastFloatToU16(float value, u16* output);

float fastFloorf(float value);

#endif
