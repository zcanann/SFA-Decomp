#ifndef DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_FLOAT_HELPERS_H_
#define DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_FLOAT_HELPERS_H_

#include "dolphin/types.h"

float fastCastS16ToFloat(s16* p);
void fastCastFloatToS16(float x, s16* p);
float fastCastU16ToFloat(u16* p);
void fastCastFloatToU16(float x, u16* p);

float fastFloorf(float x);

#endif
