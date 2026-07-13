#ifndef DOLPHIN_MSL_C_PPCEABI_BARE_H_TRIG_FLOAT_HELPERS_H_
#define DOLPHIN_MSL_C_PPCEABI_BARE_H_TRIG_FLOAT_HELPERS_H_

#include "types.h"

float fn_80292DEC(float x);
void fn_80292E20(int angle, float* sinOut, float* cosOut);
void fn_80293018(int angle, float* sinOut, float* cosOut);

void angleToVec2(int angle, f32* cosOut, f32* sinOut);

#endif
