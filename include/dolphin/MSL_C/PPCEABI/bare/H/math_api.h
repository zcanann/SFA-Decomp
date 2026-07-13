#ifndef DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_
#define DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_

#include "types.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"

double __fabs(double);
double __frsqrte(double x);
f32 __kernel_sin(f32 x);
f32 powf(f32 x, f32 y);
float __fabsf(float x);
float sqrtf(float x);
float fabsf(float x);
float powfBitEstimate(float x, float y);
float fn_80291FF4(float x);
float fn_802943F4(float x);
float fn_802945E0(float x);
u32 countLeadingZeros(void);

#endif /* DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_ */
