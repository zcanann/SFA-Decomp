#ifndef DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_
#define DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_

#include "types.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"

double __fabs(double);
double __frsqrte(double x);
f32 __kernel_sin(f32 x);
f32 powf(f32 x, f32 y);
f32 powfCoreFast(f32 x, f32 y);
f32 powfCoreHighPrecision(f32 x, f32 y);
float __fabsf(float x);
float sqrtf(float x);
float expf(float x);
float fabsf(float x);
float powfBitEstimate(float base, float exponentValue);
void Vec_normalize(void* input, void* output);
void Vec_scale(void* input, void* output, float scale);
float Vec_lengthSquared(void* input);
float trigReduceQuadrant(u16* quadrant, float angle);
float fn_80291FF4(float x);
float fn_80292194(float x);
float fn_80293AC4(int angle);
void fn_80293C64(float angle, float* sinOut, float* cosOut);
float fn_80293F7C(float x);
float fn_802942EC(float x);
float mathTanf(float angle);
float fn_802945E0(float value);

#endif /* DOLPHIN_MSL_C_PPCEABI_BARE_H_MATH_API_H_ */
