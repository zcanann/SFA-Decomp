#include "dolphin.h"

#define __epsilon 3.45266983e-4f
#define __HI(x) (((s32*)&x)[0])

extern float __fabsf(float x);
extern const float __sincos_on_quadrant[];
extern const float __sincos_poly[];

static void __sinit_trigf_c(void);
float sinf(float x);
float cosf(float x);
float sin__Ff(float x);
float cos__Ff(float x);

static const float tmp_float[] = { 0.25f, 0.0232393741608f, 1.70555722434e-7f, 1.86736494323e-11f };
static float __four_over_pi_m1[] = { 0.0f, 0.0f, 0.0f, 0.0f };

__declspec(section ".ctors") static void* const __sinit_trigf_c_reference = __sinit_trigf_c;

float tanf(float x)
{
    float c = cos__Ff(x);
    return sin__Ff(x) / c;
}

#pragma dont_inline on

float cos__Ff(float x)
{
    return cosf(x);
}

float sin__Ff(float x)
{
    return sinf(x);
}

#pragma dont_inline reset

float cosf(float x)
{
    int n;
    float y;
    float ysq;
    float z;

    z = 0.63661975f * x;
    n = (__HI(x) & 0x80000000) ? (int)(z - 0.5f) : (int)(z + 0.5f);

    y = x - n * 2 + __four_over_pi_m1[0] * x + __four_over_pi_m1[1] * x + __four_over_pi_m1[2] * x + __four_over_pi_m1[3] * x;
    n &= 3;

    if (__fabsf(y) < __epsilon) {
        n <<= 1;
        return __sincos_on_quadrant[n + 1] - y * __sincos_on_quadrant[n];
    }

    ysq = y * y;
    if (n & 1) {
        n <<= 1;
        z = -((((__sincos_poly[1] * ysq + __sincos_poly[3]) * ysq + __sincos_poly[5]) * ysq + __sincos_poly[7]) * ysq
              + __sincos_poly[9])
            * y;
        return z * __sincos_on_quadrant[n];
    }

    n <<= 1;
    z = (((__sincos_poly[0] * ysq + __sincos_poly[2]) * ysq + __sincos_poly[4]) * ysq + __sincos_poly[6]) * ysq
        + __sincos_poly[8];
    return z * __sincos_on_quadrant[n + 1];
}

float sinf(float x)
{
    int n;
    float y;
    float ysq;
    float z;

    z = 0.63661975f * x;
    n = (__HI(x) & 0x80000000) ? (int)(z - 0.5f) : (int)(z + 0.5f);

    y = x - n * 2 + __four_over_pi_m1[0] * x + __four_over_pi_m1[1] * x + __four_over_pi_m1[2] * x + __four_over_pi_m1[3] * x;
    n &= 3;

    if (__fabsf(y) < __epsilon) {
        n <<= 1;
        return __sincos_on_quadrant[n] + (__sincos_on_quadrant[n + 1] * y * __sincos_poly[9]);
    }

    ysq = y * y;
    if (n & 1) {
        n <<= 1;
        z = (((__sincos_poly[0] * ysq + __sincos_poly[2]) * ysq + __sincos_poly[4]) * ysq + __sincos_poly[6]) * ysq
            + __sincos_poly[8];
        return z * __sincos_on_quadrant[n];
    }

    n <<= 1;
    z = ((((__sincos_poly[1] * ysq + __sincos_poly[3]) * ysq + __sincos_poly[5]) * ysq + __sincos_poly[7]) * ysq
         + __sincos_poly[9])
        * y;
    return z * __sincos_on_quadrant[n + 1];
}

static void __sinit_trigf_c(void)
{
    __four_over_pi_m1[0] = tmp_float[0];
    __four_over_pi_m1[1] = tmp_float[1];
    __four_over_pi_m1[2] = tmp_float[2];
    __four_over_pi_m1[3] = tmp_float[3];
}
