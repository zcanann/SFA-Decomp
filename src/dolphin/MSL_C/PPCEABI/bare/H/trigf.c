#include <PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math.h>

float fabsf__Ff(float);

static const float tmp_float[] = {
    0.25F,
    0.023239374F,
    0.00000017055572F,
    1.867365e-11F,
};

#pragma cplusplus on
static float __four_over_pi_m1[] = {
    tmp_float[0],
    tmp_float[1],
    tmp_float[2],
    tmp_float[3],
};
#pragma cplusplus off

#define __two_over_pi 0.63661975F
#define __SQRT_FLT_EPSILON__ 3.4526698300e-4F

extern const float __sincos_poly[];
extern const float __sincos_on_quadrant[];

float sinf(float x);
float cosf(float x);
__declspec(weak) float cos__Ff(float x);
__declspec(weak) float sin__Ff(float x);

#pragma dont_inline on

float tanf(float x) { return sin__Ff(x) / cos__Ff(x); }

__declspec(weak) float cos__Ff(float x) { return cosf(x); }

__declspec(weak) float sin__Ff(float x) { return sinf(x); }

float cosf(float x)
{
    float z = __two_over_pi * x;
    int n   = ((*(int*)&x) & 0x80000000) ? (int)(z - .5f) : (int)(z + .5f);
    const float frac_part = ((((x - (float)(n * 2)) + __four_over_pi_m1[0] * x)
                               + __four_over_pi_m1[1] * x)
                              + __four_over_pi_m1[2] * x)
                             + __four_over_pi_m1[3] * x;
    float xsq;

    n &= 0x00000003;

    if (fabsf__Ff(frac_part) < __SQRT_FLT_EPSILON__) {
        n <<= 1;
        return __sincos_on_quadrant[n + 1]
               - (__sincos_on_quadrant[n] * frac_part);
    }

    xsq = frac_part * frac_part;
    if (n & 0x00000001) {
        n <<= 1;
        z = -((((__sincos_poly[1] * xsq + __sincos_poly[3]) * xsq
                + __sincos_poly[5])
                   * xsq
               + __sincos_poly[7])
                  * xsq
              + __sincos_poly[9])
            * frac_part;
        return z * __sincos_on_quadrant[n];
    }

    n <<= 1;
    z = (((__sincos_poly[0] * xsq + __sincos_poly[2]) * xsq + __sincos_poly[4])
             * xsq
         + __sincos_poly[6])
            * xsq
        + __sincos_poly[8];
    return z * __sincos_on_quadrant[n + 1];
}

float sinf(float x)
{
    float z = __two_over_pi * x;
    int n   = ((*(int*)&x) & 0x80000000) ? (int)(z - .5f) : (int)(z + .5f);
    const float frac_part = ((((x - (float)(n * 2)) + __four_over_pi_m1[0] * x)
                               + __four_over_pi_m1[1] * x)
                              + __four_over_pi_m1[2] * x)
                             + __four_over_pi_m1[3] * x;
    float xsq;

    n &= 0x00000003;

    if (fabsf__Ff(frac_part) < __SQRT_FLT_EPSILON__) {
        n <<= 1;
        return __sincos_on_quadrant[n]
               + (__sincos_on_quadrant[n + 1] * frac_part * __sincos_poly[9]);
    }

    xsq = frac_part * frac_part;
    if (n & 0x00000001) {
        n <<= 1;
        z = (((__sincos_poly[0] * xsq + __sincos_poly[2]) * xsq
              + __sincos_poly[4])
                 * xsq
             + __sincos_poly[6])
                * xsq
            + __sincos_poly[8];
        return z * __sincos_on_quadrant[n];
    }

    n <<= 1;
    z = ((((__sincos_poly[1] * xsq + __sincos_poly[3]) * xsq + __sincos_poly[5])
           * xsq
           + __sincos_poly[7])
          * xsq
         + __sincos_poly[9])
        * frac_part;
    return z * __sincos_on_quadrant[n + 1];
}

#pragma dont_inline reset
