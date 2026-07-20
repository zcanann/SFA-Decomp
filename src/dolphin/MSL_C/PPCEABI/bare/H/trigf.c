#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/hyperbolicsf.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"

#define __epsilon 3.45266983e-4f
#define __HI(x) (((s32*)&x)[0])


extern const float __sincos_on_quadrant[];
extern const float __sincos_poly[];

static const float tmp_float[] = { 0.25f, 0.0232393741608f, 1.70555722434e-7f, 1.86736494323e-11f };
static float __four_over_pi_m1[] = { 0.0f, 0.0f, 0.0f, 0.0f };

__declspec(section ".ctors") static void* const __sinit_trigf_c_reference = __sinit_trigf_c;

float tanf(float angle)
{
    float cosine = cos__Ff(angle);
    return sin__Ff(angle) / cosine;
}


float cos__Ff(float angle)
{
    return cosf(angle);
}

float sin__Ff(float angle)
{
    return sinf(angle);
}


float cosf(float angle)
{
    int quadrant;
    float reducedAngle;
    float reducedSquared;
    float scaledAngle;
    float result;

    scaledAngle = 0.63661975f * angle;
    quadrant = (__HI(angle) & 0x80000000) ? (int)(scaledAngle - 0.5f) : (int)(scaledAngle + 0.5f);

    reducedAngle = angle - quadrant * 2 + __four_over_pi_m1[0] * angle + __four_over_pi_m1[1] * angle
                 + __four_over_pi_m1[2] * angle + __four_over_pi_m1[3] * angle;
    quadrant &= 3;

    if (fabsf__Ff(reducedAngle) < __epsilon) {
        quadrant <<= 1;
        return __sincos_on_quadrant[quadrant + 1] - reducedAngle * __sincos_on_quadrant[quadrant];
    }

    reducedSquared = reducedAngle * reducedAngle;
    if (quadrant & 1) {
        quadrant <<= 1;
        result = -((((__sincos_poly[1] * reducedSquared + __sincos_poly[3]) * reducedSquared + __sincos_poly[5])
                     * reducedSquared + __sincos_poly[7])
                        * reducedSquared
                    + __sincos_poly[9])
               * reducedAngle;
        return result * __sincos_on_quadrant[quadrant];
    }

    quadrant <<= 1;
    result = (((__sincos_poly[0] * reducedSquared + __sincos_poly[2]) * reducedSquared + __sincos_poly[4])
               * reducedSquared + __sincos_poly[6])
                 * reducedSquared
             + __sincos_poly[8];
    return result * __sincos_on_quadrant[quadrant + 1];
}

float sinf(float angle)
{
    int quadrant;
    float reducedAngle;
    float reducedSquared;
    float scaledAngle;
    float result;

    scaledAngle = 0.63661975f * angle;
    quadrant = (__HI(angle) & 0x80000000) ? (int)(scaledAngle - 0.5f) : (int)(scaledAngle + 0.5f);

    reducedAngle = angle - quadrant * 2 + __four_over_pi_m1[0] * angle + __four_over_pi_m1[1] * angle
                 + __four_over_pi_m1[2] * angle + __four_over_pi_m1[3] * angle;
    quadrant &= 3;

    if (fabsf__Ff(reducedAngle) < __epsilon) {
        quadrant <<= 1;
        return __sincos_on_quadrant[quadrant]
             + (__sincos_on_quadrant[quadrant + 1] * reducedAngle * __sincos_poly[9]);
    }

    reducedSquared = reducedAngle * reducedAngle;
    if (quadrant & 1) {
        quadrant <<= 1;
        result = (((__sincos_poly[0] * reducedSquared + __sincos_poly[2]) * reducedSquared + __sincos_poly[4])
                   * reducedSquared + __sincos_poly[6])
                     * reducedSquared
                 + __sincos_poly[8];
        return result * __sincos_on_quadrant[quadrant];
    }

    quadrant <<= 1;
    result = ((((__sincos_poly[1] * reducedSquared + __sincos_poly[3]) * reducedSquared + __sincos_poly[5])
                * reducedSquared + __sincos_poly[7])
                  * reducedSquared
              + __sincos_poly[9])
           * reducedAngle;
    return result * __sincos_on_quadrant[quadrant + 1];
}

void __sinit_trigf_c(void)
{
    __four_over_pi_m1[0] = tmp_float[0];
    __four_over_pi_m1[1] = tmp_float[1];
    __four_over_pi_m1[2] = tmp_float[2];
    __four_over_pi_m1[3] = tmp_float[3];
}
