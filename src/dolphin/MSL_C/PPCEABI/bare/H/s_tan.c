#include "PowerPC_EABI_Support/Runtime/runtime.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/s_tan.h"

extern double lbl_803E7C00;
extern double lbl_803E7C08;


double tan(int* quadrant, float angle)
{
    unsigned int roundedQuadrant;
    double absoluteAngle;
    double scaledAngle;

    absoluteAngle = __fabsf(angle);
    scaledAngle = lbl_803E7C00 * absoluteAngle;
    roundedQuadrant = (__cvt_fp2unsigned(scaledAngle) + 1) & ~1U;
    *quadrant = roundedQuadrant;
    return absoluteAngle - lbl_803E7C08 * (double)roundedQuadrant;
}
