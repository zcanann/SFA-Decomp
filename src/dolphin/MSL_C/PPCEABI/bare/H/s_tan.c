#include "PowerPC_EABI_Support/Runtime/runtime.h"

extern double lbl_803E7C00;
extern double lbl_803E7C08;


double tan(int* out_n, float x)
{
    unsigned int n;
    double ax;
    double scaled;

    ax = __fabsf(x);
    scaled = lbl_803E7C00 * ax;
    n = (__cvt_fp2unsigned(scaled) + 1) & ~1U;
    *out_n = n;
    return ax - lbl_803E7C08 * (double)n;
}
