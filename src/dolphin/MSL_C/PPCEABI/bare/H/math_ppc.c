#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math_ppc.h"
double pow(double, double);

float acosf(float arg0) {
    return (float)acos(arg0);
}

__declspec(weak) float cosf(float arg0) {
    return (float)cos(arg0);
}

__declspec(weak) float sinf(float arg0) {
    return (float)sin(arg0);
}

__declspec(weak) float tanf(float arg0) {
    return (float)tan(arg0);
}

float powf(float arg0, float arg1) {
    return (float)pow(arg0, arg1);
}
