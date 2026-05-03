#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common_Embedded/Math/fdlibm.h"

double sqrt(double x) {
    return __ieee754_sqrt(x);
}
