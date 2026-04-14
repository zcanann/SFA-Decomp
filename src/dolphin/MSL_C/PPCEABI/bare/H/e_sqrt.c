#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common_Embedded/Math/fdlibm.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/errno.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math.h"

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
double __ieee754_sqrt(double x) {
    unsigned r;
    unsigned t1;
    unsigned s1;
    unsigned ix1;
    unsigned q1;
    int ix0;
    int s0;
    int q;
    int m;
    int t;
    int i;
    double z;
    const double one = 1.0;
    const double tiny = 1.0e-300;

    ix0 = __HI(x);
    ix1 = __LO(x);

    if ((ix0 & 0x7ff00000) == 0x7ff00000) {
        errno = 0x21;
        return x * x + x;
    }

    if (ix0 <= 0) {
        if ((ix1 | (ix0 & (~0x80000000))) == 0) {
            return x;
        }
        if (ix0 < 0) {
            errno = 0x21;
            return NAN;
        }
    }

    m = (ix0 >> 20);
    if (m == 0) {
        while (ix0 == 0) {
            m -= 21;
            ix0 |= (ix1 >> 11);
            ix1 <<= 21;
        }

        for (i = 0; (ix0 & 0x00100000) == 0; i++) {
            ix0 <<= 1;
        }
        m -= i - 1;
        ix0 |= (ix1 >> (32 - i));
        ix1 <<= i;
    }

    m -= 1023;
    ix0 = (ix0 & 0x000fffff) | 0x00100000;
    if (m & 1) {
        ix0 += ix0 + ((ix1 & 0x80000000) >> 31);
        ix1 += ix1;
    }
    m >>= 1;

    ix0 += ix0 + ((ix1 & 0x80000000) >> 31);
    ix1 += ix1;
    q = q1 = s0 = s1 = 0;
    r = 0x00200000;

    while (r != 0) {
        t = s0 + r;
        if (t <= ix0) {
            s0 = t + r;
            ix0 -= t;
            q += r;
        }
        ix0 += ix0 + ((ix1 & 0x80000000) >> 31);
        ix1 += ix1;
        r >>= 1;
    }

    r = 0x80000000;
    while (r != 0) {
        t1 = s1 + r;
        t = s0;
        if ((t < ix0) || ((t == ix0) && (t1 <= ix1))) {
            s1 = t1 + r;
            if (((t1 & 0x80000000) == 0x80000000) && ((s1 & 0x80000000) == 0)) {
                s0 += 1;
            }
            ix0 -= t;
            if (ix1 < t1) {
                ix0 -= 1;
            }
            ix1 -= t1;
            q1 += r;
        }
        ix0 += ix0 + ((ix1 & 0x80000000) >> 31);
        ix1 += ix1;
        r >>= 1;
    }

    if ((ix0 | ix1) != 0) {
        z = 1.0 - tiny;
        if (z >= 1.0) {
            z = 1.0 + tiny;
            if (q1 == 0xffffffff) {
                q1 = 0;
                q += 1;
            } else {
                q1 += (q1 & 1);
            }
        }
    }

    ix0 = (q >> 1) + 0x3fe00000;
    ix1 = q1 >> 1;
    if ((q & 1) == 1) {
        ix1 |= 0x80000000;
    }
    ix0 += (m << 20);
    __HI(z) = ix0;
    __LO(z) = ix1;
    return z;
}
