/* @(#)s_modf.c 1.3 95/01/18 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * modf(double x, double *iptr)
 * return fraction part of x, and return x's integral part in *iptr.
 * Method:
 *	Bit twiddling.
 *
 * Exception:
 *	No exception.
 */

#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common_Embedded/Math/fdlibm.h"

#ifdef __STDC__
static const double one = 1.0;
#else
static double one = 1.0;
#endif

#ifdef __STDC__
double modf(double x, double* iptr)
#else
double modf(x, iptr)
double x, *iptr;
#endif
{
	int i0, i1, j0;
	unsigned i;
	i0 = __HI(x);
	i1 = __LO(x);
	j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
	if (j0 < 20) {
		if (j0 < 0) {
			__HIp(iptr) = i0 & 0x80000000;
			__LOp(iptr) = 0;
			return x;
		} else {
			i = (0x000fffff) >> j0;
			if (((i0 & i) | i1) == 0) {
				*iptr = x;
				__HI(x) &= 0x80000000;
				__LO(x) = 0;
				return x;
			} else {
				__HIp(iptr) = i0 & (~i);
				__LOp(iptr) = 0;
				return x - *iptr;
			}
		}
	} else if (j0 > 51) {
		*iptr = x * one;
		__HI(x) &= 0x80000000;
		__LO(x) = 0;
		return x;
	} else {
		i = ((unsigned)(0xffffffff)) >> (j0 - 20);
		if ((i1 & i) == 0) {
			*iptr = x;
			__HI(x) &= 0x80000000;
			__LO(x) = 0;
			return x;
		} else {
			__HIp(iptr) = i0;
			__LOp(iptr) = i1 & (~i);
			return x - *iptr;
		}
	}
}
