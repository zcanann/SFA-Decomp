/* @(#)s_scalbn.c 1.3 95/01/18 */
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
 * scalbn (double x, int n)
 * scalbn(x,n) returns x* 2**n  computed by  exponent
 * manipulation rather than by actually performing an
 * exponentiation or a multiplication.
 */

#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/float.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common_Embedded/Math/fdlibm.h"

extern const double lbl_803E7950;
extern const double lbl_803E7958;
extern const double lbl_803E7960;
extern const double lbl_803E7968;
extern const double lbl_803E7970;

#ifdef __STDC__
    double ldexp (double x, int n)
#else
    double ldexp (x,n)
    double x; int n;
#endif
{
    int  k,hx,lx;
    if(!isfinite(x)||lbl_803E7950==x) return x;
    hx = __HI(x);
    lx = __LO(x);
        k = (hx&0x7ff00000)>>20;        /* extract exponent */
        if (k==0) {                /* 0 or subnormal x */
            if ((lx|(hx&0x7fffffff))==0) return x; /* +-0 */
        x *= lbl_803E7958;
        hx = __HI(x);
        k = ((hx&0x7ff00000)>>20) - 54;
            if (n< -50000) return lbl_803E7960*x;     /*underflow*/
        }
        if (k==0x7ff) return x+x;        /* NaN or Inf */
        k = k+n;
        if (k >  0x7fe) return lbl_803E7968*copysign(lbl_803E7968,x); /* overflow  */
        if (k > 0)                 /* normal result */
        {__HI(x) = (hx&0x800fffff)|(k<<20); return x;}
        if (k <= -54)
            if (n > 50000)     /* in case integer overflow in n+k */
        return lbl_803E7968*copysign(lbl_803E7968,x);    /*overflow*/
        else return lbl_803E7960*copysign(lbl_803E7960,x);     /*underflow*/
        k += 54;                /* subnormal result */
        __HI(x) = (hx&0x800fffff)|(k<<20);
        return lbl_803E7970*x;
}
