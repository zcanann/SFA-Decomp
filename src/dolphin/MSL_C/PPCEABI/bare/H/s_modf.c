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
	double modf(double x, double *iptr)
#else
	double modf(x, iptr)
	double x,*iptr;
#endif
{
	int i0,i1,j0;
	unsigned i;
	i0 =  __HI(x);		/* high x */
	i1 =  __LO(x);		/* low  x */
	j0 = ((i0>>20)&0x7ff)-0x3ff;	/* exponent of x */
	if(j0<20) {			/* integer part in high x */
	    if(j0<0) {			/* |x|<1 */
		__HIp(iptr) = i0&0x80000000;
		__LOp(iptr) = 0;		/* *iptr = +-0 */
		return x;
	    } else {
		i = (0x000fffff)>>j0;
		if(((i0&i)|i1)==0) {		/* x is integral */
		    *iptr = x;
		    __HI(x) &= 0x80000000;
		    __LO(x)  = 0;	/* return +-0 */
		    return x;
		} else {
		    __HIp(iptr) = i0&(~i);
		    __LOp(iptr) = 0;
		    return x - *iptr;
		}
	    }
	} else if (j0>51) {		/* no fraction part */
	    *iptr = x*one;
	    __HI(x) &= 0x80000000;
	    __LO(x)  = 0;	/* return +-0 */
	    return x;
	} else {			/* fraction part in low x */
	    i = ((unsigned)(0xffffffff))>>(j0-20);
	    if((i1&i)==0) { 		/* x is integral */
		*iptr = x;
		__HI(x) &= 0x80000000;
		__LO(x)  = 0;	/* return +-0 */
		return x;
	    } else {
		__HIp(iptr) = i0;
		__LOp(iptr) = i1&(~i);
		return x - *iptr;
	    }
	}
}

/* additional helpers occupying the rest of v1.0's s_modf TU */

void _savefpr_29(void);
void _restfpr_29(void);

extern const float lbl_803E7978;
extern const float lbl_803E797C;
extern const float lbl_803E7980;
extern const float lbl_803E7984;
extern const float lbl_803E7988;
extern const float lbl_803E798C;
extern const float lbl_803E7990;
extern const float lbl_803E7994;
extern const float lbl_803E7998;
extern const float lbl_803E79A0;
extern const float lbl_803E79A4;
extern const float lbl_803E79A8;
extern const float lbl_803E79AC;
extern const float lbl_803E79B0;
extern const double lbl_803E79B8;

asm float fn_80291CBC(float x) {
    nofralloc
    fabs f0, f1
    frsp f1, f0
    blr
}

asm float fn_80291CC8(short* p) {
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    psq_l f31, 0(r3), 1, 3
    fmr f1, f31
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
}

asm void fn_80291CE4(short* p, float x) {
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    fmr f31, f1
    psq_st f31, 0(r3), 1, 3
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
}

asm float fn_80291E08(short* p);
asm float fn_80291E24(short* p, float x);

asm float fn_80291D00(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_29
    fmr f30, f1
    lfs f0, lbl_803E7978(r0)
    fcmpo cr0, f30, f0
    bge _d00_0
    lfs f1, lbl_803E797C(r0)
    b _d00_end
_d00_0:
    fmr f1, f30
    addi r3, r1, 0x10
    bl fn_80291E24
    addi r3, r1, 0x10
    bl fn_80291E08
    fmr f29, f1
    fsubs f31, f30, f29
    lfs f0, lbl_803E797C(r0)
    fcmpu cr0, f31, f0
    beq _d00_eq
    lfs f0, lbl_803E797C(r0)
    fcmpo cr0, f30, f0
    bge _d00_skip
    lha r3, 0x10(r1)
    subi r0, r3, 0x1
    sth r0, 0x10(r1)
    lfs f0, lbl_803E7980(r0)
    fadds f31, f31, f0
_d00_skip:
    lfs f1, lbl_803E7994(r0)
    lfs f0, lbl_803E7990(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E798C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7988(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7984(r0)
    fmadds f0, f31, f1, f0
    stfs f0, 0xc(r1)
    b _d00_combine
_d00_eq:
    lfs f0, lbl_803E7980(r0)
    stfs f0, 0xc(r1)
_d00_combine:
    lwz r3, 0xc(r1)
    lha r0, 0x10(r1)
    slwi r0, r0, 23
    add r0, r3, r0
    stw r0, 0xc(r1)
    lfs f1, 0xc(r1)
_d00_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_29
    addi r1, r1, 0x30
    mtlr r0
    blr
}

asm float fn_80291DD8(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x10(r1)
    stfs f1, 0x8(r1)
    lfs f1, lbl_803E7998(r0)
    lfs f0, 0x8(r1)
    fmuls f1, f1, f0
    bl fn_80291D00
    lwz r0, 0x14(r1)
    addi r1, r1, 0x10
    mtlr r0
    blr
}

asm float fn_80291E08(short* p) {
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    psq_l f31, 0(r3), 1, 5
    fmr f1, f31
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
}

asm float fn_80291E24(short* p, float x) {
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    fmr f31, f1
    psq_st f31, 0(r3), 1, 5
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
}

asm float fn_80291E40(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x40(r1)
    addi r11, r1, 0x40
    bl _savefpr_29
    stw r31, 0x24(r1)
    fmr f30, f1
    fabs f29, f30
    lfs f0, lbl_803E79A0(r0)
    fcmpo cr0, f29, f0
    bge _e40_big
    fmr f1, f29
    addi r3, r1, 0xc
    bl fn_80291CE4
    addi r3, r1, 0xc
    bl fn_80291CC8
    fmr f31, f1
    lfs f0, lbl_803E79A4(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _e40_neg
    fmr f1, f31
    b _e40_end
_e40_neg:
    fneg f0, f31
    fcmpu cr0, f30, f0
    beq _e40_neg2
    lfs f0, lbl_803E79A8(r0)
    fsubs f1, f0, f31
    b _e40_end
_e40_neg2:
    fneg f1, f31
    b _e40_end
_e40_big:
    lfs f0, lbl_803E79AC(r0)
    fcmpo cr0, f29, f0
    bge _e40_huge
    fctiwz f0, f30
    stfd f0, 0x18(r1)
    lwz r31, 0x1c(r1)
    lfd f1, lbl_803E79B8(r0)
    xoris r0, r31, 0x8000
    stw r0, 0x14(r1)
    lis r0, 0x4330
    stw r0, 0x10(r1)
    lfd f0, 0x10(r1)
    fsubs f31, f0, f1
    lfs f0, lbl_803E79A4(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _e40_big_neg
    fmr f1, f31
    b _e40_end
_e40_big_neg:
    fcmpu cr0, f30, f31
    beq _e40_big_eq
    lfs f0, lbl_803E79B0(r0)
    fsubs f1, f31, f0
    b _e40_end
_e40_big_eq:
    fmr f1, f31
    b _e40_end
_e40_huge:
    fmr f1, f30
_e40_end:
    lwz r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _restfpr_29
    lwz r31, 0x24(r1)
    addi r1, r1, 0x40
    mtlr r0
    blr
}
