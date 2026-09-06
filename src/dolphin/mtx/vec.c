#include "dolphin/mtx/vec.h"

#define qr0 0

asm void PSVECAdd(const register Vec* vec1, const register Vec* vec2, register Vec* ret) {
#ifdef __MWERKS__ // clang-format off
	nofralloc;
	psq_l     f2, Vec.x(vec1), 0, qr0;
	psq_l     f4, Vec.x(vec2), 0, qr0;
	ps_add    f6, f2, f4;
	psq_st    f6, Vec.x(ret), 0, qr0;
	psq_l     f3, Vec.z(vec1), 1, qr0;
	psq_l     f5, Vec.z(vec2), 1, qr0;
	ps_add    f7, f3, f5;
	psq_st    f7, Vec.z(ret), 1, qr0;
	blr
#endif // clang-format on
}

asm void PSVECSubtract(const register Vec* vec1, const register Vec* vec2, register Vec* ret) {
#ifdef __MWERKS__ // clang-format off
	nofralloc;
	psq_l     f2, Vec.x(vec1), 0, qr0;
	psq_l     f4, Vec.x(vec2), 0, qr0;
	ps_sub    f6, f2, f4;
	psq_st    f6, Vec.x(ret), 0, qr0;
	psq_l     f3, Vec.z(vec1), 1, qr0;
	psq_l     f5, Vec.z(vec2), 1, qr0;
	ps_sub    f7, f3, f5;
	psq_st    f7, Vec.z(ret), 1, qr0;
	blr
#endif // clang-format on
}

void PSVECScale(register const Vec* src, register Vec* dst, register f32 scale) {
    register f32 vxy;
    register f32 vz;
    register f32 rxy;
    register f32 rz;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l vxy, Vec.x(src), 0, qr0
		psq_l vz, Vec.z(src), 1, qr0
		ps_muls0 rxy, vxy, scale
		psq_st rxy, Vec.x(dst), 0, qr0
		ps_muls0 rz, vz, scale
		psq_st rz, Vec.z(dst), 1, qr0
	}
#endif // clang-format on
}

void PSVECNormalize(const register Vec* vec1, register Vec* ret) {
    register f32 c_half = 0.5f;
    register f32 c_three = 3.0f;
    register f32 v1_xy;
    register f32 v1_z;
    register f32 xx_zz;
    register f32 xx_yy;
    register f32 sqsum;
    register f32 rsqrt;
    register f32 nwork0;
    register f32 nwork1;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l v1_xy, Vec.x(vec1), 0, qr0
		ps_mul xx_yy, v1_xy, v1_xy
		psq_l v1_z, Vec.z(vec1), 1, qr0
		ps_madd xx_zz, v1_z, v1_z, xx_yy
		ps_sum0 sqsum, xx_zz, v1_z, xx_yy
		frsqrte rsqrt, sqsum
		fmuls nwork0, rsqrt, rsqrt
		fmuls nwork1, rsqrt, c_half
		fnmsubs nwork0, nwork0, sqsum, c_three
		fmuls rsqrt, nwork0, nwork1
		ps_muls0 v1_xy, v1_xy, rsqrt
		psq_st v1_xy, Vec.x(ret), 0, qr0
		ps_muls0 v1_z, v1_z, rsqrt
		psq_st v1_z, Vec.z(ret), 1, qr0
	}
#endif // clang-format on
}

f32 PSVECSquareMag(register const Vec* v) {
    register f32 vxy;
    register f32 vzz;
    register f32 sqmag;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l vxy, Vec.x(v), 0, qr0
		ps_mul vxy, vxy, vxy
		lfs vzz, Vec.z(v)
		ps_madd sqmag, vzz, vzz, vxy
		ps_sum0 sqmag, sqmag, vxy, vxy
	}
#endif // clang-format on
    return sqmag;
}

f32 PSVECMag(const register Vec* v) {
    register f32 vxy;
    register f32 vzz;
    register f32 sqmag;
    register f32 rmag;
    register f32 nwork0;
    register f32 nwork1;
    register f32 c_three;
    register f32 c_half;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l vxy, Vec.x(v), 0, qr0
		ps_mul vxy, vxy, vxy
		lfs vzz, Vec.z(v)
		ps_madd sqmag, vzz, vzz, vxy
	}
	c_half = 0.5f;
	asm {
		ps_sum0 sqmag, sqmag, vxy, vxy
		frsqrte rmag, sqmag
	}
	c_three = 3.0f;
	asm {
		fmuls nwork0, rmag, rmag
		fmuls nwork1, rmag, c_half
		fnmsubs nwork0, nwork0, sqmag, c_three
		fmuls rmag, nwork0, nwork1
		fsel rmag, rmag, rmag, sqmag
		fmuls sqmag, sqmag, rmag
	}
#endif // clang-format on
    return sqmag;
}

asm f32 PSVECDotProduct(const register Vec* vec1, const register Vec* vec2) {
#ifdef __MWERKS__ // clang-format off
	nofralloc;
    psq_l      f2, Vec.y(vec1), 0, qr0
    psq_l      f3, Vec.y(vec2), 0, qr0
    ps_mul     f2, f2, f3
    psq_l      f5, Vec.x(vec1), 0, qr0
    psq_l      f4, Vec.x(vec2), 0, qr0
    ps_madd    f3, f5, f4, f2
    ps_sum0    f1, f3, f2, f2
    blr
#endif // clang-format on
}

asm void PSVECCrossProduct(register const Vec* a, register const Vec* b, register Vec* axb) {
#ifdef __MWERKS__ // clang-format off
	nofralloc
    psq_l          f1, Vec.x(b), 0, qr0
    lfs            f2, Vec.z(a)
    psq_l          f0, Vec.x(a), 0, qr0
    ps_merge10     f6, f1, f1
    lfs            f3, Vec.z(b)
    ps_mul         f4, f1, f2
    ps_muls0       f7, f1, f0
    ps_msub        f5, f0, f3, f4
    ps_msub        f8, f0, f6, f7
    ps_merge11     f9, f5, f5
    ps_merge01     f10, f5, f8
    psq_st         f9, Vec.x(axb), 1, qr0
    ps_neg         f10, f10
    psq_st         f10, Vec.y(axb), 0, qr0
    blr
#endif // clang-format on
}

void C_VECReflect(const Vec* src, const Vec* normal, Vec* dst)
{
    Vec a0;
    Vec b0;
    f32 dot;

    a0.x = -src->x;
    a0.y = -src->y;
    a0.z = -src->z;
    VECNormalize(&a0, &a0);
    VECNormalize(normal, &b0);
    dot = VECDotProduct(&a0, &b0);
    dst->x = b0.x * 2.0f * dot - a0.x;
    dst->y = b0.y * 2.0f * dot - a0.y;
    dst->z = b0.z * 2.0f * dot - a0.z;
    VECNormalize(dst, dst);
}

f32 PSVECSquareDistance(register const Vec* a, register const Vec* b) {
    register f32 v0yz;
    register f32 v1yz;
    register f32 v0xy;
    register f32 v1xy;
    register f32 dyz;
    register f32 dxy;
    register f32 sqdist;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l v0yz, Vec.y(a), 0, qr0
		psq_l v1yz, Vec.y(b), 0, qr0
		ps_sub dyz, v0yz, v1yz
		psq_l v0xy, Vec.x(a), 0, qr0
		psq_l v1xy, Vec.x(b), 0, qr0
		ps_mul dyz, dyz, dyz
		ps_sub dxy, v0xy, v1xy
		ps_madd sqdist, dxy, dxy, dyz
		ps_sum0 sqdist, sqdist, dyz, dyz
	}
#endif // clang-format on
    return sqdist;
}

f32 PSVECDistance(register const Vec* a, register const Vec* b) {
    register f32 v0yz;
    register f32 v1yz;
    register f32 v0xy;
    register f32 v1xy;
    register f32 dyz;
    register f32 dxy;
    register f32 sqdist;
    register f32 rdist;
    register f32 dist;
    register f32 nwork0;
    register f32 nwork1;
    register f32 c_half;
    register f32 c_three;

#ifdef __MWERKS__ // clang-format off
	asm {
		psq_l v0yz, Vec.y(a), 0, qr0
		psq_l v1yz, Vec.y(b), 0, qr0
		ps_sub dyz, v0yz, v1yz
		psq_l v0xy, Vec.x(a), 0, qr0
		psq_l v1xy, Vec.x(b), 0, qr0
		ps_mul dyz, dyz, dyz
		ps_sub dxy, v0xy, v1xy
	}
	c_half = 0.5f;
	asm {
		ps_madd sqdist, dxy, dxy, dyz
		ps_sum0 sqdist, sqdist, dyz, dyz
	}
	c_three = 3.0f;
	asm {
		frsqrte rdist, sqdist
		fmuls nwork0, rdist, rdist
		fmuls nwork1, rdist, c_half
		fnmsubs nwork0, nwork0, sqdist, c_three
		fmuls rdist, nwork0, nwork1
		fsel rdist, rdist, rdist, sqdist
		fmuls dist, sqdist, rdist
	}
#endif // clang-format on
    return dist;
}
