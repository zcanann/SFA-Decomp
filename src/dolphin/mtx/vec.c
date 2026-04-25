#include "dolphin/mtx.h"
#include "math.h"

extern const float lbl_803E7648;  // 0.5f
extern const float lbl_803E764C;  // 3.0f
extern const float lbl_803E7650;  // 2.0f

#define R_RET fp1
#define FP2 fp2
#define FP3 fp3
#define FP4 fp4
#define FP5 fp5
#define FP6 fp6
#define FP7 fp7
#define FP8 fp8
#define FP9 fp9
#define FP10 fp10
#define FP11 fp11
#define FP12 fp12
#define FP13 fp13

asm void PSVECAdd(const register Vec *vec1, const register Vec *vec2, register Vec *ret)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc;
	psq_l     FP2,  0(vec1), 0, 0;
	psq_l     FP4,  0(vec2), 0, 0;
	ps_add    FP6, FP2, FP4;
	psq_st    FP6,  0(ret), 0, 0;
	psq_l     FP3,   8(vec1), 1, 0;
	psq_l     FP5,   8(vec2), 1, 0;
	ps_add    FP7, FP3, FP5;
	psq_st    FP7,   8(ret), 1, 0;
	blr
#endif // clang-format on
}

asm void PSVECSubtract(const register Vec *vec1, const register Vec *vec2, register Vec *ret)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc;
	psq_l     FP2,  0(vec1), 0, 0;
	psq_l     FP4,  0(vec2), 0, 0;
	ps_sub    FP6, FP2, FP4;
	psq_st    FP6, 0(ret), 0, 0;
	psq_l     FP3,   8(vec1), 1, 0;
	psq_l     FP5,   8(vec2), 1, 0;
	ps_sub    FP7, FP3, FP5;
	psq_st    FP7,  8(ret), 1, 0;
	blr
#endif // clang-format on
}

asm void PSVECScale(register const Vec *src, register Vec *dst, register f32 scale)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc
	psq_l        f0, 0(src), 0, 0
    psq_l        f2, 8(src), 1, 0
    ps_muls0     f0, f0, f1
    psq_st       f0, 0(dst), 0, 0
    ps_muls0     f0, f2, f1
    psq_st       f0, 8(dst), 1, 0
    blr 
#endif // clang-format on
}

asm void PSVECNormalize(const register Vec *vec1, register Vec *ret)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc
	lfs         f0, lbl_803E7648(r0)
	lfs         f1, lbl_803E764C(r0)
	psq_l       f2, 0(vec1), 0, 0
	ps_mul      f5, f2, f2
	psq_l       f3, 8(vec1), 1, 0
	ps_madd     f4, f3, f3, f5
	ps_sum0     f4, f4, f3, f5
	frsqrte     f5, f4
	fmuls       f6, f5, f5
	fmuls       f0, f5, f0
	fnmsubs     f6, f6, f4, f1
	fmuls       f5, f6, f0
	ps_muls0    f2, f2, f5
	psq_st      f2, 0(ret), 0, 0
	ps_muls0    f3, f3, f5
	psq_st      f3, 8(ret), 1, 0
	blr
#endif // clang-format on
}

asm f32 PSVECSquareMag(register const Vec *v) {
#ifdef __MWERKS__ // clang-format off
	nofralloc
    psq_l      f0, 0(v), 0, 0
    ps_mul     f0, f0, f0
    lfs        f1, 8(v)
    ps_madd    f1, f1, f1, f0
    ps_sum0    f1, f1, f0, f0
    blr 
#endif // clang-format on
}

asm f32 PSVECMag(const register Vec *v)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc
	psq_l       f0, 0(r3), 0, 0
	ps_mul      f0, f0, f0
	lfs         f1, 8(r3)
	ps_madd     f1, f1, f1, f0
	lfs         f4, lbl_803E7648(r0)
	ps_sum0     f1, f1, f0, f0
	frsqrte     f0, f1
	lfs         f3, lbl_803E764C(r0)
	fmuls       f2, f0, f0
	fmuls       f0, f0, f4
	fnmsubs     f2, f2, f1, f3
	fmuls       f0, f2, f0
	fsel        f0, f0, f0, f1
	fmuls       f1, f1, f0
	blr
#endif // clang-format on
}

asm f32 PSVECDotProduct(const register Vec *vec1, const register Vec *vec2)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc;
    psq_l      f2, 4(r3), 0, 0 /* qr0 */
    psq_l      f3, 4(r4), 0, 0 /* qr0 */
    ps_mul     f2, f2, f3
    psq_l      f5, 0(r3), 0, 0 /* qr0 */
    psq_l      f4, 0(r4), 0, 0 /* qr0 */
    ps_madd    f3, f5, f4, f2
    ps_sum0    f1, f3, f2, f2
    blr 
#endif // clang-format on
}

asm void PSVECCrossProduct(register const Vec *a, register const Vec *b, register Vec *axb)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc
    psq_l          f1, 0(b), 0, 0
    lfs            f2, 8(a)
    psq_l          f0, 0(a), 0, 0
    ps_merge10     f6, f1, f1
    lfs            f3, 8(b)
    ps_mul         f4, f1, f2
    ps_muls0       f7, f1, f0
    ps_msub        f5, f0, f3, f4
    ps_msub        f8, f0, f6, f7
    ps_merge11     f9, f5, f5
    ps_merge01     f10, f5, f8
    psq_st         f9, 0(axb), 1, 0
    ps_neg         f10, f10
    psq_st         f10, 4(axb), 0, 0
    blr 
#endif // clang-format on
}

/* C_VECHalfAngle uses lbl_803E7650 (was wrongly named lbl_803E82E8) */

asm void C_VECHalfAngle(const Vec *a, const Vec *b, Vec *half)
{
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x38(r1)
    stw r31, 0x34(r1)
    stw r30, 0x30(r1)
    mr r30, r4
    mr r31, r5
    lfs f0, 0x0(r3)
    fneg f0, f0
    stfs f0, 0x20(r1)
    lfs f0, 0x4(r3)
    fneg f0, f0
    stfs f0, 0x24(r1)
    lfs f0, 0x8(r3)
    addi r3, r1, 0x20
    mr r4, r3
    fneg f0, f0
    stfs f0, 0x28(r1)
    bl PSVECNormalize
    mr r3, r30
    addi r4, r1, 0x14
    bl PSVECNormalize
    addi r3, r1, 0x20
    addi r4, r1, 0x14
    bl PSVECDotProduct
    lfs f3, lbl_803E7650(r0)
    mr r3, r31
    lfs f2, 0x14(r1)
    mr r4, r31
    lfs f0, 0x20(r1)
    fmuls f2, f3, f2
    fmuls f2, f2, f1
    fsubs f0, f2, f0
    stfs f0, 0x0(r31)
    lfs f2, 0x18(r1)
    lfs f0, 0x24(r1)
    fmuls f2, f3, f2
    fmuls f2, f2, f1
    fsubs f0, f2, f0
    stfs f0, 0x4(r31)
    lfs f2, 0x1c(r1)
    lfs f0, 0x28(r1)
    fmuls f2, f3, f2
    fmuls f1, f2, f1
    fsubs f0, f1, f0
    stfs f0, 0x8(r31)
    bl PSVECNormalize
    lwz r0, 0x3c(r1)
    lwz r31, 0x34(r1)
    lwz r30, 0x30(r1)
    mtlr r0
    addi r1, r1, 0x38
    blr
}

asm f32 PSVECSquareDistance(register const Vec *a, register const Vec *b) {
#ifdef __MWERKS__ // clang-format off
	nofralloc
    psq_l      f0, 4(a), 0, 0
    psq_l      f1, 4(b), 0, 0
    ps_sub     f2, f0, f1
    psq_l      f0, 0(a), 0, 0
    psq_l      f1, 0(b), 0, 0
    ps_mul     f2, f2, f2
    ps_sub     f0, f0, f1
    ps_madd    f1, f0, f0, f2
    ps_sum0    f1, f1, f2, f2
    blr 
#endif // clang-format on
}

asm f32 PSVECDistance(register const Vec *a, register const Vec *b)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc
	psq_l       f0, 4(r3), 0, 0
	psq_l       f1, 4(r4), 0, 0
	ps_sub      f2, f0, f1
	psq_l       f0, 0(r3), 0, 0
	psq_l       f1, 0(r4), 0, 0
	ps_mul      f2, f2, f2
	ps_sub      f0, f0, f1
	lfs         f3, lbl_803E7648(r0)
	ps_madd     f0, f0, f0, f2
	ps_sum0     f0, f0, f2, f2
	lfs         f4, lbl_803E764C(r0)
	frsqrte     f1, f0
	fmuls       f2, f1, f1
	fmuls       f1, f1, f3
	fnmsubs     f2, f2, f0, f4
	fmuls       f1, f2, f1
	fsel        f1, f1, f1, f0
	fmuls       f1, f0, f1
	blr
#endif // clang-format on
}
