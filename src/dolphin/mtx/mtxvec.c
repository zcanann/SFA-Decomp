#include "dolphin/mtx.h"

extern void fn_80247494(void);
extern void fn_802474E8(void);
extern void fn_802474F4(void);

asm void PSMTXMultVec(const register Mtx m, const register Vec *in, register Vec *out)
{
    nofralloc
entry fn_80247494
    psq_l f0, 0(in), 0, 0
    psq_l f2, 0(m), 0, 0
    psq_l f1, 8(in), 1, 0
    ps_mul f4, f2, f0
    psq_l f3, 8(m), 0, 0
    ps_madd f5, f3, f1, f4
    psq_l f8, 16(m), 0, 0
    ps_sum0 f6, f5, f6, f5
    psq_l f9, 24(m), 0, 0
    ps_mul f10, f8, f0
    psq_st f6, 0(out), 1, 0
    ps_madd f11, f9, f1, f10
    psq_l f2, 32(m), 0, 0
    ps_sum0 f12, f11, f12, f11
    psq_l f3, 40(m), 0, 0
    ps_mul f4, f2, f0
    psq_st f12, 4(out), 1, 0
    ps_madd f5, f3, f1, f4
    ps_sum0 f6, f5, f6, f5
    psq_st f6, 8(out), 1, 0
    blr
}

asm void PSMTXMultVecArray(const register Mtx m, const register Vec *srcBase, register Vec *dstBase, register u32 count)
{
    nofralloc
entry fn_802474E8
    psq_l f13, 0(m), 0, 0
    psq_l f12, 16(m), 0, 0
    subi r6, r6, 1
entry fn_802474F4
    psq_l f11, 8(m), 0, 0
    ps_merge00 f0, f13, f12
    subi r5, r5, 4
    psq_l f10, 24(m), 0, 0
    ps_merge11 f1, f13, f12
    mtctr r6
    psq_l f4, 32(m), 0, 0
    ps_merge00 f2, f11, f10
    psq_l f5, 40(m), 0, 0
    ps_merge11 f3, f11, f10
    psq_l f6, 0(srcBase), 0, 0
    psq_lu f7, 8(srcBase), 1, 0
    ps_madds0 f8, f0, f6, f3
    ps_mul f9, f4, f6
    ps_madds1 f8, f1, f6, f8
    ps_madd f10, f5, f7, f9
_loop:
    psq_lu f6, 4(srcBase), 0, 0
    ps_madds0 f12, f2, f7, f8
    psq_lu f7, 8(srcBase), 1, 0
    ps_sum0 f13, f10, f9, f10
    ps_madds0 f8, f0, f6, f3
    ps_mul f9, f4, f6
    psq_stu f12, 4(dstBase), 0, 0
    ps_madds1 f8, f1, f6, f8
    psq_stu f13, 8(dstBase), 1, 0
    ps_madd f10, f5, f7, f9
    bdnz _loop
    ps_madds0 f12, f2, f7, f8
    ps_sum0 f13, f10, f9, f10
    psq_stu f12, 4(dstBase), 0, 0
    psq_stu f13, 8(dstBase), 1, 0
    blr
}

asm void PSMTXMultVecSR(const register Mtx m, const register Vec* in, register Vec* out) {
#ifdef __MWERKS__  // clang-format off
	nofralloc;
	psq_l fp0, 0(m), 0, 0;
	psq_l fp6, 0(in), 0, 0;
	psq_l fp2, 16(m), 0, 0;
	ps_mul fp8, fp0, fp6;
	psq_l fp4, 32(m), 0, 0;
	ps_mul fp10, fp2, fp6;
	psq_l fp7, 8(in), 1, 0;
	ps_mul fp12, fp4, fp6;
	psq_l fp3, 24(m), 0, 0;
	ps_sum0 fp8, fp8, fp8, fp8;
	psq_l fp5, 40(m), 0, 0;
	ps_sum0 fp10, fp10, fp10, fp10;
	psq_l fp1, 8(m), 0, 0;
	ps_sum0 fp12, fp12, fp12, fp12;
	ps_madd fp9, fp1, fp7, fp8;
	psq_st fp9, 0(out), 1, 0;
	ps_madd fp11, fp3, fp7, fp10;
	psq_st fp11, 4(out), 1, 0;
	ps_madd fp13, fp5, fp7, fp12;
	psq_st fp13, 8(out), 1, 0;
	blr
#endif  // clang-format on
}
