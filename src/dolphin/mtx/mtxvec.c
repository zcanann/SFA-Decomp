#include "dolphin/mtx.h"

asm void PSMTXMultVec(const register Mtx m, const register Vec* in, register Vec* out) {
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
