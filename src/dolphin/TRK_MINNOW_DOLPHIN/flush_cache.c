#include "TRK_MINNOW_DOLPHIN/ppc/Generic/flush_cache.h"

asm void TRK_flush_cache(register void* arg1, register int arg2)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc

	lis r5, 0xFFFF
	ori r5, r5, 0xFFF1
	and r5, r5, arg1
	subf r3, r5, arg1
	add r4, arg2, r3

loop:
	dcbst 0, r5
	dcbf 0, r5
	sync
	icbi 0, r5
	addic r5, r5, 8
	addic. r4, r4, -8
	bge loop

	isync
	blr
#endif // clang-format on
}
