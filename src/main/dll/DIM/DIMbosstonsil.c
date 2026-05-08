#include "ghidra_import.h"
#include "main/dll/DIM/DIMbosstonsil.h"

/* Trivial 4b 0-arg blr leaves. */
void dimbossgut_free(void) {}
void dimbossgut_hitDetect(void) {}
void dimbossgut_update(void) {}
void dimbossgut_release(void) {}
void dimbossgut_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dimbossgut_getExtraSize(void) { return 0x0; }
int dimbossgut_func08(void) { return 0x0; }

/* init pattern: short=-1; byte=0; return 0; */
#pragma scheduling off
#pragma peephole off
int fn_801BDBE0(int p1, int p2, void* p3) { *(s16*)((char*)p3 + 0x6e) = -1; *(u8*)((char*)p3 + 0x56) = 0; return 0; }
#pragma peephole reset
#pragma scheduling reset
