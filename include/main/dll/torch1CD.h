#ifndef MAIN_DLL_TORCH1CD_H_
#define MAIN_DLL_TORCH1CD_H_

#include "ghidra_import.h"

int dll_19B_SeqFn(int obj, int unused, u8 *buf);
int dll_19B_getExtraSize(void);
int dll_19B_getObjectTypeId(void);
void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_19B_hitDetect(void);

#endif /* MAIN_DLL_TORCH1CD_H_ */
