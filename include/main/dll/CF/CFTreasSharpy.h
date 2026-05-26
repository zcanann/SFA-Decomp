#ifndef MAIN_DLL_CF_CFTREASSHARPY_H_
#define MAIN_DLL_CF_CFTREASSHARPY_H_

#include "ghidra_import.h"

void cfccrate_init(int obj, int aux);
void fn_8018E6C4(int obj);
int fn_8018EAA4(int obj, int unused, int events);
void FUN_8018e0a8(void);
void cfccrate_release(void);
void cfccrate_initialise(void);
int fxemit_getExtraSize(void);
int fxemit_func08(void);
void fxemit_free(int obj);
void fxemit_hitDetect(void);

#endif /* MAIN_DLL_CF_CFTREASSHARPY_H_ */
