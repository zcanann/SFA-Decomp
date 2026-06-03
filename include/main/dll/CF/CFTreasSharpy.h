#ifndef MAIN_DLL_CF_CFTREASSHARPY_H_
#define MAIN_DLL_CF_CFTREASSHARPY_H_

#include "ghidra_import.h"

void cfccrate_init(int obj, int aux);
void fxemit_emitEffect(int obj);
int fxemit_SeqFn(int obj, int unused, int events);
void cfccrate_release(void);
void cfccrate_initialise(void);
int fxemit_getExtraSize(void);
int fxemit_getObjectTypeId(void);
void fxemit_free(int obj);
void fxemit_hitDetect(void);

#endif /* MAIN_DLL_CF_CFTREASSHARPY_H_ */
