#ifndef MAIN_DLL_DLL_1D0_H_
#define MAIN_DLL_DLL_1D0_H_

#include "ghidra_import.h"

typedef struct Dll19ESetup Dll19ESetup;

void dll_19E_update(void *obj);
void dll_19E_init(u8 *obj, Dll19ESetup *setup);
void dll_19E_release(void);
void dll_19E_initialise(void);

#endif /* MAIN_DLL_DLL_1D0_H_ */
