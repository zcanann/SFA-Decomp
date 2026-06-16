#ifndef MAIN_DLL_DR_DLL_0287_SPSCARAB_H_
#define MAIN_DLL_DR_DLL_0287_SPSCARAB_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gSPScarabObjDescriptor;

void spscarab_update(int param_1);
void spscarab_init(int param_1, int param_2);
void spscarab_release(void);
void spscarab_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0287_SPSCARAB_H_ */
