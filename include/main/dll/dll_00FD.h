#ifndef MAIN_DLL_DLL_14D_H_
#define MAIN_DLL_DLL_14D_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDll14DObjDescriptor;

void dll_FD_free(void);
void dll_FD_update(u16 *param_1);
void dll_FD_init(int *obj);
void FUN_8017f290(int param_1);
void magicPlantDropGem(int obj, void *setup, void *state);

#endif /* MAIN_DLL_DLL_14D_H_ */
