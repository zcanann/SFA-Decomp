#ifndef MAIN_DLL_DR_DLL_0287_SPSCARAB_H_
#define MAIN_DLL_DR_DLL_0287_SPSCARAB_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gSPScarabObjDescriptor;

void spscarab_update(int obj);
void spscarab_init(int obj, int def);
void spscarab_release(void);
void spscarab_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0287_SPSCARAB_H_ */
