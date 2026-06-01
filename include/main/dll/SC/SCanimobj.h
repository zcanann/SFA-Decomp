#ifndef MAIN_DLL_SC_SCANIMOBJ_H_
#define MAIN_DLL_SC_SCANIMOBJ_H_

#include "ghidra_import.h"

void warpstone_update(int obj);
void warpstone_release(void);
void warpstone_initialise(void);
void warpstone_init(int obj, u8 *setup);
int sh_levelcontrol_getExtraSize(void);

#endif /* MAIN_DLL_SC_SCANIMOBJ_H_ */
