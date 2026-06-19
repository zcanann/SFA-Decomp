#ifndef MAIN_DLL_SC_SCCOLLECTABLES_H_
#define MAIN_DLL_SC_SCCOLLECTABLES_H_

#include "ghidra_import.h"

int warpstone_handleMenuOptionInput(u32 p1, u32 p2, int option);
void warpstone_loadBaseUi(void);
int warpstone_updateMenuAnimObj(int obj, u32 p2, int animObj);
int warpstone_getExtraSize(void);
int warpstone_getObjectTypeId(void);

#endif /* MAIN_DLL_SC_SCCOLLECTABLES_H_ */
