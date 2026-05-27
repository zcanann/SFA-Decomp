#ifndef MAIN_DLL_CF_DLL_165_H_
#define MAIN_DLL_CF_DLL_165_H_

#include "ghidra_import.h"

void staffactivated_init(int obj, int setup);
int fn_8018A8BC(int obj, int unused, u8 *events);
int treasurechest_getExtraSize(void);
int treasurechest_getObjectTypeId(void);
void treasurechest_free(void);
void treasurechest_render(void);
void treasurechest_hitDetect(int obj);

#endif /* MAIN_DLL_CF_DLL_165_H_ */
