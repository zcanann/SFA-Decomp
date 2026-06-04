#ifndef MAIN_DLL_DLL_1E1_H_
#define MAIN_DLL_DLL_1E1_H_

#include "ghidra_import.h"

void enemymushroom_update(int *obj);
void enemymushroom_release(void);
void enemymushroom_initialise(void);
int bombplant_getExtraSize(void);
int bombplant_getObjectTypeId(void);
void bombplant_free(void);
void bombplant_hitDetect(void);

#endif /* MAIN_DLL_DLL_1E1_H_ */
