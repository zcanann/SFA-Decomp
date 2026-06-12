#ifndef MAIN_DLL_DIM_BOSSGUT_H_
#define MAIN_DLL_DIM_BOSSGUT_H_

#include "ghidra_import.h"

void enemymushroom_update(int *obj);
void enemymushroom_release(void);
void enemymushroom_initialise(void);
int bombplant_getExtraSize(void);
int bombplant_getObjectTypeId(void);
void bombplant_free(void);
void bombplant_hitDetect(void);
int bombplant_SeqFn(int *obj);

#endif /* MAIN_DLL_DIM_BOSSGUT_H_ */
