#ifndef MAIN_DLL_NW_NWMAMMOTH_H_
#define MAIN_DLL_NW_NWMAMMOTH_H_

#include "ghidra_import.h"

void ediblemushroom_init(int obj, int aux);
void enemymushroom_resetToSpawn(s16 *obj,float *state,int enableTimer);
int enemymushroom_getExtraSize(void);
int enemymushroom_func08(int obj);
void enemymushroom_free(int obj);
void enemymushroom_hitDetect(void);

#endif /* MAIN_DLL_NW_NWMAMMOTH_H_ */
