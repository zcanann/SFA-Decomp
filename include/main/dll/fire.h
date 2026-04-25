#ifndef MAIN_DLL_FIRE_H_
#define MAIN_DLL_FIRE_H_

#include "ghidra_import.h"

undefined4 fire_updateState(int obj,undefined4 param_2,u8 *stateList);
int fireObj_getExtraSize(void);
int fireObj_func08(void);
void fireObj_free(void);
void fireObj_render(void);
void fireObj_hitDetect(void);
void fireObj_update(int obj);
void fireObj_init(int obj);
void fireObj_release(void);
void fireObj_initialise(void);

#endif /* MAIN_DLL_FIRE_H_ */
