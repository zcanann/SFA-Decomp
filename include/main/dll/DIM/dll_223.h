#ifndef MAIN_DLL_DIM_DLL_223_H_
#define MAIN_DLL_DIM_DLL_223_H_

#include "ghidra_import.h"

int DIMbosstonsil_updateHitReaction(void *obj,u8 *state,int param_3);
int DIMbosstonsil_enableHitReaction(void *obj,u8 *state);
int DIMbosstonsil_chooseHitReaction(void *obj,u8 *state);
int DIMbosstonsil_startIdleHitReaction(void *obj,u8 *state);
void DIMbosstonsil_checkHit(void *obj,u8 *state);

#endif /* MAIN_DLL_DIM_DLL_223_H_ */
