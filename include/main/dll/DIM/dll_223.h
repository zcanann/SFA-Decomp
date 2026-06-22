#ifndef MAIN_DLL_DIM_DLL_223_H_
#define MAIN_DLL_DIM_DLL_223_H_

#include "ghidra_import.h"
#include "main/dll/DIM/DIMbosstonsil.h"

int DIMbosstonsil_updateHitReaction(void *obj,DIMbosstonsilState *state,int unused);
int DIMbosstonsil_enableHitReaction(void *obj,DIMbosstonsilState *state);
int DIMbosstonsil_chooseHitReaction(void *obj,DIMbosstonsilState *state);
int DIMbosstonsil_startIdleHitReaction(void *obj,DIMbosstonsilState *state);
void DIMbosstonsil_checkHit(void *obj,DIMbosstonsilState *state);

#endif /* MAIN_DLL_DIM_DLL_223_H_ */
