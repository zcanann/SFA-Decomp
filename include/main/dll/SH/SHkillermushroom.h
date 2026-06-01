#ifndef MAIN_DLL_SH_SHKILLERMUSHROOM_H_
#define MAIN_DLL_SH_SHKILLERMUSHROOM_H_

#include "ghidra_import.h"

void bombplantspore_free(void *obj);
void bombplantspore_startDriftBurst(void *obj, void *state);
void bombplantspore_updateDrift(void *obj, void *state);
int bombplantspore_getExtraSize(void);

#endif /* MAIN_DLL_SH_SHKILLERMUSHROOM_H_ */
