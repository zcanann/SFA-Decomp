#ifndef MAIN_DLL_SH_DLL_1E7_H_
#define MAIN_DLL_SH_DLL_1E7_H_

#include "main/dll/SH/SHthorntail_internal.h"

int fn_801D4CD0(SHthorntailObject *obj);
void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime);
uint SHthorntail_chooseNextState(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config);

#endif /* MAIN_DLL_SH_DLL_1E7_H_ */
