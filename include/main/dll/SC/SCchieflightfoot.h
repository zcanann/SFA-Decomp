#ifndef MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_
#define MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_

#include "ghidra_import.h"

#include "main/dll/SH/SHthorntail_internal.h"

void sh_thorntail_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8);
void sh_thorntail_init(SHthorntailObject *obj,SHthorntailConfig *config);
void SHthorntail_updateDustEffects(SHthorntailObject *obj);

#endif /* MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_ */
