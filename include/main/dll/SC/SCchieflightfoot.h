#ifndef MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_
#define MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_

#include "ghidra_import.h"

#include "main/dll/SH/SHthorntail_internal.h"

void SHthorntail_update(SHthorntailObject *obj);
void sh_thorntail_init(SHthorntailObject *obj,SHthorntailConfig *config);
void SHthorntail_updateDustEffects(SHthorntailObject *obj);

#endif /* MAIN_DLL_SC_SCCHIEFLIGHTFOOT_H_ */
